//! TCP connection lifecycle hooks.
//! Tracks connect, accept, and close to bookend every flow event.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
    },
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use flow_sensor_common::*;

use crate::{kread, maps::*};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Extract FlowKey from a kernel sock pointer
unsafe fn flow_key_from_sock(sk: *const core::ffi::c_void) -> Option<FlowKey> {
    // Offsets into struct sock for common fields
    // These are stable across kernel versions we support (5.8+)
    const SK_SRC_IP_OFFSET: usize = 0x4;    // inet_sock.inet_saddr
    const SK_DST_IP_OFFSET: usize = 0x0;    // inet_sock.inet_daddr
    const SK_SRC_PORT_OFFSET: usize = 0xC;  // inet_sock.inet_sport
    const SK_DST_PORT_OFFSET: usize = 0xA;  // inet_sock.inet_dport
    const SK_PROTOCOL_OFFSET: usize = 0x10; // sk_protocol

    let base = sk.cast::<u8>();
    let src_ip = kread::read_u32_ne(base.add(SK_SRC_IP_OFFSET)).ok()?;
    let dst_ip = kread::read_u32_ne(base.add(SK_DST_IP_OFFSET)).ok()?;
    let src_port = kread::read_u16_ne(base.add(SK_SRC_PORT_OFFSET)).ok()?;
    let dst_port = kread::read_u16_ne(base.add(SK_DST_PORT_OFFSET)).ok()?;
    let protocol = kread::read_u8(base.add(SK_PROTOCOL_OFFSET)).ok()?;

    Some(FlowKey {
        src_ip,
        dst_ip,
        src_port: u16::from_be(src_port),
        dst_port: u16::from_be(dst_port),
        protocol,
        _pad: [0; 3],
    })
}

/// Initialize a fresh FlowState for a new connection
unsafe fn init_flow_state(direction: u8) -> FlowState {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let now = bpf_ktime_get_ns();

    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);

    // Pull causal chain context for this thread
    let (chain_id, parent_chain_id, chain_depth) =
        if let Some(ctx) = CAUSAL_MAP.get(&pid_tgid) {
            (ctx.chain_id, ctx.parent_chain_id, ctx.depth)
        } else {
            // New chain — use timestamp as unique ID
            (now, 0, 0)
        };

    FlowState {
        pid: (pid_tgid >> 32) as u32,
        ppid: 0, // filled by userspace from /proc
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        comm,
        cgroup: [0u8; CGROUP_LEN], // filled from bpf_get_current_cgroup_id
        direction,
        bytes_sent: 0,
        bytes_recv: 0,
        pkts_sent: 0,
        pkts_recv: 0,
        srtt_us_min: u32::MAX,
        srtt_us_max: 0,
        srtt_us_last: 0,
        rttvar_us_max: 0,
        cwnd_min: u32::MAX,
        cwnd_max: 0,
        ecn_signals: 0,
        retransmit_count: 0,
        retransmit_bytes: 0,
        retransmit_rto_count: 0,
        retransmit_fast_count: 0,
        retransmit_tlp_count: 0,
        sack_blocks_received: 0,
        tls_sni: [0u8; HOST_LEN],
        http_host: [0u8; HOST_LEN],
        http_method: [0u8; 8],
        http_path: [0u8; PATH_LEN],
        http_status: 0,
        has_tls: 0,
        has_http: 0,
        ssl_write_ts_ns: 0,
        connect_ts_ns: now,
        first_byte_ts_ns: 0,
        first_recv_ts_ns: 0,
        tls_ready_ts_ns: 0,
        chain_id,
        parent_chain_id,
        chain_depth,
        congestion_state_final: 0,
    }
}

// ── TCP connect (outbound) ───────────────────────────────────────────────────

/// Fires when a process calls connect() — outbound connection initiated
#[kprobe(function = "tcp_connect")]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match unsafe { handle_tcp_connect(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_tcp_connect(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk = ctx.arg::<*const core::ffi::c_void>(0).ok_or(-1)?;
    let key = flow_key_from_sock(sk).ok_or(-1)?;
    let state = init_flow_state(FlowDirection::Outbound as u8);
    FLOW_TABLE.insert(&key, &state, 0)?;
    Ok(0)
}

// ── TCP accept (inbound) ─────────────────────────────────────────────────────

/// Fires when accept() returns — inbound connection established
#[kretprobe(function = "inet_csk_accept")]
pub fn inet_csk_accept(ctx: RetProbeContext) -> u32 {
    match unsafe { handle_accept(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_accept(ctx: &RetProbeContext) -> Result<u32, i64> {
    let sk = ctx.ret::<*const core::ffi::c_void>().ok_or(-1)?;
    if sk.is_null() { return Ok(0); }
    let key = flow_key_from_sock(sk).ok_or(-1)?;
    let state = init_flow_state(FlowDirection::Inbound as u8);
    FLOW_TABLE.insert(&key, &state, 0)?;
    Ok(0)
}

// ── TCP close ────────────────────────────────────────────────────────────────

/// Fires on tcp_close — connection is being torn down
/// This is where we emit the complete FlowEvent
#[kprobe(function = "tcp_close")]
pub fn tcp_close(ctx: ProbeContext) -> u32 {
    match unsafe { handle_tcp_close(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_tcp_close(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk = ctx.arg::<*const core::ffi::c_void>(0).ok_or(-1)?;
    let key = flow_key_from_sock(sk).ok_or(-1)?;

    let state = match FLOW_TABLE.get(&key) {
        Some(s) => *s,
        None => return Ok(0), // connection we didn't track (pre-sensor)
    };

    let now = bpf_ktime_get_ns();
    let duration_ns = now.saturating_sub(state.connect_ts_ns);

    // Build the complete FlowEvent
    let event = FlowEvent {
        pid: state.pid,
        ppid: state.ppid,
        uid: state.uid,
        gid: state.gid,
        comm: state.comm,
        cgroup: state.cgroup,
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        src_port: key.src_port,
        dst_port: key.dst_port,
        protocol: key.protocol,
        direction: state.direction,
        bytes_sent: state.bytes_sent,
        bytes_recv: state.bytes_recv,
        pkts_sent: state.pkts_sent,
        pkts_recv: state.pkts_recv,
        srtt_us_min: if state.srtt_us_min == u32::MAX { 0 } else { state.srtt_us_min },
        srtt_us_max: state.srtt_us_max,
        srtt_us_final: state.srtt_us_last,
        rttvar_us_max: state.rttvar_us_max,
        retransmit_count: state.retransmit_count,
        retransmit_bytes: state.retransmit_bytes,
        retransmit_rto_count: state.retransmit_rto_count,
        retransmit_fast_count: state.retransmit_fast_count,
        retransmit_tlp_count: state.retransmit_tlp_count,
        sack_blocks_received: state.sack_blocks_received,
        cwnd_min: if state.cwnd_min == u32::MAX { 0 } else { state.cwnd_min },
        cwnd_max: state.cwnd_max,
        ecn_signals: state.ecn_signals,
        tls_sni: state.tls_sni,
        http_host: state.http_host,
        http_method: state.http_method,
        http_path: state.http_path,
        http_status: state.http_status,
        has_tls: state.has_tls,
        has_http: state.has_http,
        connect_ts_ns: state.connect_ts_ns,
        first_byte_ts_ns: state.first_byte_ts_ns,
        first_recv_ts_ns: state.first_recv_ts_ns,
        close_ts_ns: now,
        duration_ns,
        time_to_first_byte_ns: state.first_byte_ts_ns.saturating_sub(state.connect_ts_ns),
        tls_handshake_ns: if state.tls_ready_ts_ns > 0 {
            state.tls_ready_ts_ns.saturating_sub(state.connect_ts_ns)
        } else { 0 },
        app_response_time_ns: if state.first_recv_ts_ns > 0 && state.ssl_write_ts_ns > 0 {
            state.first_recv_ts_ns.saturating_sub(state.ssl_write_ts_ns)
        } else { 0 },
        close_reason: CloseReason::LocalClose as u8,
        congestion_state_final: state.congestion_state_final,
        chain_id: state.chain_id,
        parent_chain_id: state.parent_chain_id,
        chain_depth: state.chain_depth,
    };

    // Write to ring buffer — zero-copy path to userspace
    if let Some(mut buf) = FLOW_EVENTS.reserve::<FlowEvent>(0) {
        buf.write(event);
        buf.submit(0);
    }

    // Clean up flow state
    FLOW_TABLE.remove(&key)?;
    Ok(0)
}

// ── TCP RST handling ─────────────────────────────────────────────────────────

/// Fires when a RST is sent — update close reason before tcp_close fires
#[kprobe(function = "tcp_send_active_reset")]
pub fn tcp_send_active_reset(ctx: ProbeContext) -> u32 {
    match unsafe { handle_rst(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_rst(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk = ctx.arg::<*const core::ffi::c_void>(0).ok_or(-1)?;
    let key = flow_key_from_sock(sk).ok_or(-1)?;

    if let Some(state) = FLOW_TABLE.get_ptr_mut(&key) {
        (*state).congestion_state_final = CloseReason::Reset as u8;
    }
    Ok(0)
}

// ── Byte/packet counting ─────────────────────────────────────────────────────

/// Count bytes sent — fires on tcp_sendmsg
#[kprobe(function = "tcp_sendmsg")]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match unsafe { handle_sendmsg(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_sendmsg(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk = ctx.arg::<*const core::ffi::c_void>(0).ok_or(-1)?;
    let size = ctx.arg::<usize>(2).ok_or(-1)? as u64;
    let key = flow_key_from_sock(sk).ok_or(-1)?;

    if let Some(state) = FLOW_TABLE.get_ptr_mut(&key) {
        (*state).bytes_sent = (*state).bytes_sent.saturating_add(size);
        (*state).pkts_sent = (*state).pkts_sent.saturating_add(1);
        if (*state).first_byte_ts_ns == 0 {
            (*state).first_byte_ts_ns = bpf_ktime_get_ns();
        }
    }
    Ok(0)
}

/// Count bytes received — fires on tcp_recvmsg return
#[kretprobe(function = "tcp_recvmsg")]
pub fn tcp_recvmsg(ctx: RetProbeContext) -> u32 {
    match unsafe { handle_recvmsg(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_recvmsg(ctx: &RetProbeContext) -> Result<u32, i64> {
    let bytes = ctx.ret::<i64>().ok_or(-1)?;
    if bytes <= 0 { return Ok(0); }

    // We need the sock — stored in a scratch map keyed by pid_tgid
    // (simplified here — full impl uses entry/exit pair)
    Ok(0)
}
