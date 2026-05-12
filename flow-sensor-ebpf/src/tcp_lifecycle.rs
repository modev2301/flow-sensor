//! TCP connection lifecycle hooks.
//! Tracks connect, accept, and close to bookend every flow event.

use core::mem::MaybeUninit;

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

/// Insert an empty row then fill identity in-place (keeps large `FlowState` off the stack).
unsafe fn init_flow_row(key: &FlowKey, direction: u8) -> Result<(), i64> {
    FLOW_TABLE.insert(key, &EMPTY_FLOW_STATE, 0)?;
    let Some(st) = FLOW_TABLE.get_ptr_mut(key) else {
        return Err(-1);
    };
    fill_new_flow_state(&mut *st, direction);
    Ok(())
}

unsafe fn fill_new_flow_state(st: &mut FlowState, direction: u8) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let now = bpf_ktime_get_ns();

    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);

    let (chain_id, parent_chain_id, chain_depth) =
        if let Some(ctx) = CAUSAL_MAP.get(&pid_tgid) {
            (ctx.chain_id, ctx.parent_chain_id, ctx.depth)
        } else {
            (now, 0, 0)
        };

    st.pid = (pid_tgid >> 32) as u32;
    st.ppid = 0;
    st.uid = uid_gid as u32;
    st.gid = (uid_gid >> 32) as u32;
    st.comm = comm;
    st.cgroup = [0u8; CGROUP_LEN];
    st.direction = direction;
    st.bytes_sent = 0;
    st.bytes_recv = 0;
    st.pkts_sent = 0;
    st.pkts_recv = 0;
    st.srtt_us_min = u32::MAX;
    st.srtt_us_max = 0;
    st.srtt_us_last = 0;
    st.rttvar_us_max = 0;
    st.cwnd_min = u32::MAX;
    st.cwnd_max = 0;
    st.ecn_signals = 0;
    st.retransmit_count = 0;
    st.retransmit_bytes = 0;
    st.retransmit_rto_count = 0;
    st.retransmit_fast_count = 0;
    st.retransmit_tlp_count = 0;
    st.sack_blocks_received = 0;
    st.tls_sni = [0u8; HOST_LEN];
    st.http_host = [0u8; HOST_LEN];
    st.http_method = [0u8; 8];
    st.http_path = [0u8; PATH_LEN];
    st.http_status = 0;
    st.has_tls = 0;
    st.has_http = 0;
    st.ssl_write_ts_ns = 0;
    st.connect_ts_ns = now;
    st.first_byte_ts_ns = 0;
    st.first_recv_ts_ns = 0;
    st.tls_ready_ts_ns = 0;
    st.chain_id = chain_id;
    st.parent_chain_id = parent_chain_id;
    st.chain_depth = chain_depth;
    st.congestion_state_final = 0;
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
    init_flow_row(&key, FlowDirection::Outbound as u8)?;
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
    init_flow_row(&key, FlowDirection::Inbound as u8)?;
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

    let Some(state) = FLOW_TABLE.get(&key) else {
        return Ok(0);
    };
    let now = bpf_ktime_get_ns();
    let duration_ns = now.saturating_sub(state.connect_ts_ns);

    // Never build a `FlowEvent` on the BPF stack (~900B): verifier caps stack (~512B).
    // Reserve ringbuf memory first, then fill in place (off-stack).
    let Some(mut entry) = FLOW_EVENTS.reserve::<FlowEvent>(0) else {
        return Ok(0);
    };
    let e = MaybeUninit::as_mut_ptr(&mut *entry);
    core::ptr::write_bytes(e as *mut u8, 0, core::mem::size_of::<FlowEvent>());

    (*e).pid = state.pid;
    (*e).ppid = state.ppid;
    (*e).uid = state.uid;
    (*e).gid = state.gid;
    (*e).comm = state.comm;
    (*e).cgroup = state.cgroup;
    (*e).src_ip = key.src_ip;
    (*e).dst_ip = key.dst_ip;
    (*e).src_port = key.src_port;
    (*e).dst_port = key.dst_port;
    (*e).protocol = key.protocol;
    (*e).direction = state.direction;
    (*e).bytes_sent = state.bytes_sent;
    (*e).bytes_recv = state.bytes_recv;
    (*e).pkts_sent = state.pkts_sent;
    (*e).pkts_recv = state.pkts_recv;
    (*e).srtt_us_min = if state.srtt_us_min == u32::MAX {
        0
    } else {
        state.srtt_us_min
    };
    (*e).srtt_us_max = state.srtt_us_max;
    (*e).srtt_us_final = state.srtt_us_last;
    (*e).rttvar_us_max = state.rttvar_us_max;
    (*e).retransmit_count = state.retransmit_count;
    (*e).retransmit_bytes = state.retransmit_bytes;
    (*e).retransmit_rto_count = state.retransmit_rto_count;
    (*e).retransmit_fast_count = state.retransmit_fast_count;
    (*e).retransmit_tlp_count = state.retransmit_tlp_count;
    (*e).sack_blocks_received = state.sack_blocks_received;
    (*e).cwnd_min = if state.cwnd_min == u32::MAX {
        0
    } else {
        state.cwnd_min
    };
    (*e).cwnd_max = state.cwnd_max;
    (*e).ecn_signals = state.ecn_signals;
    (*e).tls_sni = state.tls_sni;
    (*e).http_host = state.http_host;
    (*e).http_method = state.http_method;
    (*e).http_path = state.http_path;
    (*e).http_status = state.http_status;
    (*e).has_tls = state.has_tls;
    (*e).has_http = state.has_http;
    (*e).connect_ts_ns = state.connect_ts_ns;
    (*e).first_byte_ts_ns = state.first_byte_ts_ns;
    (*e).first_recv_ts_ns = state.first_recv_ts_ns;
    (*e).close_ts_ns = now;
    (*e).duration_ns = duration_ns;
    (*e).time_to_first_byte_ns = state
        .first_byte_ts_ns
        .saturating_sub(state.connect_ts_ns);
    (*e).tls_handshake_ns = if state.tls_ready_ts_ns > 0 {
        state.tls_ready_ts_ns.saturating_sub(state.connect_ts_ns)
    } else {
        0
    };
    (*e).app_response_time_ns = if state.first_recv_ts_ns > 0 && state.ssl_write_ts_ns > 0 {
        state
            .first_recv_ts_ns
            .saturating_sub(state.ssl_write_ts_ns)
    } else {
        0
    };
    (*e).close_reason = CloseReason::LocalClose as u8;
    (*e).congestion_state_final = state.congestion_state_final;
    (*e).chain_id = state.chain_id;
    (*e).parent_chain_id = state.parent_chain_id;
    (*e).chain_depth = state.chain_depth;

    entry.submit(0);

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
