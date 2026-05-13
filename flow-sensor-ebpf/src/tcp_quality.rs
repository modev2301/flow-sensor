//! TCP quality hooks — continuous RTT, jitter, congestion window tracking.
//! Fires on every ACK received, updating per-flow quality metrics in-place.
//! Much richer than IPFIX which only captures RTT at handshake time.

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
};
use flow_sensor_common::*;

use crate::{kread, maps::*};

// Offsets into struct tcp_sock for quality fields
// Verified against Linux 5.8-6.x
pub(crate) const TCP_SRTT_US_OFFSET: usize = 0x1E0; // srtt_us (smoothed RTT << 3)
const TCP_RTTVAR_US_OFFSET: usize = 0x1E4; // rttvar_us (variance << 2)
const TCP_SND_CWND_OFFSET: usize = 0x1AC;   // snd_cwnd
const TCP_ICSK_CA_STATE_OFFSET: usize = 0x164; // inet_csk.icsk_ca_state
// ── inet_sock / sock offsets ─────────────────────────────────────────────
// Must match kernel layout used elsewhere (tcp_lifecycle, retransmit, etc)

const INET_DADDR_OFFSET: usize = 0x0;  // inet_daddr
const INET_SADDR_OFFSET: usize = 0x4;  // inet_saddr
const INET_DPORT_OFFSET: usize = 0xA;  // inet_dport (network byte order)
const INET_SPORT_OFFSET: usize = 0xC;  // inet_sport (network byte order)

// struct sock
const SK_PROTO_OFFSET: usize = 0x3;    // sk_protocol
/// Fires on every established TCP ACK received.
/// This is the highest-frequency hook — be efficient.
#[kprobe(function = "tcp_rcv_established")]
pub fn tcp_rcv_established(ctx: ProbeContext) -> u32 {
    match unsafe { handle_rcv_established(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_rcv_established(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk = ctx.arg::<*const u8>(0).ok_or(-1)?;

    // Read TCP quality fields directly from struct tcp_sock
    let srtt_us_raw = kread::read_u32_ne(sk.add(TCP_SRTT_US_OFFSET))?;
    let rttvar_us_raw = kread::read_u32_ne(sk.add(TCP_RTTVAR_US_OFFSET))?;
    let cwnd = kread::read_u32_ne(sk.add(TCP_SND_CWND_OFFSET))?;

    // Kernel stores srtt as (actual_rtt << 3) for precision — shift back
    let srtt_us = srtt_us_raw >> 3;
    // rttvar stored as (variance << 2)
    let rttvar_us = rttvar_us_raw >> 2;

    // Extract flow key from sock
    let mut key = core::mem::MaybeUninit::<FlowKey>::uninit();
    if !flow_key_from_sk(sk, key.as_mut_ptr()) {
        return Err(-1);
    }
    let key = unsafe { key.assume_init() };

    if let Some(state) = FLOW_TABLE.get_ptr_mut(&key) {
        let s = &mut *state;

        // Track min/max RTT over connection lifetime
        if srtt_us > 0 {
            if srtt_us < s.srtt_us_min { s.srtt_us_min = srtt_us; }
            if srtt_us > s.srtt_us_max { s.srtt_us_max = srtt_us; }
            s.srtt_us_last = srtt_us;
        }

        // Peak jitter
        if rttvar_us > s.rttvar_us_max { s.rttvar_us_max = rttvar_us; }

        // Congestion window
        if cwnd < s.cwnd_min { s.cwnd_min = cwnd; }
        if cwnd > s.cwnd_max { s.cwnd_max = cwnd; }

        // Track congestion state
        let ca_state = kread::read_u8(sk.add(TCP_ICSK_CA_STATE_OFFSET)).unwrap_or(0);
        s.congestion_state_final = ca_state;
    }

    Ok(0)
}

/// Fires when ECN congestion signal received (explicit congestion notification)
/// This means the network is signaling congestion BEFORE dropping packets
#[kprobe(function = "tcp_enter_cwr")]
pub fn tcp_enter_cwr(ctx: ProbeContext) -> u32 {
    match unsafe { handle_ecn(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_ecn(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk = ctx.arg::<*const u8>(0).ok_or(-1)?;
    let mut key = core::mem::MaybeUninit::<FlowKey>::uninit();
    if !flow_key_from_sk(sk, key.as_mut_ptr()) {
        return Err(-1);
    }
let key = unsafe { key.assume_init() };

    if let Some(state) = FLOW_TABLE.get_ptr_mut(&key) {
        (*state).ecn_signals = (*state).ecn_signals.saturating_add(1);
    }
    Ok(0)
}

/// Fires when entering loss recovery — true packet loss detected
#[kprobe(function = "tcp_enter_loss")]
pub fn tcp_enter_loss(ctx: ProbeContext) -> u32 {
    match unsafe { handle_enter_loss(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_enter_loss(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk = ctx.arg::<*const u8>(0).ok_or(-1)?;
    let mut key = core::mem::MaybeUninit::<FlowKey>::uninit();
    if !flow_key_from_sk(sk, key.as_mut_ptr()) {
        return Err(-1);
    }
let key = unsafe { key.assume_init() };

    if let Some(state) = FLOW_TABLE.get_ptr_mut(&key) {
        (*state).congestion_state_final = CongestionState::Loss as u8;
    }
    Ok(0)
}

/// Fires on fast recovery (3 dup ACKs) — congestion signal
#[kprobe(function = "tcp_enter_recovery")]
pub fn tcp_enter_recovery(ctx: ProbeContext) -> u32 {
    match unsafe { handle_enter_recovery(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_enter_recovery(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk = ctx.arg::<*const u8>(0).ok_or(-1)?;
    let mut key = core::mem::MaybeUninit::<FlowKey>::uninit();
    if !flow_key_from_sk(sk, key.as_mut_ptr()) {
        return Err(-1);
}
let key = unsafe { key.assume_init() };

    if let Some(state) = FLOW_TABLE.get_ptr_mut(&key) {
        (*state).congestion_state_final = CongestionState::Recovery as u8;
    }
    Ok(0)
}

// ── Helper ───────────────────────────────────────────────────────────────────

/// Extract FlowKey from a raw sock pointer using known struct offsets
pub(crate) unsafe fn flow_key_from_sk(
    sk: *const u8,
    out: *mut FlowKey,
) -> bool {
    // NOTE: no '?' here; return false on any failed read
    let dst_ip = match kread::read_u32_ne(sk.add(INET_DADDR_OFFSET)) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let src_ip = match kread::read_u32_ne(sk.add(INET_SADDR_OFFSET)) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let dst_port = match kread::read_u16_ne(sk.add(INET_DPORT_OFFSET)) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let src_port = match kread::read_u16_ne(sk.add(INET_SPORT_OFFSET)) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let protocol = match kread::read_u8(sk.add(SK_PROTO_OFFSET)) {
        Ok(v) => v,
        Err(_) => return false,
    };

    (*out).src_ip = src_ip;
    (*out).dst_ip = dst_ip;
    (*out).src_port = u16::from_be(src_port);
    (*out).dst_port = u16::from_be(dst_port);
    (*out).protocol = protocol;

    // explicit padding writes (avoid memset/stack-return helpers)
    let pad = core::ptr::addr_of_mut!((*out)._pad) as *mut u8;
    core::ptr::write(pad.add(0), 0);
    core::ptr::write(pad.add(1), 0);
    core::ptr::write(pad.add(2), 0);

    true
}

