//! Retransmit tracking — the why behind every retransmit.
//! Standard NetFlow/IPFIX gives you a count. We give you reason, timing, and context.

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
};
use flow_sensor_common::*;

use crate::{kread, maps::*};
use crate::tcp_quality::flow_key_from_sk;

// Offsets into tcp_sock for retransmit-related fields
const TCP_RTO_OFFSET: usize = 0x1B8;        // icsk_rto (in jiffies, but we use srtt)
const TCP_SND_UNA_OFFSET: usize = 0x188;    // snd_una (last unacked)
const TCP_SND_NXT_OFFSET: usize = 0x18C;    // snd_nxt (next to send)

/// Fires on every retransmit — including RTO, fast retransmit, SACK, TLP
#[kprobe(function = "tcp_retransmit_skb")]
pub fn tcp_retransmit_skb(ctx: ProbeContext) -> u32 {
    match unsafe { handle_retransmit(&ctx, RetransmitReason::Rto) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/// Tail Loss Probe — speculative retransmit sent before RTO fires
/// Distinguishing TLP from RTO is significant: TLP = maybe lost, RTO = definitely lost
#[kprobe(function = "tcp_send_loss_probe")]
pub fn tcp_send_loss_probe(ctx: ProbeContext) -> u32 {
    match unsafe { handle_retransmit(&ctx, RetransmitReason::Tlp) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/// Fast retransmit — triggered by 3 duplicate ACKs, not timeout
/// This is a congestion signal, not necessarily packet loss
#[kprobe(function = "tcp_retransmit_timer")]  
pub fn tcp_fast_retransmit(ctx: ProbeContext) -> u32 {
    match unsafe { handle_retransmit(&ctx, RetransmitReason::FastRetransmit) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_retransmit(
    ctx: &ProbeContext,
    reason: RetransmitReason,
) -> Result<u32, i64> {
    let sk = ctx.arg::<*const u8>(0).ok_or(-1)?;
    let key = flow_key_from_sk(sk)?;

    // Read retransmit context from tcp_sock
    let srtt_us_raw = kread::read_u32_ne(sk.add(crate::tcp_quality::TCP_SRTT_US_OFFSET)).unwrap_or(0);
    let snd_una = kread::read_u32_ne(sk.add(TCP_SND_UNA_OFFSET)).unwrap_or(0);
    let snd_nxt = kread::read_u32_ne(sk.add(TCP_SND_NXT_OFFSET)).unwrap_or(0);

    let _srtt_us = srtt_us_raw >> 3;
    // Gap = bytes in flight that haven't been acknowledged
    let bytes_in_flight = snd_nxt.wrapping_sub(snd_una) as u64;

    // Update flow state
    if let Some(state) = FLOW_TABLE.get_ptr_mut(&key) {
        let s = &mut *state;
        s.retransmit_count = s.retransmit_count.saturating_add(1);
        s.retransmit_bytes = s.retransmit_bytes.saturating_add(bytes_in_flight);

        match reason {
            RetransmitReason::Rto => {
                s.retransmit_rto_count = s.retransmit_rto_count.saturating_add(1);
            }
            RetransmitReason::FastRetransmit => {
                s.retransmit_fast_count = s.retransmit_fast_count.saturating_add(1);
            }
            RetransmitReason::Tlp => {
                s.retransmit_tlp_count = s.retransmit_tlp_count.saturating_add(1);
            }
            _ => {}
        }
    }

    Ok(0)
}

/// SACK block received — selective acknowledgment, indicates partial loss
#[kprobe(function = "tcp_sacktag_write_queue")]
pub fn tcp_sacktag(ctx: ProbeContext) -> u32 {
    match unsafe { handle_sack(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_sack(ctx: &ProbeContext) -> Result<u32, i64> {
    let sk = ctx.arg::<*const u8>(0).ok_or(-1)?;
    let key = flow_key_from_sk(sk)?;

    if let Some(state) = FLOW_TABLE.get_ptr_mut(&key) {
        (*state).sack_blocks_received = (*state).sack_blocks_received.saturating_add(1);
    }
    Ok(0)
}
