//! BPF loader — loads and attaches all eBPF programs, runs the event loop.
//!
//! Build with aya on Rust 1.79+:
//!   Add to Cargo.toml: aya = { version = "0.13", features = ["async_tokio"] }
//!   Add to Cargo.toml: aya-log = { version = "0.2" }
//!
//! Without aya (stub mode): runs a synthetic event so the output pipeline
//! can be verified without kernel privileges.

use flow_sensor_common::FlowEvent;
use tokio::signal;
use tracing::info;

use crate::{enricher, printer, EventFilter};

pub struct BpfHandle {
    // In real impl: pub bpf: aya::Bpf
    _private: (),
}

/// Load and attach all eBPF programs to the kernel.
/// Requires CAP_BPF + CAP_NET_ADMIN (root).
pub async fn load_and_attach(interface: &str) -> anyhow::Result<BpfHandle> {
    info!("Attaching eBPF programs to interface: {}", interface);

    // ── Real aya implementation (uncomment when aya is in Cargo.toml) ────────
    //
    // use aya::{include_bytes_aligned, Bpf};
    // use aya::programs::{KProbe, KRetProbe};
    // use aya_log::BpfLogger;
    //
    // let bpf_bytes = include_bytes_aligned!(
    //     "../../target/bpfel-unknown-none/release/flow-sensor-ebpf"
    // );
    // let mut bpf = Bpf::load(bpf_bytes)?;
    // if let Err(e) = BpfLogger::init(&mut bpf) {
    //     tracing::warn!("BPF logger init failed: {}", e);
    // }
    //
    // // TCP lifecycle
    // attach_kprobe(&mut bpf, "tcp_connect", "tcp_connect")?;
    // attach_kretprobe(&mut bpf, "inet_csk_accept", "inet_csk_accept")?;
    // attach_kprobe(&mut bpf, "tcp_close", "tcp_close")?;
    // attach_kprobe(&mut bpf, "tcp_sendmsg", "tcp_sendmsg")?;
    // attach_kprobe(&mut bpf, "tcp_send_active_reset", "tcp_send_active_reset")?;
    //
    // // TCP quality
    // attach_kprobe(&mut bpf, "tcp_rcv_established", "tcp_rcv_established")?;
    // attach_kprobe(&mut bpf, "tcp_enter_cwr", "tcp_enter_cwr")?;
    // attach_kprobe(&mut bpf, "tcp_enter_loss", "tcp_enter_loss")?;
    // attach_kprobe(&mut bpf, "tcp_enter_recovery", "tcp_enter_recovery")?;
    //
    // // Retransmit reasons
    // attach_kprobe(&mut bpf, "tcp_retransmit_skb", "tcp_retransmit_skb")?;
    // attach_kprobe(&mut bpf, "tcp_send_loss_probe", "tcp_send_loss_probe")?;
    // attach_kprobe(&mut bpf, "tcp_sacktag_write_queue", "tcp_sacktag_write_queue")?;
    //
    // // Causal chains
    // attach_kprobe(&mut bpf, "wake_up_new_task", "wake_up_new_task")?;
    // attach_kprobe(&mut bpf, "do_exit", "do_exit")?;
    //
    // return Ok(BpfHandle { bpf });
    // ─────────────────────────────────────────────────────────────────────────

    info!("Stub mode — aya not compiled in. Add aya to Cargo.toml for live BPF.");
    Ok(BpfHandle { _private: () })
}

// /// Attach a kprobe program by name
// fn attach_kprobe(bpf: &mut aya::Bpf, prog: &str, func: &str) -> anyhow::Result<()> {
//     use aya::programs::KProbe;
//     let p: &mut KProbe = bpf.program_mut(prog)
//         .ok_or_else(|| anyhow::anyhow!("program {} not found", prog))?
//         .try_into()?;
//     p.load()?;
//     p.attach(func, 0)?;
//     tracing::debug!("kprobe attached: {} -> {}", prog, func);
//     Ok(())
// }
//
// /// Attach a kretprobe program by name
// fn attach_kretprobe(bpf: &mut aya::Bpf, prog: &str, func: &str) -> anyhow::Result<()> {
//     use aya::programs::KRetProbe;
//     let p: &mut KRetProbe = bpf.program_mut(prog)
//         .ok_or_else(|| anyhow::anyhow!("program {} not found", prog))?
//         .try_into()?;
//     p.load()?;
//     p.attach(func, 0)?;
//     tracing::debug!("kretprobe attached: {} -> {}", prog, func);
//     Ok(())
// }

/// Main event loop — reads FlowEvents from ring buffer, enriches, outputs.
pub async fn event_loop(
    _handle: BpfHandle,
    output_format: &str,
    filter: EventFilter,
) -> anyhow::Result<()> {
    // ── Real aya ring buffer loop (uncomment with aya) ────────────────────────
    //
    // use aya::maps::RingBuf;
    // let mut ring = {
    //     let map = _handle.bpf.map_mut("FLOW_EVENTS")
    //         .ok_or_else(|| anyhow::anyhow!("FLOW_EVENTS map not found"))?;
    //     RingBuf::try_from(map)?
    // };
    // let mut count = 0u64;
    // loop {
    //     tokio::select! {
    //         _ = signal::ctrl_c() => {
    //             info!("Total flows: {}", count);
    //             break;
    //         }
    //         _ = tokio::time::sleep(tokio::time::Duration::from_millis(1)) => {
    //             while let Some(item) = ring.next() {
    //                 let event = unsafe { &*(item.as_ptr() as *const FlowEvent) };
    //                 count += 1;
    //                 if !filter.matches(event) { continue; }
    //                 let enriched = enricher::enrich(event);
    //                 match output_format {
    //                     "json" | "jsonl" => printer::print_json(&enriched),
    //                     _ => printer::print_pretty(&enriched),
    //                 }
    //             }
    //         }
    //     }
    // }
    // ─────────────────────────────────────────────────────────────────────────

    info!("Event loop: stub mode — emitting synthetic test event");

    let event = make_test_event();
    if filter.matches(&event) {
        let enriched = enricher::enrich(&event);
        match output_format {
            "json" | "jsonl" => printer::print_json(&enriched),
            _ => printer::print_pretty(&enriched),
        }
    }

    info!("Waiting for Ctrl+C...");
    signal::ctrl_c().await?;
    Ok(())
}

/// Synthetic flow event for verifying the output pipeline without live BPF.
/// Represents a python3 script hitting api.bigpanda.io through a proxy,
/// with retransmits and TLS context — exactly the use case we designed for.
fn make_test_event() -> FlowEvent {
    let mut e = unsafe { std::mem::zeroed::<FlowEvent>() };

    e.pid        = std::process::id();
    e.uid        = libc_getuid();
    e.src_ip     = u32::from_be_bytes([10, 0, 1, 50]);
    e.dst_ip     = u32::from_be_bytes([104, 18, 20, 1]);  // Cloudflare (bigpanda CDN)
    e.src_port   = 54821;
    e.dst_port   = 443;
    e.protocol   = 6; // TCP
    e.direction  = flow_sensor_common::FlowDirection::Outbound as u8;

    e.bytes_sent = 1240;
    e.bytes_recv = 48200;
    e.pkts_sent  = 12;
    e.pkts_recv  = 38;

    e.srtt_us_min   = 1800;
    e.srtt_us_max   = 4200;
    e.srtt_us_final = 2100;
    e.rttvar_us_max = 800;

    e.retransmit_count      = 3;
    e.retransmit_rto_count  = 1;
    e.retransmit_fast_count = 2;
    e.retransmit_tlp_count  = 0;
    e.retransmit_bytes      = 2480;
    e.sack_blocks_received  = 2;

    e.cwnd_min  = 10;
    e.cwnd_max  = 32;
    e.ecn_signals = 0;

    e.has_tls = 1;
    e.has_http = 1;

    copy_str(&mut e.comm,        b"python3");
    copy_str(&mut e.tls_sni,     b"api.bigpanda.io");
    copy_str(&mut e.http_host,   b"api.bigpanda.io");
    copy_str(&mut e.http_method, b"POST");
    copy_str(&mut e.http_path,   b"/api/v2/alerts");
    e.http_status = 200;

    e.connect_ts_ns         = 0;
    e.duration_ns           = 142_800_000;
    e.time_to_first_byte_ns = 13_200_000;
    e.tls_handshake_ns      = 12_400_000;
    e.app_response_time_ns  = 48_200_000;

    e.close_reason = flow_sensor_common::CloseReason::Clean as u8;

    e.chain_id        = 0xf7a2b1c3d4e5f601;
    e.parent_chain_id = 0;
    e.chain_depth     = 0;

    e
}

fn copy_str(dst: &mut [u8], src: &[u8]) {
    let len = src.len().min(dst.len().saturating_sub(1));
    dst[..len].copy_from_slice(&src[..len]);
}

fn libc_getuid() -> u32 { 0 }
