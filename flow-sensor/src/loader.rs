//! BPF loader — loads and attaches all eBPF programs, runs the event loop.
//!
//! On **Linux**, `aya` loads `flow-sensor-ebpf` and reads `FLOW_EVENTS` from a ring buffer.
//! On other targets, stub mode emits one synthetic event (for CI / macOS dev).

use flow_sensor_common::FlowEvent;
use tokio::signal;
use tracing::{info, warn};

use crate::{enricher, printer, EventFilter};

// ── Linux: live BPF ───────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod live {
    use super::*;
    use anyhow::Context;
    use aya::maps::RingBuf;
    use std::convert::TryInto;
    use std::io::Write;
    use std::path::PathBuf;

    pub struct BpfHandle {
        pub bpf: aya::Ebpf,
        ring: RingBuf<aya::maps::MapData>,
    }

    fn ebpf_object_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../flow-sensor-ebpf/target/bpfel-unknown-none/release/libflow_sensor_ebpf.so",
        )
    }

    fn attach_kprobe(bpf: &mut aya::Ebpf, prog: &str, kernel_fn: &str) -> anyhow::Result<()> {
        let program = bpf
            .program_mut(prog)
            .ok_or_else(|| anyhow::anyhow!("program `{prog}` not found in BPF object"))?;
        let p: &mut aya::programs::KProbe = program.try_into().with_context(|| {
            format!("program `{prog}` is not a kprobe/kretprobe (wrong type or missing)")
        })?;
        p.load()
            .with_context(|| format!("failed to load BPF program `{prog}`"))?;
        let _link = p
            .attach(kernel_fn, 0)
            .with_context(|| format!("failed to attach `{prog}` to kernel `{kernel_fn}`"))?;
        Ok(())
    }

    pub async fn load_and_attach(_interface: &str) -> anyhow::Result<BpfHandle> {
        info!("Loading eBPF (aya) — live mode");
        let path = ebpf_object_path();
        let data = std::fs::read(&path).with_context(|| {
            format!(
                "read BPF object {} — build the eBPF crate first (see README / ./build.sh)",
                path.display()
            )
        })?;

        let mut bpf = aya::Ebpf::load(&data).context("Ebpf::load failed")?;

        // (program section name, kernel function symbol)
        const ATTACH: &[(&str, &str)] = &[
            ("tcp_connect", "tcp_connect"),
            ("inet_csk_accept", "inet_csk_accept"),
            ("tcp_close", "tcp_close"),
            ("tcp_send_active_reset", "tcp_send_active_reset"),
            ("tcp_sendmsg", "tcp_sendmsg"),
            ("tcp_recvmsg", "tcp_recvmsg"),
            ("tcp_rcv_established", "tcp_rcv_established"),
            ("tcp_enter_cwr", "tcp_enter_cwr"),
            ("tcp_enter_loss", "tcp_enter_loss"),
            ("tcp_enter_recovery", "tcp_enter_recovery"),
            ("tcp_retransmit_skb", "tcp_retransmit_skb"),
            ("tcp_send_loss_probe", "tcp_send_loss_probe"),
            ("tcp_fast_retransmit", "tcp_retransmit_timer"),
            ("tcp_sacktag", "tcp_sacktag_write_queue"),
            ("on_new_task", "wake_up_new_task"),
            ("on_exit", "do_exit"),
        ];

        for (prog, kfn) in ATTACH {
            attach_kprobe(&mut bpf, prog, kfn)
                .with_context(|| format!("kprobe attach `{prog}` -> `{kfn}`"))?;
        }

        let map = bpf
            .take_map("FLOW_EVENTS")
            .context("map FLOW_EVENTS missing from BPF object")?;
        let ring =
            RingBuf::try_from(map).context("FLOW_EVENTS is not a BPF_MAP_TYPE_RINGBUF")?;

        Ok(BpfHandle { bpf, ring })
    }

    pub async fn event_loop(
        mut handle: BpfHandle,
        output_format: &str,
        filter: EventFilter,
    ) -> anyhow::Result<()> {
        info!("Event loop: FLOW_EVENTS ring buffer (live BPF)");
        let ring = &mut handle.ring;
        let mut count = 0u64;
        loop {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    info!("Total flows received: {}", count);
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(50)) => {
                    while let Some(item) = ring.next() {
                        if item.len() < std::mem::size_of::<FlowEvent>() {
                            continue;
                        }
                        let event = unsafe {
                            (item.as_ptr() as *const FlowEvent).read_unaligned()
                        };
                        count += 1;
                        if !filter.matches(&event) {
                            continue;
                        }
                        let enriched = enricher::enrich(&event);
                        match output_format {
                            "json" | "jsonl" => printer::print_json(&enriched),
                            _ => printer::print_pretty(&enriched),
                        }
                        let _ = std::io::stdout().flush();
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use live::{event_loop, load_and_attach, BpfHandle};

// ── Non-Linux: stub ───────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
pub struct BpfHandle {
    _private: (),
}

#[cfg(not(target_os = "linux"))]
pub async fn load_and_attach(interface: &str) -> anyhow::Result<BpfHandle> {
    info!("Attaching eBPF programs to interface: {}", interface);
    info!("Stub mode — aya is only linked on Linux. Build on Linux for live BPF.");
    Ok(BpfHandle { _private: () })
}

#[cfg(not(target_os = "linux"))]
pub async fn event_loop(
    _handle: BpfHandle,
    output_format: &str,
    filter: EventFilter,
) -> anyhow::Result<()> {
    use std::io::Write;

    info!("Event loop: stub mode — emitting synthetic test event");

    let event = make_test_event();
    if filter.matches(&event) {
        let enriched = enricher::enrich(&event);
        match output_format {
            "json" | "jsonl" => printer::print_json(&enriched),
            _ => printer::print_pretty(&enriched),
        }
        let _ = std::io::stdout().flush();
    } else {
        warn!(
            "Synthetic stub event was filtered out (CLI filters apply in stub mode too). \
             Try: omit --sample-rate / use --sample-rate 1, drop --ports / --retransmits-only, \
             or lower --min-duration-ms (stub flow duration ≈ 1.5s)."
        );
    }

    info!("Waiting for Ctrl+C...");
    signal::ctrl_c().await?;
    Ok(())
}

/// Synthetic flow event for verifying the output pipeline without live BPF.
#[cfg(not(target_os = "linux"))]
fn make_test_event() -> FlowEvent {
    let mut e = unsafe { std::mem::zeroed::<FlowEvent>() };

    e.pid = std::process::id();
    e.uid = 0;
    e.src_ip = u32::from_be_bytes([10, 0, 1, 50]);
    e.dst_ip = u32::from_be_bytes([104, 18, 20, 1]);
    e.src_port = 54821;
    e.dst_port = 443;
    e.protocol = 6;
    e.direction = flow_sensor_common::FlowDirection::Outbound as u8;

    e.bytes_sent = 1240;
    e.bytes_recv = 48200;
    e.pkts_sent = 12;
    e.pkts_recv = 38;

    e.srtt_us_min = 1800;
    e.srtt_us_max = 4200;
    e.srtt_us_final = 2100;
    e.rttvar_us_max = 800;

    e.retransmit_count = 3;
    e.retransmit_rto_count = 1;
    e.retransmit_fast_count = 2;
    e.retransmit_tlp_count = 0;
    e.retransmit_bytes = 2480;
    e.sack_blocks_received = 2;

    e.cwnd_min = 10;
    e.cwnd_max = 32;
    e.ecn_signals = 0;

    e.has_tls = 1;
    e.has_http = 1;

    copy_str(&mut e.comm, b"python3");
    copy_str(&mut e.tls_sni, b"api.bigpanda.io");
    copy_str(&mut e.http_host, b"api.bigpanda.io");
    copy_str(&mut e.http_method, b"POST");
    copy_str(&mut e.http_path, b"/api/v2/alerts");
    e.http_status = 200;

    e.connect_ts_ns = 0;
    e.duration_ns = 1_500_000_000;
    e.time_to_first_byte_ns = 13_200_000;
    e.tls_handshake_ns = 12_400_000;
    e.app_response_time_ns = 48_200_000;

    e.close_reason = flow_sensor_common::CloseReason::Clean as u8;

    e.chain_id = 0;
    e.parent_chain_id = 0;
    e.chain_depth = 0;

    e
}

#[cfg(not(target_os = "linux"))]
fn copy_str(dst: &mut [u8], src: &[u8]) {
    let len = src.len().min(dst.len().saturating_sub(1));
    dst[..len].copy_from_slice(&src[..len]);
}
