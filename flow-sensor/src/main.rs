//! Flow Sensor — userspace daemon.
//! Loads eBPF programs into the kernel, reads events from ring buffers,
//! enriches them, and exports to configured outputs (console, gRPC, etc.)

mod loader;
mod enricher;
mod printer;
mod tls_attach;

use clap::Parser;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "flow-sensor")]
#[command(about = "eBPF-powered network flow sensor with process attribution and TLS visibility")]
struct Args {
    /// Network interface to attach XDP program to
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// Output format: pretty, json, or jsonl
    #[arg(short, long, default_value = "pretty")]
    output: String,

    /// Minimum duration to report (filters out very short connections), in ms
    #[arg(long, default_value = "0")]
    min_duration_ms: u64,

    /// Only report flows involving these ports (comma-separated, empty = all)
    #[arg(long, default_value = "")]
    ports: String,

    /// Enable TLS uprobe attachment to libssl (requires target process PIDs or all)
    #[arg(long, default_value = "true")]
    tls: bool,

    /// Attach TLS probes to specific PIDs (comma-separated, empty = system-wide)
    #[arg(long, default_value = "")]
    tls_pids: String,

    /// Sample rate: 1 = every flow, N = 1-in-N sampling
    #[arg(long, default_value = "1")]
    sample_rate: u32,

    /// Show only flows with retransmits
    #[arg(long, default_value = "false")]
    retransmits_only: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("flow_sensor=info".parse()?))
        .with_target(false)
        .init();

    let args = Args::parse();

    // Check privileges
    if !nix::unistd::getuid().is_root() {
        error!("flow-sensor requires root privileges (CAP_BPF, CAP_NET_ADMIN)");
        std::process::exit(1);
    }

    info!("🔬 Flow Sensor starting up");
    info!("   Interface: {}", args.interface);
    info!("   Output: {}", args.output);
    info!("   TLS probes: {}", args.tls);

    // Parse port filter
    let port_filter: Vec<u16> = if args.ports.is_empty() {
        vec![]
    } else {
        args.ports.split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    };

    // Parse TLS PIDs
    let tls_pids: Vec<u32> = if args.tls_pids.is_empty() {
        vec![]
    } else {
        args.tls_pids.split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect()
    };

    // Load and attach all eBPF programs
    let mut bpf_handle = loader::load_and_attach(&args.interface).await?;

    // Attach TLS uprobes if enabled
    if args.tls {
        tls_attach::attach_tls_probes(&mut bpf_handle, &tls_pids).await?;
    }

    info!("✅ eBPF programs loaded and attached");
    info!("📡 Listening for flows... (Ctrl+C to stop)\n");

    // Print header
    printer::print_header(&args.output);

    // Event loop — read from ring buffer, enrich, print
    let filter = EventFilter {
        min_duration_ms: args.min_duration_ms,
        port_filter,
        retransmits_only: args.retransmits_only,
        sample_rate: args.sample_rate,
    };

    loader::event_loop(bpf_handle, &args.output, filter).await?;

    Ok(())
}

pub struct EventFilter {
    pub min_duration_ms: u64,
    pub port_filter: Vec<u16>,
    pub retransmits_only: bool,
    pub sample_rate: u32,
}

impl EventFilter {
    pub fn matches(&self, event: &flow_sensor_common::FlowEvent) -> bool {
        // Duration filter
        if self.min_duration_ms > 0 {
            let duration_ms = event.duration_ns / 1_000_000;
            if duration_ms < self.min_duration_ms { return false; }
        }

        // Port filter
        if !self.port_filter.is_empty() {
            let port_match = self.port_filter.contains(&event.src_port)
                || self.port_filter.contains(&event.dst_port);
            if !port_match { return false; }
        }

        // Retransmit filter
        if self.retransmits_only && event.retransmit_count == 0 {
            return false;
        }

        // Sampling
        if self.sample_rate > 1 {
            // Use flow's chain_id as a stable hash for consistent sampling
            if event.chain_id % self.sample_rate as u64 != 0 { return false; }
        }

        true
    }
}
