//! BPF map definitions — shared state between all programs and userspace.
//! Maps are the primary communication channel: kernel ↔ kernel and kernel ↔ userspace.

use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap, PerfEventArray, RingBuf},
};
use flow_sensor_common::*;

// ── Output ring buffers (kernel → userspace) ─────────────────────────────────

/// Primary output: complete flow events emitted on connection close
/// RingBuf is more efficient than PerfEventArray for large structs
#[map]
pub static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0); // 16MB

/// Retransmit events — emitted immediately, aggregated in userspace
#[map]
pub static RETRANSMIT_EVENTS: PerfEventArray<RetransmitEvent> = PerfEventArray::new(0);

/// TCP quality samples — periodic RTT/cwnd observations
#[map]
pub static QUALITY_EVENTS: PerfEventArray<TcpQualityEvent> = PerfEventArray::new(0);

/// TLS/HTTP events — from uprobes on libssl
#[map]
pub static TLS_EVENTS: PerfEventArray<TlsEvent> = PerfEventArray::new(0);

// ── Flow state table (per active connection) ─────────────────────────────────

/// Key for all flow state lookups
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

/// Per-connection state accumulated while connection is alive
/// Written by multiple BPF programs, read and zeroed on close
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowState {
    // Identity (set on connect)
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; COMM_LEN],
    pub cgroup: [u8; CGROUP_LEN],
    pub direction: u8,

    // Counters
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub pkts_sent: u64,
    pub pkts_recv: u64,

    // TCP quality — accumulated
    pub srtt_us_min: u32,
    pub srtt_us_max: u32,
    pub srtt_us_last: u32,
    pub rttvar_us_max: u32,
    pub cwnd_min: u32,
    pub cwnd_max: u32,
    pub ecn_signals: u32,

    // Loss counters
    pub retransmit_count: u32,
    pub retransmit_bytes: u64,
    pub retransmit_rto_count: u32,
    pub retransmit_fast_count: u32,
    pub retransmit_tlp_count: u32,
    pub sack_blocks_received: u32,

    // Application layer (from uprobes)
    pub tls_sni: [u8; HOST_LEN],
    pub http_host: [u8; HOST_LEN],
    pub http_method: [u8; 8],
    pub http_path: [u8; PATH_LEN],
    pub http_status: u16,
    pub has_tls: u8,
    pub has_http: u8,
    pub ssl_write_ts_ns: u64,   // for app response time calculation

    // Timing
    pub connect_ts_ns: u64,
    pub first_byte_ts_ns: u64,
    pub first_recv_ts_ns: u64,
    pub tls_ready_ts_ns: u64,

    // Causal chain
    pub chain_id: u64,
    pub parent_chain_id: u64,
    pub chain_depth: u32,

    // Congestion state at close
    pub congestion_state_final: u8,
}

/// LRU hash — kernel evicts oldest entries automatically under memory pressure
/// Key: FlowKey (5-tuple), Value: FlowState
#[map]
pub static FLOW_TABLE: LruHashMap<FlowKey, FlowState> =
    LruHashMap::with_max_entries(100_000, 0);

// ── Causal chain tracking ────────────────────────────────────────────────────

/// Per-thread causal context — follows execution across fork/clone
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CausalCtx {
    pub chain_id: u64,
    pub parent_chain_id: u64,
    pub depth: u32,
    pub origin_pid: u32,
    pub origin_ts_ns: u64,
}

/// Key: pid_tgid (u64)
#[map]
pub static CAUSAL_MAP: HashMap<u64, CausalCtx> =
    HashMap::with_max_entries(10_000, 0);

// ── Configuration (userspace → kernel) ───────────────────────────────────────

/// Runtime config pushed by userspace — no recompile needed to tune
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SensorConfig {
    pub sample_rate: u32,           // 1 = every event, N = 1-in-N sampling
    pub rtt_change_threshold_us: u32, // min RTT delta to emit quality event
    pub enable_tls_probes: u8,
    pub enable_http_parse: u8,
    pub enable_causal_chains: u8,
    pub _pad: [u8; 5],
}

/// Single-entry config map — index 0
#[map]
pub static CONFIG: aya_ebpf::maps::Array<SensorConfig> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);
