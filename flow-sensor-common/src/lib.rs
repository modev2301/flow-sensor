//! Shared types between eBPF kernel programs and userspace.
//! Must be #![no_std] compatible so it can compile for both targets.

#![cfg_attr(not(feature = "std"), no_std)]

/// Maximum length for process name (comm)
pub const COMM_LEN: usize = 16;
/// Maximum length for TLS SNI / HTTP Host header
pub const HOST_LEN: usize = 256;
/// Maximum length for HTTP path
pub const PATH_LEN: usize = 256;
/// Maximum length for cgroup path (k8s pod identity)
pub const CGROUP_LEN: usize = 128;

/// Why a retransmit occurred — richer than just a count
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetransmitReason {
    Unknown = 0,
    /// Retransmit timeout fired — true packet loss
    Rto = 1,
    /// 3 duplicate ACKs — congestion signal
    FastRetransmit = 2,
    /// Selective ACK based retransmit
    Sack = 3,
    /// Tail Loss Probe — speculative, faster than RTO
    Tlp = 4,
}

/// Why a connection closed
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Unknown = 0,
    /// Clean FIN exchange
    Clean = 1,
    /// RST received or sent
    Reset = 2,
    /// Connection timed out
    Timeout = 3,
    /// Local process called close()
    LocalClose = 4,
}

/// TCP congestion state
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    Open = 0,       // Normal
    Disorder = 1,   // Some reordering or loss
    Cwr = 2,        // ECN congestion window reduced
    Recovery = 3,   // Fast recovery
    Loss = 4,       // Loss-based recovery
}

/// Direction of the flow from this host's perspective
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection {
    Unknown = 0,
    Outbound = 1,   // This host initiated
    Inbound = 2,    // Remote host initiated
}

/// Retransmit event — emitted immediately on each retransmit
/// These are aggregated into FlowEvent on connection close
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RetransmitEvent {
    pub timestamp_ns: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub reason: u8,         // RetransmitReason
    pub seq: u32,           // sequence number retransmitted
    pub rto_us: u32,        // RTO value at time of retransmit
    pub srtt_us: u32,       // smoothed RTT at time of retransmit
    pub cwnd: u32,          // congestion window at time of retransmit
    pub pid: u32,
}

/// TLS/HTTP event — emitted on SSL_write (outbound) or SSL_read (inbound)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub is_read: u8,                    // 0=write (outbound), 1=read (inbound)
    pub sni: [u8; HOST_LEN],            // TLS SNI
    pub http_host: [u8; HOST_LEN],      // HTTP Host header
    pub http_method: [u8; 8],           // GET, POST, etc.
    pub http_path: [u8; PATH_LEN],      // request path
    pub http_status: u16,               // response status (on read)
    pub payload_len: u32,
}

/// TCP quality sample — emitted periodically per connection
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpQualityEvent {
    pub timestamp_ns: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub srtt_us: u32,       // smoothed RTT
    pub rttvar_us: u32,     // RTT variance (jitter)
    pub cwnd: u32,          // congestion window
    pub rcv_wnd: u32,       // receive window
    pub lost_out: u32,      // packets marked lost
    pub retrans_out: u32,   // packets currently in retransmit
    pub sacked_out: u32,    // SACK'd packets
    pub bytes_acked: u64,
    pub bytes_retrans: u64,
}

/// The canonical complete flow event — emitted when a connection closes
/// This is the primary output of the sensor
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FlowEvent {
    // ── Identity ────────────────────────────────────────────────
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; COMM_LEN],           // process name e.g. "python3"
    pub cgroup: [u8; CGROUP_LEN],       // k8s pod/container identity

    // ── Network ─────────────────────────────────────────────────
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,                   // 6=TCP, 17=UDP
    pub direction: u8,                  // FlowDirection

    // ── Volume ──────────────────────────────────────────────────
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub pkts_sent: u64,
    pub pkts_recv: u64,

    // ── TCP Quality — aggregated over connection lifetime ────────
    pub srtt_us_min: u32,
    pub srtt_us_max: u32,
    pub srtt_us_final: u32,
    pub rttvar_us_max: u32,             // peak jitter

    // ── Loss ────────────────────────────────────────────────────
    pub retransmit_count: u32,
    pub retransmit_bytes: u64,
    pub retransmit_rto_count: u32,      // true loss events
    pub retransmit_fast_count: u32,     // congestion events
    pub retransmit_tlp_count: u32,      // tail loss probes
    pub sack_blocks_received: u32,

    // ── Congestion ──────────────────────────────────────────────
    pub cwnd_min: u32,
    pub cwnd_max: u32,
    pub ecn_signals: u32,               // explicit congestion notifications

    // ── Application Layer (from uprobes) ────────────────────────
    pub tls_sni: [u8; HOST_LEN],
    pub http_host: [u8; HOST_LEN],
    pub http_method: [u8; 8],
    pub http_path: [u8; PATH_LEN],
    pub http_status: u16,
    pub has_tls: u8,                    // 1 if TLS was observed
    pub has_http: u8,                   // 1 if HTTP was parsed

    // ── Timing ──────────────────────────────────────────────────
    pub connect_ts_ns: u64,
    pub first_byte_ts_ns: u64,          // time to first byte sent
    pub first_recv_ts_ns: u64,          // time to first byte received
    pub close_ts_ns: u64,
    pub duration_ns: u64,

    // ── Derived timing ──────────────────────────────────────────
    pub time_to_first_byte_ns: u64,     // connect → first data sent
    pub tls_handshake_ns: u64,          // TCP connect → SSL ready
    pub app_response_time_ns: u64,      // first write → first read back

    // ── Lifecycle ───────────────────────────────────────────────
    pub close_reason: u8,               // CloseReason
    pub congestion_state_final: u8,     // CongestionState at close

    // ── Causal chain ────────────────────────────────────────────
    pub chain_id: u64,                  // links flows causally
    pub parent_chain_id: u64,           // 0 if origin
    pub chain_depth: u32,
}

impl FlowEvent {
    /// Source IP as a formatted string — convenience for display
    #[cfg(feature = "std")]
    pub fn src_ip_str(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.src_ip.to_be())
    }

    #[cfg(feature = "std")]
    pub fn dst_ip_str(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.dst_ip.to_be())
    }

    #[cfg(feature = "std")]
    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
        std::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }

    #[cfg(feature = "std")]
    pub fn sni_str(&self) -> &str {
        let end = self.tls_sni.iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&self.tls_sni[..end]).unwrap_or("")
    }

    #[cfg(feature = "std")]
    pub fn http_host_str(&self) -> &str {
        let end = self.http_host.iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&self.http_host[..end]).unwrap_or("")
    }

    #[cfg(feature = "std")]
    pub fn http_path_str(&self) -> &str {
        let end = self.http_path.iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&self.http_path[..end]).unwrap_or("")
    }

    #[cfg(feature = "std")]
    pub fn retransmit_rate_pct(&self) -> f64 {
        if self.pkts_sent == 0 { return 0.0; }
        (self.retransmit_count as f64 / self.pkts_sent as f64) * 100.0
    }

    #[cfg(feature = "std")]
    pub fn close_reason(&self) -> CloseReason {
        match self.close_reason {
            1 => CloseReason::Clean,
            2 => CloseReason::Reset,
            3 => CloseReason::Timeout,
            4 => CloseReason::LocalClose,
            _ => CloseReason::Unknown,
        }
    }
}
