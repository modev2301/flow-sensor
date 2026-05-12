//! Userspace enrichment — adds context that can't be gathered in BPF.
//! BPF programs run with strict limits; we do richer lookups here.

use flow_sensor_common::FlowEvent;
use std::net::Ipv4Addr;

/// Enriched flow event — FlowEvent plus userspace-resolved metadata
#[derive(Debug)]
pub struct EnrichedFlow {
    pub event: FlowEvent,

    // Resolved from /proc
    pub ppid: Option<u32>,
    pub exe_path: Option<String>,       // /proc/pid/exe → real binary path
    pub cmdline: Option<String>,        // /proc/pid/cmdline

    // Resolved cgroup → k8s identity
    pub k8s_pod: Option<String>,
    pub k8s_namespace: Option<String>,
    pub k8s_container: Option<String>,

    // Network context
    pub dst_hostname: Option<String>,   // reverse DNS (cached)
    pub dst_asn: Option<u32>,
    pub dst_org: Option<String>,

    // Computed
    pub is_external: bool,              // dst is public IP
    pub protocol_guess: Option<String>, // guessed from port if not in TLS/HTTP
}

/// Enrich a raw FlowEvent with userspace-resolved metadata
pub fn enrich(event: &FlowEvent) -> EnrichedFlow {
    let pid = event.pid;
    let dst_ip = Ipv4Addr::from(event.dst_ip.to_be());

    // Resolve process info from /proc
    let (ppid, exe_path, cmdline) = resolve_proc(pid);

    // Resolve cgroup → k8s identity
    let (k8s_pod, k8s_namespace, k8s_container) = resolve_cgroup(event);

    // Check if destination is external (public IP)
    let is_external = is_public_ip(dst_ip);

    // Guess application protocol from port if we don't have TLS/HTTP context
    let protocol_guess = if event.has_http == 1 {
        Some("HTTP".to_string())
    } else if event.has_tls == 1 {
        Some("TLS".to_string())
    } else {
        guess_protocol(event.dst_port)
    };

    EnrichedFlow {
        event: *event,
        ppid,
        exe_path,
        cmdline,
        k8s_pod,
        k8s_namespace,
        k8s_container,
        dst_hostname: None,     // async DNS lookup — done lazily or via cache
        dst_asn: None,          // GeoIP lookup — pluggable
        dst_org: None,
        is_external,
        protocol_guess,
    }
}

/// Read process metadata from /proc filesystem
fn resolve_proc(pid: u32) -> (Option<u32>, Option<String>, Option<String>) {
    let proc_path = format!("/proc/{}", pid);

    // Read ppid from /proc/pid/status
    let ppid = std::fs::read_to_string(format!("{}/status", proc_path))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PPid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        });

    // Resolve exe path (symlink → real binary)
    let exe_path = std::fs::read_link(format!("{}/exe", proc_path))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    // Read cmdline (null-separated args)
    let cmdline = std::fs::read(format!("{}/cmdline", proc_path))
        .ok()
        .map(|bytes| {
            bytes.iter()
                .map(|&b| if b == 0 { ' ' } else { b as char })
                .collect::<String>()
                .trim()
                .to_string()
        });

    (ppid, exe_path, cmdline)
}

/// Resolve cgroup path to Kubernetes identity
/// k8s cgroup paths look like:
/// /sys/fs/cgroup/kubepods/pod<uid>/<container-id>/...
fn resolve_cgroup(event: &FlowEvent) -> (Option<String>, Option<String>, Option<String>) {
    let cgroup_raw = {
        let end = event.cgroup.iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&event.cgroup[..end]).unwrap_or("").to_string()
    };

    if cgroup_raw.is_empty() {
        // Try reading from /proc
        let proc_cgroup = std::fs::read_to_string(
            format!("/proc/{}/cgroup", event.pid)
        ).unwrap_or_default();

        return parse_k8s_cgroup(&proc_cgroup);
    }

    parse_k8s_cgroup(&cgroup_raw)
}

fn parse_k8s_cgroup(cgroup: &str) -> (Option<String>, Option<String>, Option<String>) {
    // Example: 0::/kubepods/burstable/pod<uid>/<container-hash>
    // or: 12:devices:/kubepods/besteffort/pod<pod-uid>/<container-id>
    for line in cgroup.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 3 { continue; }
        let path = parts[2];

        if path.contains("kubepods") {
            let segments: Vec<&str> = path.split('/').collect();

            let pod = segments.iter()
                .find(|s| s.starts_with("pod"))
                .map(|s| s.trim_start_matches("pod").to_string());

            // Container ID is typically the last non-empty segment
            let container = segments.last()
                .filter(|s| !s.is_empty() && s.len() >= 12)
                .map(|s| s[..12].to_string()); // short container ID

            // Namespace requires reading from k8s API or pod labels file
            // For now, mark as unknown — full impl queries CRI socket
            let namespace = Some("unknown".to_string());

            if pod.is_some() {
                return (pod, namespace, container);
            }
        }
    }
    (None, None, None)
}

/// Check if an IP is a public (non-RFC1918) address
fn is_public_ip(ip: Ipv4Addr) -> bool {
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_documentation()
        && !ip.is_unspecified()
}

/// Guess application protocol from well-known destination ports
fn guess_protocol(dst_port: u16) -> Option<String> {
    match dst_port {
        80   => Some("HTTP".to_string()),
        443  => Some("HTTPS".to_string()),
        8080 => Some("HTTP-alt".to_string()),
        8443 => Some("HTTPS-alt".to_string()),
        22   => Some("SSH".to_string()),
        25 | 587 | 465 => Some("SMTP".to_string()),
        53   => Some("DNS".to_string()),
        5432 => Some("PostgreSQL".to_string()),
        3306 => Some("MySQL".to_string()),
        6379 => Some("Redis".to_string()),
        9200 | 9300 => Some("Elasticsearch".to_string()),
        2055 => Some("NetFlow".to_string()),
        4739 => Some("IPFIX".to_string()),
        6343 => Some("sFlow".to_string()),
        9092 => Some("Kafka".to_string()),
        2181 => Some("ZooKeeper".to_string()),
        50051 => Some("gRPC".to_string()),
        _    => None,
    }
}
