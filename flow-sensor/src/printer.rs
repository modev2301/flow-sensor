//! Console output formatters — pretty and JSON.

use flow_sensor_common::{CloseReason, CongestionState, FlowDirection};
use std::net::Ipv4Addr;
use crate::enricher::EnrichedFlow;

pub fn print_header(format: &str) {
    if format != "pretty" { return; }
    println!(
        "{:<6} {:<16} {:<21} {:<21} {:<6} {:<10} {:<10} {:<8} {:<6} {}",
        "PROTO", "PROCESS", "SRC", "DST", "DIR", "BYTES↑", "BYTES↓",
        "RTT(ms)", "REXMT", "APP CONTEXT"
    );
    println!("{}", "─".repeat(130));
}

pub fn print_pretty(flow: &EnrichedFlow) {
    let e = &flow.event;

    let src = format!("{}:{}", Ipv4Addr::from(e.src_ip.to_be()), e.src_port);
    let dst = format!("{}:{}", Ipv4Addr::from(e.dst_ip.to_be()), e.dst_port);

    let direction = match e.direction {
        d if d == FlowDirection::Outbound as u8 => "→out",
        d if d == FlowDirection::Inbound as u8  => "←in ",
        _                                        => "  ? ",
    };

    let proto = match e.protocol { 6 => "TCP", 17 => "UDP", _ => "???" };
    let rtt_ms = e.srtt_us_final as f64 / 1000.0;
    let app_ctx = build_app_context(flow);
    let rexmt = if e.retransmit_count > 0 {
        format!("⚠{}", e.retransmit_count)
    } else {
        "  0".to_string()
    };

    println!(
        "{:<6} {:<16} {:<21} {:<21} {:<6} {:<10} {:<10} {:<8.2} {:<6} {}",
        proto, truncate(e.comm_str(), 16),
        truncate(&src, 21), truncate(&dst, 21),
        direction,
        format_bytes(e.bytes_sent), format_bytes(e.bytes_recv),
        rtt_ms, rexmt, app_ctx,
    );

    if e.retransmit_count > 0 || e.ecn_signals > 0 {
        print_quality_detail(e);
    }
    if e.has_tls == 1 || e.has_http == 1 {
        print_app_detail(flow);
    }
    if e.chain_depth > 0 {
        println!("    ├─ causal: chain={:#x} parent={:#x} depth={}",
            e.chain_id, e.parent_chain_id, e.chain_depth);
    }
    if flow.exe_path.is_some() || flow.cmdline.is_some() {
        print_process_detail(flow);
    }
}

fn print_quality_detail(e: &flow_sensor_common::FlowEvent) {
    print!("    ├─ quality: rtt={:.2}ms-{:.2}ms jitter={:.2}ms",
        e.srtt_us_min as f64 / 1000.0,
        e.srtt_us_max as f64 / 1000.0,
        e.rttvar_us_max as f64 / 1000.0);
    if e.retransmit_count > 0 {
        print!(" | retx={} [rto={} fast={} tlp={}]",
            e.retransmit_count, e.retransmit_rto_count,
            e.retransmit_fast_count, e.retransmit_tlp_count);
    }
    if e.ecn_signals > 0 { print!(" | ecn={}", e.ecn_signals); }
    let cong = match e.congestion_state_final {
        s if s == CongestionState::Loss as u8     => " | ⛔LOSS",
        s if s == CongestionState::Recovery as u8 => " | ⚠RECOVERY",
        s if s == CongestionState::Cwr as u8      => " | ⚠CWR",
        _ => "",
    };
    println!("{}", cong);
}

fn print_app_detail(flow: &EnrichedFlow) {
    let e = &flow.event;
    if e.has_tls == 1 {
        let sni = e.sni_str();
        if !sni.is_empty() {
            print!("    ├─ tls: sni={}", sni);
            if e.tls_handshake_ns > 0 {
                print!(" handshake={:.2}ms", e.tls_handshake_ns as f64 / 1_000_000.0);
            }
            println!();
        }
    }
    if e.has_http == 1 {
        let end = e.http_method.iter().position(|&b| b == 0).unwrap_or(0);
        let method = std::str::from_utf8(&e.http_method[..end]).unwrap_or("");
        print!("    ├─ http: {} {}", method, e.http_path_str());
        let host = e.http_host_str();
        if !host.is_empty() { print!(" host={}", host); }
        if e.http_status > 0 { print!(" status={}", e.http_status); }
        if e.app_response_time_ns > 0 {
            print!(" app_rtt={:.2}ms", e.app_response_time_ns as f64 / 1_000_000.0);
        }
        println!();
    }
}

fn print_process_detail(flow: &EnrichedFlow) {
    if let Some(ref exe) = flow.exe_path {
        println!("    ├─ exe: {}", exe);
    }
    if let Some(ref cmd) = flow.cmdline {
        println!("    ├─ cmd: {}", if cmd.len() > 80 { &cmd[..80] } else { cmd });
    }
    if let Some(ref pod) = flow.k8s_pod {
        println!("    ├─ k8s: pod={} ns={} container={}",
            pod,
            flow.k8s_namespace.as_deref().unwrap_or("?"),
            flow.k8s_container.as_deref().unwrap_or("?"));
    }
    let e = &flow.event;
    println!("    └─ timing: duration={:.2}ms ttfb={:.2}ms close={}",
        e.duration_ns as f64 / 1_000_000.0,
        e.time_to_first_byte_ns as f64 / 1_000_000.0,
        match e.close_reason() {
            CloseReason::Clean      => "clean",
            CloseReason::Reset      => "RST",
            CloseReason::Timeout    => "timeout",
            CloseReason::LocalClose => "local",
            CloseReason::Unknown    => "?",
        });
}

pub fn print_json(flow: &EnrichedFlow) {
    let e = &flow.event;

    // Pre-compute values that can't go inline in json! macro
    let method_end = e.http_method.iter().position(|&b| b == 0).unwrap_or(0);
    let http_method = std::str::from_utf8(&e.http_method[..method_end]).unwrap_or("").to_string();

    let tls_val = if e.has_tls == 1 {
        serde_json::json!({
            "sni": e.sni_str(),
            "handshake_ms": e.tls_handshake_ns as f64 / 1_000_000.0,
        })
    } else {
        serde_json::Value::Null
    };

    let http_val = if e.has_http == 1 {
        serde_json::json!({
            "host": e.http_host_str(),
            "method": http_method,
            "path": e.http_path_str(),
            "status": e.http_status,
            "app_rtt_ms": e.app_response_time_ns as f64 / 1_000_000.0,
        })
    } else {
        serde_json::Value::Null
    };

    let k8s_val = if flow.k8s_pod.is_some() {
        serde_json::json!({
            "pod": flow.k8s_pod,
            "namespace": flow.k8s_namespace,
            "container": flow.k8s_container,
        })
    } else {
        serde_json::Value::Null
    };

    let causal_val = if e.chain_id != 0 {
        serde_json::json!({
            "chain_id": format!("{:#x}", e.chain_id),
            "parent_chain_id": format!("{:#x}", e.parent_chain_id),
            "depth": e.chain_depth,
        })
    } else {
        serde_json::Value::Null
    };

    let obj = serde_json::json!({
        "pid": e.pid, "ppid": flow.ppid, "uid": e.uid,
        "comm": e.comm_str(),
        "exe": flow.exe_path,
        "cmdline": flow.cmdline,
        "src_ip": Ipv4Addr::from(e.src_ip.to_be()).to_string(),
        "dst_ip": Ipv4Addr::from(e.dst_ip.to_be()).to_string(),
        "src_port": e.src_port,
        "dst_port": e.dst_port,
        "protocol": if e.protocol == 6 { "TCP" } else { "UDP" },
        "direction": if e.direction == FlowDirection::Outbound as u8 { "outbound" } else { "inbound" },
        "bytes_sent": e.bytes_sent,
        "bytes_recv": e.bytes_recv,
        "pkts_sent": e.pkts_sent,
        "pkts_recv": e.pkts_recv,
        "rtt_ms": {
            "min": e.srtt_us_min as f64 / 1000.0,
            "max": e.srtt_us_max as f64 / 1000.0,
            "final": e.srtt_us_final as f64 / 1000.0,
            "jitter_max": e.rttvar_us_max as f64 / 1000.0,
        },
        "retransmits": {
            "total": e.retransmit_count,
            "bytes": e.retransmit_bytes,
            "rto": e.retransmit_rto_count,
            "fast": e.retransmit_fast_count,
            "tlp": e.retransmit_tlp_count,
            "sack_blocks": e.sack_blocks_received,
            "rate_pct": e.retransmit_rate_pct(),
        },
        "congestion": {
            "cwnd_min": e.cwnd_min,
            "cwnd_max": e.cwnd_max,
            "ecn_signals": e.ecn_signals,
        },
        "tls": tls_val,
        "http": http_val,
        "timing": {
            "connect_ts_ns": e.connect_ts_ns,
            "duration_ms": e.duration_ns as f64 / 1_000_000.0,
            "ttfb_ms": e.time_to_first_byte_ns as f64 / 1_000_000.0,
        },
        "k8s": k8s_val,
        "causal": causal_val,
        "is_external": flow.is_external,
        "protocol_guess": flow.protocol_guess,
        "close_reason": match e.close_reason() {
            CloseReason::Clean      => "clean",
            CloseReason::Reset      => "reset",
            CloseReason::Timeout    => "timeout",
            CloseReason::LocalClose => "local_close",
            CloseReason::Unknown    => "unknown",
        },
    });

    println!("{}", obj);
}

fn build_app_context(flow: &EnrichedFlow) -> String {
    let e = &flow.event;
    if e.has_tls == 1 {
        let sni = e.sni_str();
        if !sni.is_empty() {
            if e.has_http == 1 {
                let end = e.http_method.iter().position(|&b| b == 0).unwrap_or(0);
                let method = std::str::from_utf8(&e.http_method[..end]).unwrap_or("");
                return format!("TLS/{} {} {}", sni, method, e.http_path_str());
            }
            return format!("TLS/{}", sni);
        }
    }
    if e.has_http == 1 {
        let host = e.http_host_str();
        let end = e.http_method.iter().position(|&b| b == 0).unwrap_or(0);
        let method = std::str::from_utf8(&e.http_method[..end]).unwrap_or("");
        return format!("HTTP {} {} {}", host, method, e.http_path_str());
    }
    if let Some(ref proto) = flow.protocol_guess {
        return proto.clone();
    }
    format!("port/{}", e.dst_port)
}

fn format_bytes(bytes: u64) -> String {
    match bytes {
        b if b < 1_024         => format!("{}B", b),
        b if b < 1_048_576     => format!("{:.1}KB", b as f64 / 1_024.0),
        b if b < 1_073_741_824 => format!("{:.1}MB", b as f64 / 1_048_576.0),
        b                      => format!("{:.1}GB", b as f64 / 1_073_741_824.0),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max.saturating_sub(1)]) }
}
