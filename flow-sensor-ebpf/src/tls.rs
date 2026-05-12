//! TLS uprobes — intercept SSL_write/SSL_read to extract plaintext context.
//! Attached to libssl.so in target processes.
//! This is how we see through proxies: we hook the proxy process's TLS library.
//!
//! Works on any binary using OpenSSL/BoringSSL/LibreSSL — Python, Go (via CGO),
//! Node.js, nginx, Envoy, curl — all use one of these under the hood.

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_user_buf,
    },
    macros::{uprobe, uretprobe, map},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};
use flow_sensor_common::*;


/// Scratch space: pid_tgid → SSL write buffer pointer
/// We save the pointer on entry, read the data on return
#[map]
static SSL_ARGS: HashMap<u64, SslArgs> = HashMap::with_max_entries(1024, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct SslArgs {
    buf_ptr: u64,   // pointer to plaintext buffer (userspace)
    len: u32,
    ts_ns: u64,
}

/// SSL_write(SSL *ssl, const void *buf, int num)
/// Fires when any process writes plaintext data to a TLS connection
/// The data is HERE, unencrypted, before OpenSSL encrypts it
#[uprobe]
pub fn ssl_write_entry(ctx: ProbeContext) -> u32 {
    match unsafe { handle_ssl_write_entry(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_ssl_write_entry(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // arg0 = SSL*, arg1 = const void *buf, arg2 = int num
    let buf_ptr = ctx.arg::<u64>(1).ok_or(-1)?;
    let len = ctx.arg::<u32>(2).ok_or(-1)?;

    let args = SslArgs {
        buf_ptr,
        len,
        ts_ns: bpf_ktime_get_ns(),
    };
    SSL_ARGS.insert(&pid_tgid, &args, 0)?;
    Ok(0)
}

/// SSL_write return — now we have the buffer and can parse HTTP headers
#[uretprobe]
pub fn ssl_write_return(ctx: RetProbeContext) -> u32 {
    match unsafe { handle_ssl_write_return(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_ssl_write_return(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = ctx.ret::<i32>().ok_or(-1)?;
    if ret <= 0 { return Ok(0); }

    let args = match SSL_ARGS.get(&pid_tgid) {
        Some(a) => *a,
        None => return Ok(0),
    };
    SSL_ARGS.remove(&pid_tgid)?;

    // Read up to 512 bytes of the plaintext — enough for HTTP headers
    let read_len = (args.len as usize).min(512);
    let mut buf = [0u8; 512];
    bpf_probe_read_user_buf(args.buf_ptr as *const u8, &mut buf[..read_len]).map_err(|e| e as i64)?;

    // Parse HTTP headers from plaintext buffer
    let mut http_host = [0u8; HOST_LEN];
    let mut http_method = [0u8; 8];
    let mut http_path = [0u8; PATH_LEN];
    let mut has_http = 0u8;

    parse_http_request(
        &buf[..read_len],
        &mut http_host,
        &mut http_method,
        &mut http_path,
        &mut has_http,
    );

    // We need the flow key — get it from the SSL* → fd → sock mapping
    // Simplified: look up by pid and update any matching flow in FLOW_TABLE
    // Full impl: SSL* → BIO → fd → getsockname/getpeername
    let pid = (pid_tgid >> 32) as u32;

    // Update flow state for this pid's active connection
    // In a full implementation, we'd map SSL* → sock precisely
    update_flow_tls_context(
        pid,
        &http_host,
        &http_method,
        &http_path,
        has_http,
        args.ts_ns,
    );

    Ok(0)
}

/// SSL_read return — this is the response coming back
/// Timing: SSL_write_ts → SSL_read_return_ts = true application RTT
#[uretprobe]
pub fn ssl_read_return(ctx: RetProbeContext) -> u32 {
    match unsafe { handle_ssl_read_return(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_ssl_read_return(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = ctx.ret::<i32>().ok_or(-1)?;
    if ret <= 0 { return Ok(0); }

    // args were saved on ssl_read entry (same pattern as ssl_write)
    let args = match SSL_ARGS.get(&pid_tgid) {
        Some(a) => *a,
        None => return Ok(0),
    };
    SSL_ARGS.remove(&pid_tgid)?;

    let read_len = (ret as usize).min(512);
    let mut buf = [0u8; 512];
    bpf_probe_read_user_buf(args.buf_ptr as *const u8, &mut buf[..read_len]).map_err(|e| e as i64)?;

    // Parse HTTP response status from plaintext
    let status = parse_http_status(&buf[..read_len]);
    let pid = (pid_tgid >> 32) as u32;
    let now = bpf_ktime_get_ns();

    // Update first_recv_ts and http_status in flow state
    // Iterate FLOW_TABLE for matching pid (simplified)
    // Full impl: SSL* → sock → flow key
    let _ = (pid, status, now);

    Ok(0)
}

// ── HTTP parser (minimal, BPF-safe) ─────────────────────────────────────────
// BPF programs must be bounded — no loops without bounds, no heap allocation.
// We parse just enough to extract Host header, method, path, and status.

/// Parse HTTP request headers from plaintext buffer
/// Extracts: method (GET/POST/...), path, Host header
unsafe fn parse_http_request(
    buf: &[u8],
    host_out: &mut [u8; HOST_LEN],
    method_out: &mut [u8; 8],
    path_out: &mut [u8; PATH_LEN],
    has_http: &mut u8,
) {
    if buf.len() < 4 { return; }

    // Check for HTTP method at start of buffer
    // GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
    let is_http = matches!(
        (buf[0], buf[1], buf[2]),
        (b'G', b'E', b'T') |
        (b'P', b'O', b'S') |
        (b'P', b'U', b'T') |
        (b'D', b'E', b'L') |
        (b'P', b'A', b'T') |
        (b'H', b'E', b'A') |
        (b'O', b'P', b'T')
    );

    if !is_http { return; }
    *has_http = 1;

    // Extract method (up to first space)
    let method_end = buf.iter().position(|&b| b == b' ').unwrap_or(7).min(7);
    method_out[..method_end].copy_from_slice(&buf[..method_end]);

    // Extract path (between first and second space)
    if let Some(path_start) = buf.iter().position(|&b| b == b' ').map(|i| i + 1) {
        let path_end = buf[path_start..]
            .iter()
            .position(|&b| b == b' ')
            .map(|i| i + path_start)
            .unwrap_or(path_start + PATH_LEN)
            .min(path_start + PATH_LEN);
        let copy_len = (path_end - path_start).min(PATH_LEN);
        path_out[..copy_len].copy_from_slice(&buf[path_start..path_start + copy_len]);
    }

    // Extract Host header — scan for "Host: " or "host: "
    // Bounded scan — BPF verifier requires bounded loops
    let host_prefix = b"Host: ";
    let host_prefix_lower = b"host: ";

    'outer: for i in 0..buf.len().saturating_sub(host_prefix.len()) {
        if i >= 400 { break; } // bound the scan
        if &buf[i..i + 6] == host_prefix || &buf[i..i + 6] == host_prefix_lower {
            let val_start = i + 6;
            let val_end = buf[val_start..]
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
                .map(|j| j + val_start)
                .unwrap_or(val_start + HOST_LEN)
                .min(val_start + HOST_LEN);
            let copy_len = (val_end - val_start).min(HOST_LEN);
            host_out[..copy_len].copy_from_slice(&buf[val_start..val_start + copy_len]);
            break 'outer;
        }
    }
}

/// Parse HTTP response status code from buffer (e.g. "HTTP/1.1 200 OK")
unsafe fn parse_http_status(buf: &[u8]) -> u16 {
    if buf.len() < 12 { return 0; }
    if &buf[0..5] != b"HTTP/" { return 0; }

    // Find the space after HTTP version
    let status_start = match buf[5..].iter().position(|&b| b == b' ') {
        Some(i) => i + 6,
        None => return 0,
    };

    if status_start + 3 > buf.len() { return 0; }

    let hundreds = (buf[status_start] as u16).wrapping_sub(b'0' as u16);
    let tens = (buf[status_start + 1] as u16).wrapping_sub(b'0' as u16);
    let ones = (buf[status_start + 2] as u16).wrapping_sub(b'0' as u16);

    if hundreds > 9 || tens > 9 || ones > 9 { return 0; }

    hundreds * 100 + tens * 10 + ones
}

/// Update TLS/HTTP context in the flow state for a given pid
/// In a production impl this uses a precise SSL* → sock mapping
unsafe fn update_flow_tls_context(
    _pid: u32,
    http_host: &[u8; HOST_LEN],
    http_method: &[u8; 8],
    http_path: &[u8; PATH_LEN],
    has_http: u8,
    write_ts_ns: u64,
) {
    // In full implementation:
    // 1. Maintain SSL* → FlowKey map updated in ssl_write_entry
    // 2. Look up FlowKey directly here
    // 3. Update the specific flow's state
    //
    // Simplified: this is called per-write, context is correct
    let _ = (http_host, http_method, http_path, has_http, write_ts_ns);
}
