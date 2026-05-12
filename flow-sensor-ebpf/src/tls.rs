//! TLS uprobes — intercept SSL_write/SSL_read to extract plaintext context.
//! Attached to libssl.so in target processes.
//! This is how we see through proxies: we hook the proxy process's TLS library.
//!
//! Outbound `FlowKey` is taken from `TLS_THREAD_FLOW` (set in `tcp_connect` on the same thread).
//! Parses TLS ClientHello SNI plus minimal HTTP from cleartext application data.

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_user_buf,
    },
    macros::{map, uprobe},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};
use flow_sensor_common::*;

use crate::maps::{FLOW_TABLE, TLS_THREAD_FLOW};

/// Max bytes copied from userspace per SSL hook.
/// Keep small: the BPF stack is 512B by default; `ssl_write_return` must not hold scratch + full
/// `HOST_LEN`/`PATH_LEN` copies at once (that produced invalid BPF / verifier "0 insns").
const TLS_SCRATCH_LEN: usize = 256;

/// `#[repr(C)]` with explicit padding so every byte is initialized on the stack.
/// Implicit padding after `len` would leave holes and make `bpf_map_update_elem` fail verification.
#[repr(C)]
#[derive(Clone, Copy)]
struct SslArgs {
    buf_ptr: u64,
    len: u32,
    _pad: u32,
    ts_ns: u64,
}

/// `pid_tgid` → saved `SSL_write` buffer pointer (entry → return).
#[map]
static SSL_WRITE_ARGS: HashMap<u64, SslArgs> = HashMap::with_max_entries(4096, 0);

/// `pid_tgid` → saved `SSL_read` buffer pointer (entry → return).
#[map]
static SSL_READ_ARGS: HashMap<u64, SslArgs> = HashMap::with_max_entries(4096, 0);

/// SSL_write(SSL *ssl, const void *buf, int num)
#[uprobe]
pub fn ssl_write_entry(ctx: ProbeContext) -> u32 {
    match unsafe { handle_ssl_write_entry(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_ssl_write_entry(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let buf_ptr = ctx.arg::<u64>(1).ok_or(-1)?;
    let len = ctx.arg::<u32>(2).ok_or(-1)?;
    let args = SslArgs {
        buf_ptr,
        len,
        _pad: 0,
        ts_ns: bpf_ktime_get_ns(),
    };
    SSL_WRITE_ARGS.insert(&pid_tgid, &args, 0)?;
    Ok(0)
}

/// `SSL_write` return — manual section (avoid `#[uretprobe]` macro: nested same-name `fn` + trailing
/// `return 0` has produced invalid BPF / verifier "last insn is not an exit", 0 insns).
#[no_mangle]
#[link_section = "uretprobe"]
pub unsafe fn ssl_write_return(ctx: *mut c_void) -> u32 {
    let ctx = RetProbeContext::new(ctx);
    match handle_ssl_write_return(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_ssl_write_return(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = ctx.ret::<i32>().ok_or(-1)?;
    if ret <= 0 {
        let _ = SSL_WRITE_ARGS.remove(&pid_tgid);
        return Ok(0);
    }

    let args = match SSL_WRITE_ARGS.get(&pid_tgid) {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = SSL_WRITE_ARGS.remove(&pid_tgid);

    let flow_key = match TLS_THREAD_FLOW.get(&pid_tgid) {
        Some(k) => *k,
        None => return Ok(0),
    };

    let Some(st) = FLOW_TABLE.get_ptr_mut(&flow_key) else {
        return Ok(0);
    };

    let read_len = (args.len as usize).min(TLS_SCRATCH_LEN);
    let mut buf = [0u8; TLS_SCRATCH_LEN];
    bpf_probe_read_user_buf(args.buf_ptr as *const u8, &mut buf[..read_len]).map_err(|e| e as i64)?;

    let has_sni = parse_tls_clienthello_sni(&buf[..read_len], &mut (*st).tls_sni);

    let mut has_http = 0u8;
    parse_http_request(
        &buf[..read_len],
        &mut (*st).http_host,
        &mut (*st).http_method,
        &mut (*st).http_path,
        &mut has_http,
    );

    let mut has_tls = 0u8;
    if has_sni != 0 {
        has_tls = 1;
    } else if read_len >= 6 && buf[0] == 0x16 && buf[5] == 0x01 {
        has_tls = 1;
    }

    if has_tls != 0 {
        (*st).has_tls = 1;
        if (*st).tls_ready_ts_ns == 0 {
            (*st).tls_ready_ts_ns = bpf_ktime_get_ns();
        }
    }

    if has_http != 0 {
        (*st).has_http = 1;
    }

    if has_http != 0 || has_tls != 0 {
        (*st).ssl_write_ts_ns = args.ts_ns;
    }

    Ok(0)
}

/// SSL_read(SSL *ssl, void *buf, int num)
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) -> u32 {
    match unsafe { handle_ssl_read_entry(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_ssl_read_entry(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let buf_ptr = ctx.arg::<u64>(1).ok_or(-1)?;
    let len = ctx.arg::<u32>(2).ok_or(-1)?;
    let args = SslArgs {
        buf_ptr,
        len,
        _pad: 0,
        ts_ns: bpf_ktime_get_ns(),
    };
    SSL_READ_ARGS.insert(&pid_tgid, &args, 0)?;
    Ok(0)
}

#[no_mangle]
#[link_section = "uretprobe"]
pub unsafe fn ssl_read_return(ctx: *mut c_void) -> u32 {
    let ctx = RetProbeContext::new(ctx);
    match handle_ssl_read_return(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn handle_ssl_read_return(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret = ctx.ret::<i32>().ok_or(-1)?;
    if ret <= 0 {
        let _ = SSL_READ_ARGS.remove(&pid_tgid);
        return Ok(0);
    }

    let args = match SSL_READ_ARGS.get(&pid_tgid) {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = SSL_READ_ARGS.remove(&pid_tgid);

    let read_len = (ret as usize).min(TLS_SCRATCH_LEN);
    let mut buf = [0u8; TLS_SCRATCH_LEN];
    bpf_probe_read_user_buf(args.buf_ptr as *const u8, &mut buf[..read_len]).map_err(|e| e as i64)?;

    let flow_key = match TLS_THREAD_FLOW.get(&pid_tgid) {
        Some(k) => *k,
        None => return Ok(0),
    };

    let status = parse_http_status(&buf[..read_len]);
    if status == 0 {
        return Ok(0);
    }

    let Some(st) = FLOW_TABLE.get_ptr_mut(&flow_key) else {
        return Ok(0);
    };
    (*st).http_status = status;
    Ok(0)
}

// ── TLS ClientHello SNI (bounded) ───────────────────────────────────────────

/// Returns `1` if a hostname was copied into `sni_out`.
unsafe fn parse_tls_clienthello_sni(buf: &[u8], sni_out: &mut [u8; HOST_LEN]) -> u8 {
    let max = buf.len().min(TLS_SCRATCH_LEN);
    if max < 43 {
        return 0;
    }
    let buf = &buf[..max];

    if buf[0] != 0x16 || buf[1] != 0x03 {
        return 0;
    }

    let rec_len = ((buf[3] as usize) << 8) | (buf[4] as usize);
    let _rec_end = 5usize.saturating_add(rec_len);
    if _rec_end > buf.len() {
        return 0;
    }

    if buf[5] != 0x01 {
        return 0;
    }

    let mut p: usize = 9;
    if p + 2 > buf.len() {
        return 0;
    }
    p += 2; // legacy_client_version
    if p + 32 > buf.len() {
        return 0;
    }
    p += 32; // random
    if p + 1 > buf.len() {
        return 0;
    }
    let sess_len = buf[p] as usize;
    p += 1;
    if p + sess_len > buf.len() {
        return 0;
    }
    p += sess_len;

    if p + 2 > buf.len() {
        return 0;
    }
    let cs_len = ((buf[p] as usize) << 8) | (buf[p + 1] as usize);
    p += 2;
    if p + cs_len > buf.len() {
        return 0;
    }
    p += cs_len;

    if p + 1 > buf.len() {
        return 0;
    }
    let comp_len = buf[p] as usize;
    p += 1;
    if p + comp_len > buf.len() {
        return 0;
    }
    p += comp_len;

    if p + 2 > buf.len() {
        return 0;
    }
    let ext_total = ((buf[p] as usize) << 8) | (buf[p + 1] as usize);
    p += 2;
    let ext_end = p.saturating_add(ext_total);
    if ext_end > buf.len() {
        return 0;
    }

    let mut n = 0u32;
    while p + 4 <= ext_end && p + 4 <= buf.len() && n < 48 {
        n += 1;
        let etype = ((buf[p] as u16) << 8) | (buf[p + 1] as u16);
        let elen = ((buf[p + 2] as usize) << 8) | (buf[p + 3] as usize);
        p += 4;
        if p + elen > buf.len() || p + elen > ext_end {
            return 0;
        }
        if etype == 0 {
            if parse_sni_extension(&buf[p..p + elen], sni_out) != 0 {
                return 1;
            }
        }
        p += elen;
    }
    0
}

unsafe fn parse_sni_extension(ep: &[u8], sni_out: &mut [u8; HOST_LEN]) -> u8 {
    if ep.len() < 5 {
        return 0;
    }
    let list_len = ((ep[0] as usize) << 8) | (ep[1] as usize);
    if list_len < 3 || 2 + list_len > ep.len() {
        return 0;
    }
    let mut q: usize = 2;
    if ep[q] != 0 {
        return 0;
    } // host_name
    q += 1;
    if q + 2 > ep.len() {
        return 0;
    }
    let name_len = ((ep[q] as usize) << 8) | (ep[q + 1] as usize);
    q += 2;
    if name_len == 0 || name_len > HOST_LEN || q + name_len > ep.len() {
        return 0;
    }
    sni_out[..name_len].copy_from_slice(&ep[q..q + name_len]);
    1
}

// ── HTTP parser (minimal, BPF-safe) ─────────────────────────────────────────

unsafe fn parse_http_request(
    buf: &[u8],
    host_out: &mut [u8; HOST_LEN],
    method_out: &mut [u8; 8],
    path_out: &mut [u8; PATH_LEN],
    has_http: &mut u8,
) {
    if buf.len() < 4 {
        return;
    }

    let is_http = matches!(
        (buf[0], buf[1], buf[2]),
        (b'G', b'E', b'T')
            | (b'P', b'O', b'S')
            | (b'P', b'U', b'T')
            | (b'D', b'E', b'L')
            | (b'P', b'A', b'T')
            | (b'H', b'E', b'A')
            | (b'O', b'P', b'T')
    );

    if !is_http {
        return;
    }
    *has_http = 1;

    let method_end = buf
        .iter()
        .position(|&b| b == b' ')
        .unwrap_or(7)
        .min(7);
    method_out[..method_end].copy_from_slice(&buf[..method_end]);

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

    let host_prefix = b"Host: ";
    let host_prefix_lower = b"host: ";

    'outer: for i in 0..buf.len().saturating_sub(6) {
        if i >= 400 {
            break;
        }
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

unsafe fn parse_http_status(buf: &[u8]) -> u16 {
    if buf.len() < 12 {
        return 0;
    }
    if &buf[0..5] != b"HTTP/" {
        return 0;
    }

    let status_start = match buf[5..].iter().position(|&b| b == b' ') {
        Some(i) => i + 6,
        None => return 0,
    };

    if status_start + 3 > buf.len() {
        return 0;
    }

    let hundreds = (buf[status_start] as u16).wrapping_sub(b'0' as u16);
    let tens = (buf[status_start + 1] as u16).wrapping_sub(b'0' as u16);
    let ones = (buf[status_start + 2] as u16).wrapping_sub(b'0' as u16);

    if hundreds > 9 || tens > 9 || ones > 9 {
        return 0;
    }

    hundreds * 100 + tens * 10 + ones
}
