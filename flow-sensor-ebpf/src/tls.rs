//! TLS uprobes — intercept SSL_write/SSL_read to extract plaintext context.
//! Attached to libssl.so in target processes.
//! Outbound `FlowKey` is taken from `TLS_THREAD_FLOW` (set in `tcp_connect` on the same thread).
//! Parses TLS ClientHello SNI plus minimal HTTP from cleartext application data.
//
// NOTE:
// - DO NOT put `#![no_std]` here. That belongs in crate root (lib.rs / main.rs).
// - Avoid dynamic slicing + copy_from_slice: they can introduce trap paths => __bpf_trap on older kernels.
#[inline(always)]
unsafe fn copy_bytes_bounded(
    out: *mut u8,
    out_len: usize,
    src: *const u8,
    src_len: usize,
    start: usize,
    cnt: usize,
) {
    let mut i = 0usize;
    while i < cnt && i < out_len && start + i < src_len {
        *out.add(i) = *src.add(start + i);
        i += 1;
    }
}


use core::ffi::c_void;
use core::ptr::addr_of_mut;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, gen},
    macros::{map, uprobe},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};

use flow_sensor_common::*;
use crate::maps::{FLOW_TABLE, TLS_THREAD_FLOW, TLS_SCRATCH_LEN, TLS_UPROBE_SCRATCH};

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

#[inline(always)]
unsafe fn read_u8(ptr: *const u8, len: usize, idx: usize) -> Option<u8> {
    if idx < len {
        Some(core::ptr::read_unaligned(ptr.add(idx)))
    } else {
        None
    }
}

/// Parse TLS ClientHello SNI from first `len` bytes. Copy into `sni_out` (HOST_LEN).
/// Returns 1 if found/copied, else 0.
#[inline(always)]
unsafe fn parse_tls_clienthello_sni(ptr: *const u8, len: usize, sni_out: *mut u8) -> u8 {
    if len < 43 {
        return 0;
    }

    // TLS record header
    let b0 = read_u8(ptr, len, 0).unwrap_or(0);
    let b1 = read_u8(ptr, len, 1).unwrap_or(0);
    let b3 = read_u8(ptr, len, 3).unwrap_or(0);
    let b4 = read_u8(ptr, len, 4).unwrap_or(0);

    if b0 != 0x16 || b1 != 0x03 {
        return 0;
    }

    let rec_len = ((b3 as usize) << 8) | (b4 as usize);
    let rec_end = 5usize.saturating_add(rec_len);
    if rec_end > len {
        return 0;
    }

    // handshake type
    let hs = read_u8(ptr, len, 5).unwrap_or(0);
    if hs != 0x01 {
        return 0;
    }

    // Your original logic effectively starts at p=9
    let mut p: usize = 9;

    // skip client version (2)
    if p + 2 > len {
        return 0;
    }
    p += 2;

    // skip random (32)
    if p + 32 > len {
        return 0;
    }
    p += 32;

    // session id
    if p + 1 > len {
        return 0;
    }
    let sess_len = read_u8(ptr, len, p).unwrap_or(0) as usize;
    p += 1;
    if p + sess_len > len {
        return 0;
    }
    p += sess_len;

    // cipher suites
    if p + 2 > len {
        return 0;
    }
    let cs_len = ((read_u8(ptr, len, p).unwrap_or(0) as usize) << 8)
        | (read_u8(ptr, len, p + 1).unwrap_or(0) as usize);
    p += 2;
    if p + cs_len > len {
        return 0;
    }
    p += cs_len;

    // compression methods
    if p + 1 > len {
        return 0;
    }
    let comp_len = read_u8(ptr, len, p).unwrap_or(0) as usize;
    p += 1;
    if p + comp_len > len {
        return 0;
    }
    p += comp_len;

    // extensions total
    if p + 2 > len {
        return 0;
    }
    let ext_total = ((read_u8(ptr, len, p).unwrap_or(0) as usize) << 8)
        | (read_u8(ptr, len, p + 1).unwrap_or(0) as usize);
    p += 2;
    let ext_end = p.saturating_add(ext_total);
    if ext_end > len {
        return 0;
    }

    // scan extensions (bounded loop)
    let mut p2 = p;
    for _ in 0..48usize {
        if p2 + 4 > ext_end {
            break;
        }

        let etype = ((read_u8(ptr, len, p2).unwrap_or(0) as u16) << 8)
            | (read_u8(ptr, len, p2 + 1).unwrap_or(0) as u16);
        let elen = ((read_u8(ptr, len, p2 + 2).unwrap_or(0) as usize) << 8)
            | (read_u8(ptr, len, p2 + 3).unwrap_or(0) as usize);
        p2 += 4;

        if p2 + elen > ext_end {
            return 0;
        }

        // server_name extension
        if etype == 0 && elen >= 5 {
            // list_len (2) at p2, then name_type (1), then name_len (2), then name bytes
            let list_len = ((read_u8(ptr, len, p2).unwrap_or(0) as usize) << 8)
                | (read_u8(ptr, len, p2 + 1).unwrap_or(0) as usize);
            if list_len >= 3 && (2 + list_len) <= elen {
                let mut q = p2 + 2;
                let name_type = read_u8(ptr, len, q).unwrap_or(0);
                if name_type == 0 {
                    q += 1;
                    if q + 2 <= p2 + elen {
                        let name_len = ((read_u8(ptr, len, q).unwrap_or(0) as usize) << 8)
                            | (read_u8(ptr, len, q + 1).unwrap_or(0) as usize);
                        q += 2;

                        if name_len > 0
                            && name_len <= HOST_LEN
                            && (q + name_len) <= (p2 + elen)
                        {
                            copy_bytes_bounded(sni_out, HOST_LEN, ptr, len, q, name_len);
                            return 1;
                        }
                    }
                }
            }
        }

        p2 += elen;
    }

    0
}

/// Parse minimal HTTP request: method, path, host.
/// Writes directly to output buffers with bounded loops; sets `*has_http=1` if looks like HTTP.
#[inline(always)]
unsafe fn parse_http_request(
    ptr: *const u8,
    len: usize,
    host_out: *mut u8,
    method_out: *mut u8, // 8 bytes
    path_out: *mut u8,
    has_http: *mut u8,
) {
    if len < 4 {
        return;
    }

    let b0 = read_u8(ptr, len, 0).unwrap_or(0);
    let b1 = read_u8(ptr, len, 1).unwrap_or(0);
    let b2 = read_u8(ptr, len, 2).unwrap_or(0);

    let is_http = (b0 == b'G' && b1 == b'E' && b2 == b'T')
        || (b0 == b'P' && b1 == b'O' && b2 == b'S')
        || (b0 == b'P' && b1 == b'U' && b2 == b'T')
        || (b0 == b'D' && b1 == b'E' && b2 == b'L')
        || (b0 == b'P' && b1 == b'A' && b2 == b'T')
        || (b0 == b'H' && b1 == b'E' && b2 == b'A')
        || (b0 == b'O' && b1 == b'P' && b2 == b'T');

    if !is_http {
        return;
    }

    core::ptr::write_unaligned(has_http, 1u8);

    // Find first space
    let mut first_space = len;
    for si in 0..TLS_SCRATCH_LEN {
        if si >= len {
            break;
        }
        let c = read_u8(ptr, len, si).unwrap_or(0);
        if c == b' ' {
            first_space = si;
            break;
        }
    }

    // Copy method (<=7 bytes)
    let method_end = if first_space == len { 7usize } else { core::cmp::min(first_space, 7) };
    copy_bytes_bounded(method_out, 8, ptr, len, 0, method_end);

    // Copy path
    if first_space < len {
        let path_start = first_space + 1;
        if path_start < len {
            let mut path_end = core::cmp::min(path_start + PATH_LEN, len);
            for off in 0..PATH_LEN {
                let pj = path_start + off;
                if pj >= len || pj >= path_start + PATH_LEN {
                    break;
                }
                let c = read_u8(ptr, len, pj).unwrap_or(0);
                if c == b' ' {
                    path_end = pj;
                    break;
                }
            }
            let copy_len = path_end.saturating_sub(path_start);
            copy_bytes_bounded(path_out, PATH_LEN, ptr, len, path_start, copy_len);
        }
    }

    // Find Host header: scan first 400 bytes
    for hi in 0..400usize {
        if hi + 6 > len {
            break;
        }
        let h0 = read_u8(ptr, len, hi).unwrap_or(0);
        let h1 = read_u8(ptr, len, hi + 1).unwrap_or(0);
        let h2 = read_u8(ptr, len, hi + 2).unwrap_or(0);
        let h3 = read_u8(ptr, len, hi + 3).unwrap_or(0);
        let h4 = read_u8(ptr, len, hi + 4).unwrap_or(0);
        let h5 = read_u8(ptr, len, hi + 5).unwrap_or(0);

        let is_host_line = (h0 == b'H' || h0 == b'h')
            && (h1 == b'o' || h1 == b'O')
            && (h2 == b's' || h2 == b'S')
            && (h3 == b't' || h3 == b'T')
            && h4 == b':'
            && h5 == b' ';

        if is_host_line {
            let val_start = hi + 6;
            if val_start >= len {
                break;
            }
            let mut val_end = core::cmp::min(val_start + HOST_LEN, len);
            for off in 0..HOST_LEN {
                let vj = val_start + off;
                if vj >= len || vj >= val_start + HOST_LEN {
                    break;
                }
                let c = read_u8(ptr, len, vj).unwrap_or(0);
                if c == b'\r' || c == b'\n' {
                    val_end = vj;
                    break;
                }
            }
            let copy_len = val_end.saturating_sub(val_start);
            copy_bytes_bounded(host_out, HOST_LEN, ptr, len, val_start, copy_len);
            break;
        }
    }
}

/// Parse HTTP status code from response bytes. Returns 0 if not a response/status not found.
#[inline(always)]
unsafe fn parse_http_status(ptr: *const u8, len: usize) -> u16 {
    if len < 12 {
        return 0;
    }
    let h0 = read_u8(ptr, len, 0).unwrap_or(0);
    let h1 = read_u8(ptr, len, 1).unwrap_or(0);
    let h2 = read_u8(ptr, len, 2).unwrap_or(0);
    let h3 = read_u8(ptr, len, 3).unwrap_or(0);
    let h4 = read_u8(ptr, len, 4).unwrap_or(0);
    if !(h0 == b'H' && h1 == b'T' && h2 == b'T' && h3 == b'P' && h4 == b'/') {
        return 0;
    }

    let mut status_start = 0usize;
    for si in 5..TLS_SCRATCH_LEN {
        if si >= len {
            break;
        }
        let c = read_u8(ptr, len, si).unwrap_or(0);
        if c == b' ' {
            status_start = si + 1;
            break;
        }
    }
    if status_start == 0 || status_start + 3 > len {
        return 0;
    }

    let a = read_u8(ptr, len, status_start).unwrap_or(0);
    let b = read_u8(ptr, len, status_start + 1).unwrap_or(0);
    let c = read_u8(ptr, len, status_start + 2).unwrap_or(0);

    if a < b'0' || a > b'9' || b < b'0' || b > b'9' || c < b'0' || c > b'9' {
        return 0;
    }

    ((a - b'0') as u16) * 100 + ((b - b'0') as u16) * 10 + ((c - b'0') as u16)
}

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

/// SSL_write return (TLS + HTTP parsing).
#[no_mangle]
#[link_section = "uretprobe/ssl_write_return"]
pub unsafe extern "C" fn ssl_write_return(ctx: *mut c_void) -> u32 {
    let ctx = RetProbeContext::new(ctx);
    let pid_tgid = bpf_get_current_pid_tgid();

    let ret = match ctx.ret::<i32>() {
        Some(r) => r,
        None => return 0,
    };
    if ret <= 0 {
        let _ = SSL_WRITE_ARGS.remove(&pid_tgid);
        return 0;
    }

    let args = match SSL_WRITE_ARGS.get(&pid_tgid) {
        Some(a) => *a,
        None => return 0,
    };
    let _ = SSL_WRITE_ARGS.remove(&pid_tgid);

    let flow_key = match TLS_THREAD_FLOW.get(&pid_tgid) {
        Some(k) => *k,
        None => return 0,
    };

    let Some(st) = FLOW_TABLE.get_ptr_mut(&flow_key) else {
        return 0;
    };

    let read_len = core::cmp::min(args.len as usize, TLS_SCRATCH_LEN);
    let Some(scratch) = TLS_UPROBE_SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    let dst = addr_of_mut!((*scratch).data) as *mut u8;
    let pr = gen::bpf_probe_read_user(
        dst.cast::<c_void>(),
        read_len as u32,
        (args.buf_ptr as *const u8).cast::<c_void>(),
    );
    if pr != 0 {
        return 0;
    }

    let ptr = dst.cast_const();

    // TLS SNI
    let has_sni = parse_tls_clienthello_sni(ptr, read_len, (*st).tls_sni.as_mut_ptr());

    // HTTP request
    let mut has_http: u8 = 0;
    parse_http_request(
        ptr,
        read_len,
        (*st).http_host.as_mut_ptr(),
        (*st).http_method.as_mut_ptr(),
        (*st).http_path.as_mut_ptr(),
        &mut has_http as *mut u8,
    );

    // TLS detection
    let mut has_tls: u8 = 0;
    if has_sni != 0 {
        has_tls = 1;
    } else if read_len >= 6 {
        let b0 = read_u8(ptr, read_len, 0).unwrap_or(0);
        let b5 = read_u8(ptr, read_len, 5).unwrap_or(0);
        if b0 == 0x16 && b5 == 0x01 {
            has_tls = 1;
        }
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

    0
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
#[link_section = "uretprobe/ssl_read_return"]
pub unsafe extern "C" fn ssl_read_return(ctx: *mut c_void) -> u32 {
    let ctx = RetProbeContext::new(ctx);
    let pid_tgid = bpf_get_current_pid_tgid();

    let ret = match ctx.ret::<i32>() {
        Some(r) => r,
        None => return 0,
    };
    if ret <= 0 {
        let _ = SSL_READ_ARGS.remove(&pid_tgid);
        return 0;
    }

    let args = match SSL_READ_ARGS.get(&pid_tgid) {
        Some(a) => *a,
        None => return 0,
    };
    let _ = SSL_READ_ARGS.remove(&pid_tgid);

    let read_len = core::cmp::min(ret as usize, TLS_SCRATCH_LEN);
    let Some(scratch) = TLS_UPROBE_SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    let dst = addr_of_mut!((*scratch).data) as *mut u8;
    let pr = gen::bpf_probe_read_user(
        dst.cast::<c_void>(),
        read_len as u32,
        (args.buf_ptr as *const u8).cast::<c_void>(),
    );
    if pr != 0 {
        return 0;
    }

    let flow_key = match TLS_THREAD_FLOW.get(&pid_tgid) {
        Some(k) => *k,
        None => return 0,
    };

    let status = parse_http_status(dst.cast_const(), read_len);
    if status == 0 {
        return 0;
    }

    let Some(st) = FLOW_TABLE.get_ptr_mut(&flow_key) else {
        return 0;
    };

    (*st).http_status = status;

    // NOTE: FlowState has no ssl_read_ts_ns — don’t write it.
    // If you want a timestamp, use an existing field or add one to FlowState.

    0
}