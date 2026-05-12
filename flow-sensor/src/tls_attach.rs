//! TLS uprobe attachment — finds libssl in running processes and attaches
//! SSL_write/SSL_read uprobes to capture plaintext context before encryption.
//!
//! This is how we see through proxies: hook the proxy process's TLS library.
//! Works on nginx, envoy, python3, curl, node — anything using libssl/BoringSSL.
//!
//! Requires aya in Cargo.toml to activate. Currently stubbed.

use crate::loader::BpfHandle;
use tracing::{info, debug};

/// Common libssl paths across Linux distros
const LIBSSL_PATHS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    "/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib64/libssl.so.3",
    "/usr/lib/libssl.so.3",
];

/// Process names we auto-attach TLS probes to (proxies and common API clients)
const INTERESTING_PROCS: &[&str] = &[
    "envoy", "nginx", "squid", "haproxy",
    "python3", "python", "node", "java",
    "curl", "wget",
];

/// Attach SSL_write and SSL_read uprobes to libssl in target processes.
///
/// If `pids` is empty → system-wide attachment (all processes using libssl).
/// If `pids` is specified → only those processes.
pub async fn attach_tls_probes(
    _handle: &mut BpfHandle,
    pids: &[u32],
) -> anyhow::Result<()> {

    // ── Real aya implementation (uncomment when aya is in Cargo.toml) ────────
    //
    // let libssl = find_libssl()?;
    // info!("libssl found at: {}", libssl);
    //
    // if pids.is_empty() {
    //     attach_ssl_to_path(_handle, &libssl, None)?;
    //     info!("TLS probes attached system-wide");
    // } else {
    //     for &pid in pids {
    //         match find_libssl_for_pid(pid) {
    //             Some(path) => {
    //                 attach_ssl_to_path(_handle, &path, Some(pid))?;
    //                 info!("TLS probes attached to pid {}", pid);
    //             }
    //             None => warn!("No libssl found for pid {} — may not use TLS", pid),
    //         }
    //     }
    // }
    //
    // // Auto-attach to interesting processes (proxies etc.)
    // if pids.is_empty() {
    //     for (pid, name, path) in find_interesting_processes() {
    //         debug!("Auto-attaching TLS to {} (pid {})", name, pid);
    //         let _ = attach_ssl_to_path(_handle, &path, Some(pid));
    //     }
    // }
    // ─────────────────────────────────────────────────────────────────────────

    let libssl = find_libssl().unwrap_or_else(|_| "not found".to_string());
    info!("TLS probes: stub mode (libssl on this system: {})", libssl);

    if !pids.is_empty() {
        info!("Would attach to pids: {:?}", pids);
    }

    let interesting = find_interesting_processes();
    if !interesting.is_empty() {
        info!("Interesting processes found (would attach TLS probes):");
        for (pid, name, path) in &interesting {
            info!("  pid={} comm={} ssl={}", pid, name, path);
        }
    }

    Ok(())
}

// fn attach_ssl_to_path(
//     handle: &mut BpfHandle,
//     path: &str,
//     pid: Option<u32>,
// ) -> anyhow::Result<()> {
//     use aya::programs::UProbe;
//
//     for (prog_name, sym_name) in &[
//         ("ssl_write_entry",  "SSL_write"),
//         ("ssl_write_return", "SSL_write"),
//         ("ssl_read_return",  "SSL_read"),
//     ] {
//         let prog: &mut UProbe = handle.bpf
//             .program_mut(prog_name)
//             .ok_or_else(|| anyhow::anyhow!("{} not found", prog_name))?
//             .try_into()?;
//         prog.load()?;
//         prog.attach(Some(sym_name), 0, path, pid)?;
//     }
//     Ok(())
// }

/// Find libssl on this system via ldconfig, then known paths
pub fn find_libssl() -> anyhow::Result<String> {
    // Try ldconfig cache first
    if let Ok(out) = std::process::Command::new("ldconfig").arg("-p").output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains("libssl.so") {
                if let Some(path) = line.split("=>").nth(1) {
                    let path = path.trim().to_string();
                    if std::path::Path::new(&path).exists() {
                        return Ok(path);
                    }
                }
            }
        }
    }

    // Fall back to known paths
    for &path in LIBSSL_PATHS {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    anyhow::bail!("libssl not found — install openssl or specify path manually")
}

/// Find which libssl a specific PID is using via /proc/pid/maps
pub fn find_libssl_for_pid(pid: u32) -> Option<String> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;
    for line in maps.lines() {
        if line.contains("libssl") {
            if let Some(path) = line.split_whitespace().last() {
                if std::path::Path::new(path).exists() {
                    return Some(path.to_string());
                }
            }
        }
    }
    None
}

/// Scan /proc for interesting processes (proxies, API clients) that use libssl
pub fn find_interesting_processes() -> Vec<(u32, String, String)> {
    let mut results = Vec::new();

    let Ok(entries) = std::fs::read_dir("/proc") else { return results };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else { continue };

        let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) else { continue };
        let comm = comm.trim().to_string();

        if INTERESTING_PROCS.iter().any(|&n| comm.contains(n)) {
            if let Some(ssl_path) = find_libssl_for_pid(pid) {
                debug!("Found: {} (pid {}) using {}", comm, pid, ssl_path);
                results.push((pid, comm, ssl_path));
            }
        }
    }

    results
}
