//! TLS uprobe attachment — finds libssl in running processes and attaches
//! SSL_write/SSL_read uprobes to capture plaintext context before encryption.
//!
//! This is how we see through proxies: hook the proxy process's TLS library.
//! Requires processes linked against OpenSSL/LibreSSL (`libssl.so`); static BoringSSL builds are not covered.

use crate::loader::BpfHandle;
use tracing::{debug, info, warn};

/// TLS uprobes we attach to libssl — must match ELF program names.
#[cfg(target_os = "linux")]
const TLS_EBPF_PROGRAMS: &[&str] = &[
    "ssl_write_entry",
    "ssl_write_return",
    "ssl_read_entry",
    "ssl_read_return",
];

/// Parse the on-disk BPF `.so` with `aya-obj` and log each TLS program's instruction count.
///
/// **Fact:** the kernel verifier line `processed 0 insns` is printed from `print_verification_stats()`
/// after an *early* failure (often `check_subprogs()` in Linux `kernel/bpf/verifier.c`), before the
/// main instruction walk — it does **not** mean the ELF had zero instructions.
///
/// If `aya_obj` reports `insn_count > 0` but load still fails with `last insn is not an exit or jmp`,
/// the usual cause is **invalid BPF subprogram boundaries** (LLVM emitted BPF-to-BPF calls).
#[cfg(target_os = "linux")]
fn assert_tls_programs_non_empty_elf(so_path: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::fs;
    use aya_obj::Object;

    let data = fs::read(so_path).with_context(|| format!("read BPF object {}", so_path.display()))?;
    let obj = Object::parse(&data).with_context(|| format!("aya_obj::Object::parse {}", so_path.display()))?;

    for &name in TLS_EBPF_PROGRAMS {
        let prog = obj
            .programs
            .get(name)
            .with_context(|| format!("ELF missing BPF program `{name}` (wrong object path or stale build?)"))?;
        let key = prog.function_key();
        let func = obj.functions.get(&key).with_context(|| format!(
            "ELF program `{name}` has no linked Function at (section_index={}, address={:#x})",
            key.0, key.1
        ))?;
        let n = func.instructions.len();
        info!(
            program = %name,
            insn_count = n,
            path = %so_path.display(),
            "TLS program instruction count from ELF (pre-BPF_PROG_LOAD)"
        );
        if n == 0 {
            anyhow::bail!(
                "BPF object `{}`: program `{}` has **0 instructions** in the ELF that aya_obj parsed. \
That would produce an empty `BPF_PROG_LOAD` payload. \
Rebuild `flow-sensor-ebpf` (release, target `bpfel-unknown-none`).",
                so_path.display(),
                name,
            );
        }
    }
    Ok(())
}

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
    "envoy", "nginx", "squid", "haproxy", "python3", "python", "node", "java", "curl", "wget",
];

#[cfg(target_os = "linux")]
fn attach_ssl_symbol(
    bpf: &mut aya::Ebpf,
    prog_name: &'static str,
    sym: &'static str,
    path: &str,
    pid: Option<u32>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use aya::programs::UProbe;

    let program = bpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow::anyhow!("BPF program `{prog_name}` not found in object"))?;
    let p: &mut UProbe = program
        .try_into()
        .with_context(|| format!("`{prog_name}` is not a uprobe/uretprobe program"))?;
    p.load()
        .with_context(|| format!("failed to load BPF program `{prog_name}`"))?;
    let pid_i32 = pid.map(|p| p as i32);
    p.attach(Some(sym), 0, path, pid_i32)
        .with_context(|| format!("failed to attach `{prog_name}` to `{sym}` in {path}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn load_tls_programs(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    use anyhow::Context;
    use aya::programs::UProbe;

    for prog_name in TLS_EBPF_PROGRAMS {
        let program = bpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("BPF program `{prog_name}` not found"))?;
        let p: &mut UProbe = program
            .try_into()
            .with_context(|| format!("`{prog_name}` is not a uprobe/uretprobe"))?;
        p.load()
            .with_context(|| format!("failed to load `{prog_name}`"))?;
    }
    Ok(())
}

/// Attach SSL_write and SSL_read uprobes to libssl in target processes.
///
/// If `pids` is empty → system-wide attachment (all processes using that `libssl` path).
/// If `pids` is specified → only those processes (per-PID `libssl` from `/proc/pid/maps`).
#[cfg(target_os = "linux")]
pub async fn attach_tls_probes(handle: &mut BpfHandle, pids: &[u32]) -> anyhow::Result<()> {
    use anyhow::Context;

    const PAIRS: &[(&str, &str)] = &[
        ("ssl_write_entry", "SSL_write"),
        ("ssl_write_return", "SSL_write"),
        ("ssl_read_entry", "SSL_read"),
        ("ssl_read_return", "SSL_read"),
    ];

    let so_path = crate::loader::ebpf_object_path();
    assert_tls_programs_non_empty_elf(&so_path).context("TLS BPF ELF inspection failed")?;

    load_tls_programs(&mut handle.bpf).context("load TLS BPF programs")?;

    if !pids.is_empty() {
        for &pid in pids {
            let Some(path) = find_libssl_for_pid(pid) else {
                warn!(
                    "no libssl in /proc/{}/maps — skip TLS uprobes (static TLS or non-OpenSSL)",
                    pid
                );
                continue;
            };
            for &(prog, sym) in PAIRS {
                attach_ssl_symbol(&mut handle.bpf, prog, sym, &path, Some(pid))
                    .with_context(|| format!("attach {prog} for pid {pid}"))?;
            }
            info!(pid = pid, path = %path, "TLS uprobes attached");
        }
        return Ok(());
    }

    let libssl = find_libssl()?;
    for &(prog, sym) in PAIRS {
        attach_ssl_symbol(&mut handle.bpf, prog, sym, &libssl, None)
            .with_context(|| format!("system-wide attach {prog}"))?;
    }
    info!(path = %libssl, "TLS uprobes attached system-wide");

    let interesting = find_interesting_processes();
    if !interesting.is_empty() {
        debug!("Processes with libssl (for troubleshooting):");
        for (pid, name, path) in &interesting {
            debug!(pid = pid, comm = %name, path = %path, "libssl user");
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn attach_tls_probes(_handle: &mut BpfHandle, _pids: &[u32]) -> anyhow::Result<()> {
    Ok(())
}

/// Find libssl on this system via ldconfig, then known paths
pub fn find_libssl() -> anyhow::Result<String> {
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

    for &path in LIBSSL_PATHS {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    anyhow::bail!("libssl not found — install openssl or attach with explicit PIDs after installing libssl")
}

/// Find which libssl a specific PID is using via /proc/pid/maps
pub fn find_libssl_for_pid(pid: u32) -> Option<String> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in maps.lines() {
        if line.contains("libssl") {
            if let Some(path) = line.split_whitespace().last() {
                if path.starts_with('[') {
                    continue;
                }
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

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return results;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else {
            continue;
        };
        let comm = comm.trim().to_string();

        if INTERESTING_PROCS.iter().any(|&n| comm.contains(n)) {
            if let Some(ssl_path) = find_libssl_for_pid(pid) {
                debug!(pid = pid, comm = %comm, path = %ssl_path, "interesting + libssl");
                results.push((pid, comm, ssl_path));
            }
        }
    }

    results
}
