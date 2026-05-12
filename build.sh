#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "${REPO_ROOT}"
BPF_LINKER_PREFIX="${REPO_ROOT}/flow-sensor-ebpf/.bpf-linker"
BPF_LINKER_BIN="${BPF_LINKER_PREFIX}/bin/bpf-linker"

echo "🔨 Building Flow Sensor"
echo ""

# Check dependencies
command -v cargo >/dev/null 2>&1 || { echo "❌ cargo not found. Install Rust: https://rustup.rs"; exit 1; }
command -v clang >/dev/null 2>&1 || { echo "❌ clang not found. Install: apt-get install clang"; exit 1; }

# bpf-linker in PATH is often distro LLVM14; nightly emits LLVM22 bitcode. Install a known-good
# copy under flow-sensor-ebpf/.bpf-linker/ so builds never pick /usr/bin/bpf-linker by mistake.
export PATH="${CARGO_HOME:-${HOME}/.cargo}/bin:${PATH}"

# Ensure nightly is available for BPF target
echo "→ Checking Rust nightly..."
rustup toolchain install nightly --component rust-src 2>/dev/null || true
rustup target add --toolchain nightly bpfel-unknown-none 2>/dev/null || true

# bpf-linker (via aya-rustc-llvm-proxy) dlopens rustc's libLLVM*.so — that .so often
# depends on distro libs (zlib, ncurses, …) that live outside the rustup sysroot.
RUST_SYSROOT="$(rustc +nightly --print sysroot)"
RUST_HOST="$(rustc +nightly -vV | sed -n 's/^host: //p')"
# Sysroot MUST be first: /usr/lib* often ships libLLVM.so (LLVM 14). If that appears
# before rustup's libLLVM (LLVM 22), bpf-linker loads the wrong LLVM and fails with
# "Opaque pointers... Reader: LLVM 14.0.0" while reading rustc's LLVM 22 bitcode.
_base_lp="${RUST_SYSROOT}/lib:${RUST_SYSROOT}/lib/rustlib/${RUST_HOST}/lib:${LD_LIBRARY_PATH:-}"
_GNU_TRIPLE="$(printf '%s\n' "${RUST_HOST}" | sed 's/-unknown-/-/')"
for _bpf_lib in /usr/lib64 /lib64 "/usr/lib/${_GNU_TRIPLE}" "/lib/${_GNU_TRIPLE}"; do
    if [ -d "${_bpf_lib}" ]; then
        _base_lp="${_base_lp}:${_bpf_lib}"
    fi
done
# Only for bpf-linker / eBPF link: do not export globally (would affect stable userspace link).

# bpf-linker must match rustc nightly LLVM (opaque pointers / bitcode). Pin 0.10.x + LLVM22 features.
# Reinstall when nightly's LLVM version changes, or when FLOW_SENSOR_FORCE_BPF_LINKER=1.
RUST_LLVM_VER="$(rustc +nightly -vV | sed -n 's/^LLVM version: //p')"
BPF_LINKER_STAMP="${BPF_LINKER_PREFIX}/.installed-for-rustc-llvm"
_need_bpf_linker=false
if ! [ -x "${BPF_LINKER_BIN}" ]; then
    _need_bpf_linker=true
elif [ ! -f "${BPF_LINKER_STAMP}" ] || ! grep -qxF "${RUST_LLVM_VER}" "${BPF_LINKER_STAMP}" 2>/dev/null; then
    _need_bpf_linker=true
fi
if [ "${FLOW_SENSOR_FORCE_BPF_LINKER:-}" = 1 ]; then
    _need_bpf_linker=true
fi
if [ "${_need_bpf_linker}" = true ]; then
    echo "→ Installing bpf-linker 0.10.3 (LLVM22) for rustc LLVM ${RUST_LLVM_VER} → ${BPF_LINKER_PREFIX}"
    mkdir -p "${BPF_LINKER_PREFIX}"
    env LD_LIBRARY_PATH="${_base_lp}" cargo +nightly install bpf-linker \
        --version 0.10.3 \
        --force \
        --locked \
        --no-default-features \
        --features rust-llvm-22,llvm-22 \
        --root "${BPF_LINKER_PREFIX}"
    printf '%s\n' "${RUST_LLVM_VER}" >"${BPF_LINKER_STAMP}"
fi
if ! [ -x "${BPF_LINKER_BIN}" ]; then
    echo "❌ Expected bpf-linker at ${BPF_LINKER_BIN} but it is missing or not executable." >&2
    exit 1
fi

echo ""
echo "→ Building eBPF programs (kernel space)..."
echo "   (using BPF linker: ${BPF_LINKER_BIN})"
# Cargo env overrides any global config; absolute path avoids PATH (/usr/bin LLVM14).
export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="${BPF_LINKER_BIN}"
export FLOW_SENSOR_BPF_LINKER="${BPF_LINKER_BIN}"
# RUSTFLAGS only for this crate: do not pass BPF llvm-args to the host userspace build below.
env LD_LIBRARY_PATH="${_base_lp}" \
    RUSTFLAGS="${RUSTFLAGS:-} -Cllvm-args=-bpf-stack-size=1048576 -Cllvm-args=--bpf-expand-memcpy-in-order '-Clink-arg=--llvm-args=--bpf-stack-size=1048576 --bpf-expand-memcpy-in-order'" \
    cargo +nightly build \
    --manifest-path flow-sensor-ebpf/Cargo.toml \
    --target bpfel-unknown-none \
    -Z build-std=core \
    -Z build-std-features=panic_immediate_abort \
    --release 2>&1

echo ""
echo "→ Building userspace daemon..."
cargo build \
    --package flow-sensor \
    --release 2>&1

echo ""
echo "✅ Build complete!"
echo ""
echo "Run with:"
echo "  sudo ./target/release/flow-sensor"
echo "  sudo ./target/release/flow-sensor --output json | jq ."
echo "  sudo ./target/release/flow-sensor --help"
