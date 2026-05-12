#!/usr/bin/env bash
set -euo pipefail

echo "🔨 Building Flow Sensor"
echo ""

# Check dependencies
command -v cargo >/dev/null 2>&1 || { echo "❌ cargo not found. Install Rust: https://rustup.rs"; exit 1; }
command -v clang >/dev/null 2>&1 || { echo "❌ clang not found. Install: apt-get install clang"; exit 1; }

# Prefer cargo-installed bpf-linker over distro packages (e.g. Ubuntu often ships LLVM14;
# nightly rustc emits LLVM22 bitcode → "Opaque pointers... Reader: LLVM 14.0.0").
export PATH="${CARGO_HOME:-${HOME}/.cargo}/bin:${PATH}"

# Ensure nightly is available for BPF target
echo "→ Checking Rust nightly..."
rustup toolchain install nightly --component rust-src 2>/dev/null || true
rustup target add --toolchain nightly bpfel-unknown-none 2>/dev/null || true

# bpf-linker (via aya-rustc-llvm-proxy) dlopens rustc's libLLVM*.so — that .so often
# depends on distro libs (zlib, ncurses, …) that live outside the rustup sysroot.
RUST_SYSROOT="$(rustc +nightly --print sysroot)"
RUST_HOST="$(rustc +nightly -vV | sed -n 's/^host: //p')"
export LD_LIBRARY_PATH="${RUST_SYSROOT}/lib:${RUST_SYSROOT}/lib/rustlib/${RUST_HOST}/lib:${LD_LIBRARY_PATH:-}"
# Typical glibc multiarch paths (Debian/Ubuntu/Fedora-ish); harmless if missing.
_GNU_TRIPLE="$(printf '%s\n' "${RUST_HOST}" | sed 's/-unknown-/-/')"
for _bpf_lib in /usr/lib64 /lib64 "/usr/lib/${_GNU_TRIPLE}" "/lib/${_GNU_TRIPLE}"; do
    if [ -d "${_bpf_lib}" ]; then
        LD_LIBRARY_PATH="${_bpf_lib}:${LD_LIBRARY_PATH}"
    fi
done
export LD_LIBRARY_PATH

# bpf-linker must embed the same LLVM generation as rustc nightly (bitcode compatibility).
# Reinstall when nightly's LLVM version changes, or when FLOW_SENSOR_FORCE_BPF_LINKER=1.
RUST_LLVM_VER="$(rustc +nightly -vV | sed -n 's/^LLVM version: //p')"
BPF_LINKER_STAMP="${CARGO_HOME:-${HOME}/.cargo}/.flow-sensor-bpf-linker-llvm-version"
_need_bpf_linker=false
if ! command -v bpf-linker >/dev/null 2>&1; then
    _need_bpf_linker=true
elif [ ! -f "${BPF_LINKER_STAMP}" ] || ! grep -qxF "${RUST_LLVM_VER}" "${BPF_LINKER_STAMP}" 2>/dev/null; then
    _need_bpf_linker=true
fi
if [ "${FLOW_SENSOR_FORCE_BPF_LINKER:-}" = 1 ]; then
    _need_bpf_linker=true
fi
if [ "${_need_bpf_linker}" = true ]; then
    echo "→ Installing/upgrading bpf-linker for rustc LLVM ${RUST_LLVM_VER}..."
    cargo +nightly install bpf-linker --force --locked
    printf '%s\n' "${RUST_LLVM_VER}" >"${BPF_LINKER_STAMP}"
fi

echo ""
echo "→ Building eBPF programs (kernel space)..."
# Cargo env overrides config; never resolve bare "bpf-linker" from PATH (distro LLVM 14).
export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="${CARGO_HOME:-${HOME}/.cargo}/bin/bpf-linker"
# RUSTFLAGS only for this crate: do not pass BPF llvm-args to the host userspace build below.
env RUSTFLAGS="${RUSTFLAGS:-} -Cllvm-args=-bpf-stack-size=1048576 -Clink-arg=--llvm-args=--bpf-stack-size=1048576" \
    cargo +nightly build \
    --manifest-path flow-sensor-ebpf/Cargo.toml \
    --target bpfel-unknown-none \
    -Z build-std=core \
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
