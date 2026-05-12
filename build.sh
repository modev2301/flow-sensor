#!/usr/bin/env bash
set -euo pipefail

echo "🔨 Building Flow Sensor"
echo ""

# Check dependencies
command -v cargo >/dev/null 2>&1 || { echo "❌ cargo not found. Install Rust: https://rustup.rs"; exit 1; }
command -v clang >/dev/null 2>&1 || { echo "❌ clang not found. Install: apt-get install clang"; exit 1; }

# Ensure nightly is available for BPF target
echo "→ Checking Rust nightly..."
rustup toolchain install nightly --component rust-src 2>/dev/null || true
rustup target add --toolchain nightly bpfel-unknown-none 2>/dev/null || true

# bpf-linker loads rustc's libLLVM; some installs need the toolchain lib dir on LD_LIBRARY_PATH.
RUST_SYSROOT="$(rustc +nightly --print sysroot)"
export LD_LIBRARY_PATH="${RUST_SYSROOT}/lib:${LD_LIBRARY_PATH:-}"

# Install bpf-linker if not present
if ! command -v bpf-linker >/dev/null 2>&1; then
    echo "→ Installing bpf-linker..."
    cargo install bpf-linker
fi

echo ""
echo "→ Building eBPF programs (kernel space)..."
# RUSTFLAGS only for this crate: do not pass BPF llvm-args to the host userspace build below.
env RUSTFLAGS="${RUSTFLAGS:-} -Cllvm-args=-bpf-stack-size=524288" \
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
