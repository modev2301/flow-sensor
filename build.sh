#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE-$0}")" && pwd)"
cd "${REPO_ROOT}"

BPF_LINKER_PREFIX="${REPO_ROOT}/flow-sensor-ebpf/.bpf-linker"
BPF_LINKER_BIN="${BPF_LINKER_PREFIX}/bin/bpf-linker"

echo "🔨 Building Flow Sensor"
echo ""

# -------------------------------------------------------------------
# Dependencies
# -------------------------------------------------------------------
command -v cargo >/dev/null 2>&1 || {
    echo "❌ cargo not found. Install Rust: https://rustup.rs"
    exit 1
}
command -v clang >/dev/null 2>&1 || {
    echo "❌ clang not found. Install: apt-get install clang"
    exit 1
}

export PATH="${CARGO_HOME:-${HOME}/.cargo}/bin:${PATH}"

# -------------------------------------------------------------------
# Rust nightly + BPF target
# -------------------------------------------------------------------
echo "→ Checking Rust nightly..."
rustup toolchain install nightly --component rust-src 2>/dev/null || true
rustup target add --toolchain nightly bpfel-unknown-none 2>/dev/null || true

# -------------------------------------------------------------------
# LLVM runtime environment (critical for bpf-linker)
# -------------------------------------------------------------------
RUST_SYSROOT="$(rustc +nightly --print sysroot)"
RUST_HOST="$(rustc +nightly -vV | sed -n 's/^host: //p')"

_base_lp="${RUST_SYSROOT}/lib:${RUST_SYSROOT}/lib/rustlib/${RUST_HOST}/lib:${LD_LIBRARY_PATH:-}"

_GNU_TRIPLE="$(printf '%s\n' "${RUST_HOST}" | sed 's/-unknown-/-/')"
for _bpf_lib in /usr/lib64 /lib64 "/usr/lib/${_GNU_TRIPLE}" "/lib/${_GNU_TRIPLE}"; do
    if [ -d "${_bpf_lib}" ]; then
        _base_lp="${_base_lp}:${_bpf_lib}"
    fi
done

# -------------------------------------------------------------------
# bpf-linker pinning (must match rustc LLVM = 22)
# -------------------------------------------------------------------
RUST_LLVM_VER="$(rustc +nightly -vV | sed -n 's/^LLVM version: //p')"
BPF_LINKER_STAMP="${BPF_LINKER_PREFIX}/.installed-for-rustc-llvm"

_need_bpf_linker=false
if ! [ -x "${BPF_LINKER_BIN}" ]; then
    _need_bpf_linker=true
elif [ ! -f "${BPF_LINKER_STAMP}" ] || \
     ! grep -qxF "${RUST_LLVM_VER}" "${BPF_LINKER_STAMP}" 2>/dev/null; then
    _need_bpf_linker=true
fi

if [ "${FLOW_SENSOR_FORCE_BPF_LINKER:-}" = 1 ]; then
    _need_bpf_linker=true
fi

if [ "${_need_bpf_linker}" = true ]; then
    echo "→ Installing bpf-linker 0.10.3 (LLVM22) for rustc LLVM ${RUST_LLVM_VER}"
    mkdir -p "${BPF_LINKER_PREFIX}"

    env LD_LIBRARY_PATH="${_base_lp}" \
        cargo +nightly install bpf-linker \
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

# -------------------------------------------------------------------
# Build eBPF programs (kernel space)
# -------------------------------------------------------------------
echo ""
echo "→ Building eBPF programs (kernel space)..."
echo "   (using BPF linker: ${BPF_LINKER_BIN})"

export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="${BPF_LINKER_BIN}"
export FLOW_SENSOR_BPF_LINKER="${BPF_LINKER_BIN}"

# Do **not** pass bpf-linker `--unroll-loops` here: it fully unrolls `for 0..TLS_SCRATCH_LEN` etc.,
# exploding `ssl_write_return` to thousands of insns and a huge memset subprogram (verifier pain).
env LD_LIBRARY_PATH="${_base_lp}" \
  RUSTFLAGS="${RUSTFLAGS:-} \
    -Zunstable-options \
    -Cpanic=immediate-abort \
    -Cllvm-args=--bpf-stack-size=1048576 \
    -Cllvm-args=--bpf-expand-memcpy-in-order" \
  cargo +nightly build \
    --manifest-path flow-sensor-ebpf/Cargo.toml \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release 2>&1

# -------------------------------------------------------------------
# Build userspace daemon
# -------------------------------------------------------------------
echo ""
echo "→ Building userspace daemon..."
cargo build \
    --package flow-sensor \
    --release 2>&1

# -------------------------------------------------------------------
# Done
# -------------------------------------------------------------------
echo ""
echo "✅ Build complete!"
echo ""
echo "Run with:"
echo "  sudo ./target/release/flow-sensor"
echo "  sudo ./target/release/flow-sensor --output json | jq ."
echo "  sudo ./target/release/flow-sensor --help"
