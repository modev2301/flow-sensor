# Flow Sensor

eBPF-powered network flow sensor with process attribution, TLS visibility, 
TCP quality metrics, and causal chain tracking.

**Nothing else gives you this:** process-level attribution, RTT on every ACK 
(not just handshake), retransmit reasons (RTO vs fast vs TLP), TLS plaintext 
context through proxies, and causal chains linking related flows — all in a 
single structured event per connection.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  eBPF Programs (kernel space)                        │
│  ├── tcp_lifecycle.rs   connect/accept/close/bytes   │
│  ├── tcp_quality.rs     RTT/jitter/cwnd per-ACK      │
│  ├── retransmit.rs      reason-aware retransmit       │
│  ├── tls.rs             SSL_write/read uprobes        │
│  └── causal.rs          fork/clone chain propagation │
│           ↓ ring buffer (zero-copy, 16MB)            │
├─────────────────────────────────────────────────────┤
│  Userspace (flow-sensor binary)                      │
│  ├── loader.rs          aya BPF loader + event loop  │
│  ├── enricher.rs        /proc, cgroup, k8s, ASN      │
│  ├── printer.rs         pretty/JSON/JSONL output     │
│  └── tls_attach.rs      uprobe attachment logic      │
└─────────────────────────────────────────────────────┘
```

## Requirements

- Linux kernel 5.8+ (for BPF ring buffer support)
- `CAP_BPF` + `CAP_NET_ADMIN` (or run as root)
- Rust toolchain (stable + nightly for BPF target)
- `clang` + `llvm` for BPF compilation
- `bpf-linker` **0.10+ with LLVM 22** (not the Ubuntu `bpf-linker` package — it is often LLVM 14 and triggers “opaque pointers / Reader: LLVM 14” with current nightly)

## Build

Prefer **`./build.sh`**: it installs a pinned **bpf-linker 0.10.3** with LLVM 22 under `flow-sensor-ebpf/.bpf-linker/` and points Cargo at that binary so `/usr/bin/bpf-linker` is never used.

```bash
chmod +x build.sh && ./build.sh
```

If you still see `Reader: LLVM 14.0.0`, remove the distro package (`apt remove bpf-linker`) and run `FLOW_SENSOR_FORCE_BPF_LINKER=1 ./build.sh` to reinstall the project-local linker.

### Manual steps (without `build.sh`)

```bash
# 1. Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Nightly + BPF target + rust-src (required for -Z build-std=core)
rustup toolchain install nightly --component rust-src
rustup target add --toolchain nightly bpfel-unknown-none

# 3. Project-local bpf-linker (matches nightly LLVM; avoids /usr/bin)
mkdir -p flow-sensor-ebpf/.bpf-linker
cargo +nightly install bpf-linker --version 0.10.3 --force --locked \
    --no-default-features --features rust-llvm-22,llvm-22 \
    --root flow-sensor-ebpf/.bpf-linker

# 4. Install clang/llvm (Ubuntu/Debian)
apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# 5. Build eBPF (from repo root; linker path must be this LLVM22 binary)
export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER="$PWD/flow-sensor-ebpf/.bpf-linker/bin/bpf-linker"
cargo +nightly build --manifest-path flow-sensor-ebpf/Cargo.toml \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

# 6. Build the userspace daemon (stable Rust)
cargo build --package flow-sensor --release

# The final binary is at:
# target/release/flow-sensor
```

## Run

```bash
# Basic — pretty output, all flows
sudo ./target/release/flow-sensor

# JSON output (pipe to jq, Vector, etc.)
sudo ./target/release/flow-sensor --output json | jq .

# Only flows with retransmits
sudo ./target/release/flow-sensor --retransmits-only

# Only HTTPS traffic
sudo ./target/release/flow-sensor --ports 443

# Attach TLS probes to specific process
sudo ./target/release/flow-sensor --tls-pids $(pgrep python3)

# Minimum duration filter (ignore sub-100ms connections)
sudo ./target/release/flow-sensor --min-duration-ms 100

# 1-in-10 sampling for high traffic hosts
sudo ./target/release/flow-sensor --sample-rate 10
```

## Example Output (pretty mode)

```
PROTO  PROCESS          SRC                   DST                   DIR      BYTES↑     BYTES↓     RTT(ms)  REXMT  APP CONTEXT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
TCP    python3          10.0.1.50:54821       10.0.0.1:8080         → out    1.2KB      890B       2.10     ⚠ 3    TLS/api.bigpanda.io
    ├─ quality: rtt=1.80ms-4.20ms jitter=0.80ms | retx=3 [rto=1 fast=2 tlp=0]
    ├─ tls: sni=api.bigpanda.io handshake=12.40ms
    ├─ http: POST /api/v2/alerts host=api.bigpanda.io status=200 app_rtt=48.20ms
    ├─ process: exe=/usr/bin/python3.11
    ├─ cmdline: python3 abpython_script.py --env prod
    └─ timing: duration=142.80ms ttfb=13.20ms close=clean

TCP    nginx            0.0.0.0:443           10.0.1.100:49201      ← in     48.2KB     2.1KB      0.80       0    TLS/app.example.com
    ├─ tls: sni=app.example.com handshake=3.10ms
    └─ timing: duration=890.20ms ttfb=0.40ms close=clean
```

## Example Output (JSON mode)

```json
{
  "pid": 9182, "ppid": 9100, "uid": 1000,
  "comm": "python3",
  "exe": "/usr/bin/python3.11",
  "cmdline": "python3 abpython_script.py",
  "src_ip": "10.0.1.50", "dst_ip": "10.0.0.1",
  "src_port": 54821, "dst_port": 8080,
  "protocol": "TCP", "direction": "outbound",
  "bytes_sent": 1240, "bytes_recv": 890,
  "rtt_ms": { "min": 1.8, "max": 4.2, "final": 2.1, "jitter_max": 0.8 },
  "retransmits": {
    "total": 3, "bytes": 2480,
    "rto": 1, "fast": 2, "tlp": 0,
    "sack_blocks": 2, "rate_pct": 1.2
  },
  "congestion": { "cwnd_min": 10, "cwnd_max": 32, "ecn_signals": 0 },
  "tls": { "sni": "api.bigpanda.io", "handshake_ms": 12.4 },
  "http": {
    "host": "api.bigpanda.io", "method": "POST",
    "path": "/api/v2/alerts", "status": 200,
    "app_rtt_ms": 48.2
  },
  "timing": { "duration_ms": 142.8, "ttfb_ms": 13.2 },
  "causal": { "chain_id": "0xf7a2b1", "parent_chain_id": "0x0", "depth": 0 },
  "is_external": true,
  "protocol_guess": "HTTPS",
  "close_reason": "clean"
}
```

## Piping to Vector (when ready)

```bash
# JSONL output → Vector stdin source
sudo flow-sensor --output jsonl | vector --config vector.toml

# vector.toml
[sources.flow_sensor]
type = "stdin"
decoding.codec = "json"

[sinks.clickhouse]
type = "clickhouse"
inputs = ["flow_sensor"]
endpoint = "http://localhost:8123"
table = "flows"
```

## Project Structure

```
flowsensor/
├── Cargo.toml                    # workspace
├── flow-sensor-common/           # shared types (no_std)
│   └── src/lib.rs                # FlowEvent, enums, constants
├── flow-sensor-ebpf/             # BPF programs (kernel space)
│   └── src/
│       ├── main.rs               # entry point
│       ├── maps.rs               # BPF map definitions
│       ├── tcp_lifecycle.rs      # connect/accept/close/bytes
│       ├── tcp_quality.rs        # RTT/jitter/cwnd tracking
│       ├── retransmit.rs         # retransmit reason tracking
│       ├── tls.rs                # SSL_write/read uprobes
│       └── causal.rs             # fork/clone chain propagation
└── flow-sensor/                  # userspace daemon
    └── src/
        ├── main.rs               # CLI, startup
        ├── loader.rs             # BPF loader + event loop
        ├── enricher.rs           # /proc, cgroup, k8s enrichment
        ├── printer.rs            # pretty/JSON output
        └── tls_attach.rs         # uprobe attachment
```

## Kernel Version Notes

| Feature | Min Kernel |
|---|---|
| BPF ring buffer | 5.8 |
| kprobes | 4.1 |
| uprobes | 3.5 |
| BPF LRU hash maps | 4.10 |
| BPF CO-RE (portable offsets) | 5.5 |

For full CO-RE support (avoids hardcoded struct offsets), kernel 5.5+ recommended.
The current implementation uses BTF-verified offsets; a CO-RE port would use 
`bpf_core_read!()` macros for fully portable struct access.

## Roadmap

- [ ] CO-RE (BPF Compile Once, Run Everywhere) for struct portability
- [ ] UDP flow tracking  
- [ ] IPv6 support
- [ ] gRPC export (bidirectional, with backpressure)
- [ ] Vector native source
- [ ] Fleet management (remote config, health telemetry)
- [ ] GeoIP / ASN enrichment
- [ ] IPFIX bridge (output as IPFIX for legacy collectors)
- [ ] eBPF-based enforcement (XDP drop on threat score threshold)
