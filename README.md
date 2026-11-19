# NetScope

Linux network observer. A cgroup/skb eBPF program parses TCP and UDP packets.
Userspace correlates them with `/proc`, draws a terminal UI, and serves
Prometheus text.

This is not a packet generator. If the kernel refuses the program, the process
exits and says why. It does not invent flows.

## What was actually run

Build host: Linux `6.12.8+`, no `/sys/kernel/btf/vmlinux`, no BPF JIT
(`bpf_jit_enable` absent, `CONFIG_BPF_JIT` unset), no tracefs, no kprobes.
`/sys/fs/cgroup` is cgroup v2. `unprivileged_bpf_disabled=0`. The build ran as
uid 0 inside a cgroup namespace.

| Check | Result |
|---|---|
| `cargo test --workspace --exclude netscope-ebpf` | Userspace tests passed (10 tests with assertions, plus the live test which skips on exit 2). Collector ingest of 200_000 events on the final run: **1,749,434 events/s**. That number is the userspace `HashMap`, not the cost of the kernel hook. |
| eBPF object | Built with aya 0.14, aya-ebpf 0.2.1, bpf-linker 0.13.0, nightly rustc + `rust-src`, target `bpfel-unknown-none`. |
| `BPF_PROG_LOAD` of `cgroup_skb/ingress` and `cgroup_skb/egress` | Succeeded, after the programs were inlined. A BPF-to-BPF call (`src_reg = BPF_PSEUDO_CALL`) is rejected here with `EPERM` ("allowed for CAP_BPF and CAP_SYS_ADMIN") even though the process is uid 0. Helper calls (`bpf_skb_load_bytes`, `bpf_ringbuf_output`, `bpf_map_lookup_elem`) are accepted. |
| `BPF_LINK_CREATE` onto `/sys/fs/cgroup` | **Failed: `EPERM`.** A trivial `return 1` program fails the same way, on the root cgroup and on a child. `BPF_PROG_ATTACH` returns `EINVAL`. No packet was counted in this environment. The live test sees exit code 2 and skips. It does not pass by fabricating a metric. |
| `/proc/net/tcp` | Parsed on this machine. The IPv6 parser was checked against the kernel's documented little-endian word layout for `::1`. This host had no `tcp6` sockets to compare. |

On a machine where cgroup-bpf attach is allowed, the same binary is what you run. That attach was not demonstrated here, so this README does not show a sample of live packet counters.

## Layout

| Crate | Role |
|---|---|
| `ebpf` | cgroup/skb programs. Built only for `bpfel-unknown-none` by the agent `build.rs`. Not a host `cargo test` target. |
| `common` | `NetEvent`, the POD record shared with userspace. |
| `collector` | Flow table and `/proc` join (pid, comm, cgroup container id). |
| `exporter` | Prometheus text. |
| `tui` | Ratatui drawing. Tested with `TestBackend`, no tty. |
| `agent` | Loads, attaches, reads the ring, serves metrics, draws the UI. |

## Architecture

```
cgroup/skb ingress + egress
        |  IPv4 (no options) and IPv6 (no extension headers)
        |  ringbuf NetEvent: addrs, ports, proto, direction, IP length
        v
agent reader thread
        |  every 500ms: /proc/net/{tcp,udp,tcp6,udp6} inode
        |               -> /proc/<pid>/fd -> comm + cgroup
        v
flow table ---- TUI (ratatui)
             \-- GET /metrics
```

`cgroup_skb` cannot call `bpf_get_current_pid_tgid`. Pid, command and container
id come from `/proc`. A listening socket (remote address 0) is matched to an
established flow on the same local address, port and protocol.

`bytes` is the IPv4 total length, or the IPv6 payload length plus 40. It is
the skb length at the hook, not a value returned by `send` or `recv`.

The programs return `1` on every path, including a parse miss. Anything else
would drop the packet.

Container id: a 12- or 64-hex run in the cgroup path, including
`docker-<64 hex>.scope`. This host's `/proc/1/cgroup` is `0::/`, so no
container id was observed.

## Install

Userspace is stable Rust. The eBPF object needs:

- `nightly` with the `rust-src` component (`aya-build` uses `-Z build-std=core`)
- `bpf-linker` 0.13.0 on `PATH`

```sh
rustup toolchain install nightly --profile minimal --component rust-src
# static bpf-linker, no system LLVM required
curl -fsSL -o /tmp/bpf-linker.tar.zst \
  https://github.com/aya-rs/bpf-linker/releases/download/v0.13.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst
tar -C "$HOME/.local/bin" --zstd -xf /tmp/bpf-linker.tar.zst
export PATH="$HOME/.local/bin:$PATH"

cargo test --workspace --exclude netscope-ebpf
cargo build --release -p netscope
```

`cargo test --workspace` without `--exclude netscope-ebpf` tries to build the
eBPF crate for the host target and fails. The object is produced from
`agent/build.rs`.

## Run

```sh
sudo ./target/release/netscope
sudo ./target/release/netscope --headless --metrics 127.0.0.1:9108
sudo ./target/release/netscope --cgroup /sys/fs/cgroup --duration-ms 10000 --headless
```

The UI quits on `q` or Esc. `--headless` serves metrics until Ctrl-C or
`--duration-ms`.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Attached, ran, detached. |
| 2 | The kernel or the privileges are not there (missing cgroup, `EPERM` on load or attach). |
| 1 | Anything else, including a verifier rejection. |

Metrics bind to localhost unless you pass another address. There is no auth.

```
GET /metrics
# HELP netscope_events_total Packets parsed by the cgroup/skb programs.
# TYPE netscope_events_total counter
netscope_events_total 0
# HELP netscope_ringbuf_drops_total Packets parsed but not delivered because the ring buffer was full.
# TYPE netscope_ringbuf_drops_total counter
netscope_ringbuf_drops_total 0
# HELP netscope_flow_bytes_total Bytes observed at the cgroup/skb hook, IP header included.
# TYPE netscope_flow_bytes_total counter
```

A flow that has moved bytes is exported as
`netscope_flow_bytes_total{dir,proto,laddr,lport,raddr,rport,pid,comm,container}`.
The renderer test checks a single tx flow of 120 bytes; that is not a live
capture.

TUI, from the draw test at 120x24 (the values are the fixture, not a capture):

```
NETSCOPE  cgroup/skb  ·  real packets only
CONNECTIONS
UDP/53
10.8.0.4:5353
```

## Limits

- No BTF on the build kernel, so no CO-RE and no fentry/fexit. Not shipped.
- No tracefs and `CONFIG_KPROBES` / `CONFIG_FTRACE` are off. Tracepoints and kprobes are not shipped.
- No BPF JIT. The interpreter is what would run the program. It was not reached, because attach failed first.
- IPv4 options and IPv6 extension headers are ignored. Offsets are constants so the verifier does not see a variable `skb` load.
- BPF-to-BPF calls are not used. This kernel rejects them without init-namespace `CAP_BPF`.
- Pid is best-effort from `/proc`. Short-lived sockets can disappear before the 500ms scan. The packet is still counted, with pid 0.
- Ring buffer is 1 MiB. Overflows increment `netscope_ringbuf_drops_total`.
- Attaching to the root cgroup sees every process in that cgroup. That includes the agent.

## Docker

`Dockerfile` builds the workspace and runs the userspace tests. It skips
`observes_live_tcp` because `docker build` has nothing to attach to.

A live run needs the host kernel and a cgroup you are allowed to attach to:

```sh
docker build -t netscope .
docker run --rm --privileged --pid=host --network=host netscope \
  cargo test --test live -- --nocapture
```

Docker was not executed in the environment that produced this tree. The
Dockerfile is the recipe; it is not a claim that the image was built here.

## CI

`.github/workflows/ci.yml` installs the bpf-linker release binary, nightly
`rust-src`, and runs `cargo test --workspace --exclude netscope-ebpf`. The
live test skips with exit code 2 when the runner cannot attach.

## License

MIT. The eBPF object is GPL because the kernel requires a GPL-compatible
license section to call GPL helpers. That section is `GPL`. The Rust sources
are MIT.
