# Builds NetScope and runs the userspace tests.
# The live eBPF test is skipped here: `docker build` does not give the
# compiler a cgroup to attach to. Run it on a Linux host instead:
#   docker run --rm --privileged --pid=host --network=host netscope \
#     cargo test --test live -- --nocapture
FROM rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --profile minimal --component rust-src

RUN mkdir -p /usr/local/bin \
    && curl -fsSL -o /tmp/bpf-linker.tar.zst \
        https://github.com/aya-rs/bpf-linker/releases/download/v0.13.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst \
    && tar -C /usr/local/bin --zstd -xf /tmp/bpf-linker.tar.zst \
    && chmod +x /usr/local/bin/bpf-linker \
    && rm /tmp/bpf-linker.tar.zst \
    && bpf-linker --version

WORKDIR /src
COPY . .
RUN cargo test --workspace --exclude netscope-ebpf -- --skip observes_live_tcp
