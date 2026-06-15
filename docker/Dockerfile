# syntax=docker/dockerfile:1
#
# Multi-stage build + test pipeline for the PoW gate. Each stage is a checkpoint
# you can build on its own (`docker build --target <stage>`), so CI and local runs
# share exactly the same steps. See ../docs/testing.md.
#
#   core-test     → run the nginx-free engine unit tests (must pass)
#   module-build  → compile the dynamic module .so against a pinned nginx (proves
#                   the FFI shell compiles + is ABI-bound to that nginx)
#   nginx-smoke   → load the .so into that nginx and run `nginx -t`
#   e2e           → run the black-box client against a live nginx (full handshake)
#
# Keep NGINX_VERSION identical across the build and runtime stages — a module is
# only loadable by the exact nginx it was built against.

# Rust 1.85+ is required: a transitive crypto dep (base64ct) uses edition 2024.
ARG RUST_VERSION=1.90
ARG NGINX_VERSION=1.31.1

# ───────────────────────────── 1. core unit tests ────────────────────────────
FROM rust:${RUST_VERSION}-bookworm AS core-test
WORKDIR /src
COPY src/pow-gate-core/ src/pow-gate-core/
# Build & test the engine alone — no nginx needed, fast and deterministic.
RUN cd src/pow-gate-core && cargo test --locked || cargo test

# ──────────────────────────── 2. build the module ────────────────────────────
FROM rust:${RUST_VERSION}-bookworm AS module-build
ARG NGINX_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential perl libclang-dev clang libpcre2-dev zlib1g-dev libssl-dev \
      curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Fetch + CONFIGURE the matching nginx (nginx-sys needs the objs/ a `./configure`
# produces). --with-compat gives a stable module ABI so the runtime nginx package
# accepts the .so. Then build the cdylib against that configured tree.
RUN set -eux; \
    curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar -xz -C /tmp; \
    cd "/tmp/nginx-${NGINX_VERSION}" && ./configure --with-compat && cd /src; \
    export NGINX_SOURCE_DIR="/tmp/nginx-${NGINX_VERSION}"; \
    cargo build --release -p ngx-http-pow-gate; \
    cp target/release/libngx_http_pow_gate.so /ngx_http_pow_gate_module.so

# ──────────────────────────── 3. nginx load smoke ────────────────────────────
FROM nginx:${NGINX_VERSION} AS nginx-smoke
COPY --from=module-build /ngx_http_pow_gate_module.so /etc/nginx/modules/ngx_http_pow_gate_module.so
COPY docker/nginx.test.conf /etc/nginx/nginx.conf
RUN install -d -m 700 /etc/pow && head -c 32 /dev/urandom > /etc/pow/hmac.key && chmod 600 /etc/pow/hmac.key
# the "upstream" content (served in the CONTENT phase, after the gate runs) +
# the verifier IP-range feed (0.0.0.0/0 so any client IP is "in range").
RUN install -d /var/www \
 && printf 'upstream-content\n' > /var/www/index.html \
 && printf 'ok\n' > /var/www/healthz.txt \
 && printf '{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"},{"ipv6Prefix":"::/0"}]}\n' > /var/www/ranges.json
# Fails the build if the module is ABI-incompatible or any directive won't parse.
RUN nginx -t

# ───────────────────────────── 4. e2e test client ────────────────────────────
# Builds the black-box client that walks challenge → solve → verify → cleared,
# reusing pow-gate-core to solve the PoW and sign proofs (same crate the server
# uses). Run it against a live nginx via docker-compose.test.yml.
FROM rust:${RUST_VERSION}-bookworm AS e2e
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY src/pow-gate-core/ src/pow-gate-core/
COPY tests/integration/ tests/integration/
RUN cd tests/integration && cargo build --release
ENV BASE_URL=http://nginx:8080
CMD ["/src/tests/integration/target/release/pow-gate-e2e"]

# ───────────────────────────── 5. perf load client ───────────────────────────
# Builds the load generator (docs/performance.md). Run against a live nginx via
# docker-compose.perf.yml. Knobs via PERF_DURATION / PERF_CONCURRENCY / PERF_MODES.
FROM rust:${RUST_VERSION}-bookworm AS perf
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY src/pow-gate-core/ src/pow-gate-core/
COPY perf/ perf/
RUN cd perf && cargo build --release
ENV BASE_URL=http://nginx:8080
CMD ["/src/perf/target/release/pow-gate-perf"]
