# syntax=docker/dockerfile:1
#
# Multi-stage build + test pipeline for the PoW gate. Each stage is a checkpoint
# you can build on its own (`docker build --target <stage>`), so CI and local runs
# share exactly the same steps. See ../docs/testing.md.
#
#   core-test            → run the nginx-free engine unit tests (must pass)
#   module-build-debian  → compile the .so on Debian trixie (glibc)
#   module-build-alpine  → compile the .so on Alpine (musl)
#   module-export-{debian,alpine} → emit just the .so (`--output type=local`)
#   nginx-smoke-{debian,alpine}   → load the matching .so into nginx + `nginx -t`
#   e2e                  → run the black-box client against a live nginx
#
# An nginx dynamic module is libc-specific: the glibc (.so from trixie) loads into
# the Debian nginx image, the musl one into nginx:alpine. Both target the SAME
# nginx version, built `--with-compat` for a stable module ABI.
#
# Reproducible builds: base images are pinned by DIGEST (not just tag) and the
# nginx source tarball by SHA256, so each .so is byte-identical given the same
# Cargo.lock + toolchain. Update a digest with `docker buildx imagetools inspect
# <image:tag>`; update NGINX_SHA256 from https://nginx.org/download/.
#
# Base images are pulled through mirror.gcr.io (Google's public pull-through cache
# of Docker Hub) to dodge Docker Hub's anonymous pull rate limit on shared CI IPs.
# Digests are unchanged (same content), so reproducibility pins still hold.
# Override REGISTRY=docker.io/library to go straight to Docker Hub.
ARG REGISTRY=mirror.gcr.io/library
# Rust 1.85+ is required: a transitive crypto dep (base64ct) uses edition 2024.
ARG RUST_VERSION=1.95
ARG RUST_TRIXIE_DIGEST=sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3
ARG RUST_ALPINE_DIGEST=sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2
ARG NGINX_VERSION=1.31.8
ARG NGINX_DEBIAN_DIGEST=sha256:6e67f8eaac94fc456588d4ff6c470d984841f5b5dc4279863d5cbe6ec5a60def
ARG NGINX_ALPINE_DIGEST=sha256:e2d97c2b8c016f12c2f1a27d095685063b2f281c4edf2babfde6001cf4fb77a8
ARG NGINX_SHA256=0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1

# Determinism knobs shared by both module builds: a fixed epoch, no incremental
# artifacts, C locale/UTC, a single codegen unit (removes parallel-codegen
# ordering nondeterminism), and path remapping so no absolute build/registry
# paths leak into the .so. (Set per stage — ENV does not cross FROM.)

# ───────────────────────────── 1. core unit tests ────────────────────────────
FROM ${REGISTRY}/rust:${RUST_VERSION}-trixie@${RUST_TRIXIE_DIGEST} AS core-test
WORKDIR /src
COPY src/pow-gate-core/ src/pow-gate-core/
# Build & test the engine alone — no nginx needed, fast and deterministic.
RUN cd src/pow-gate-core && cargo test --locked || cargo test

# ──────────────────────── 2a. build the module (Debian) ──────────────────────
FROM ${REGISTRY}/rust:${RUST_VERSION}-trixie@${RUST_TRIXIE_DIGEST} AS module-build-debian
ARG TARGETARCH
ARG CARGO_BUILD_JOBS
ARG NGINX_VERSION
ARG NGINX_SHA256
# clang/libclang are pinned to a major version: nginx-sys runs bindgen, whose
# output depends on the libclang version, so a floating clang would break
# byte-for-byte reproducibility. LIBCLANG_PATH points bindgen at this exact one.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential perl clang-19 libclang-19-dev libpcre2-dev zlib1g-dev libssl-dev \
      curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV LIBCLANG_PATH=/usr/lib/llvm-19/lib
ENV SOURCE_DATE_EPOCH=1700000000 \
    CARGO_INCREMENTAL=0 \
    LC_ALL=C \
    TZ=UTC \
    RUSTFLAGS="--remap-path-prefix=/var/cache/cargo=/cargo --remap-path-prefix=/src=/build -C codegen-units=1"
WORKDIR /src
# Fetch + verify + CONFIGURE the matching nginx (nginx-sys needs the objs/ a
# `./configure` produces). --with-compat gives a stable module ABI so the runtime
# nginx package accepts the .so. The configured source is cached separately
# from module source changes; compilation uses the committed Cargo.lock.
RUN set -eux; \
    curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o /tmp/nginx.tar.gz; \
    echo "${NGINX_SHA256}  /tmp/nginx.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/nginx.tar.gz -C /tmp; \
    cd "/tmp/nginx-${NGINX_VERSION}"; \
    ./configure --with-compat
COPY . .
# Reuse Cargo's complete cache/lock and target artifacts across source changes.
# Keep architectures and libc variants apart; nginx-sys tracks its source env.
# Touch crate roots so copied source timestamps cannot hide a changed module.
# The exported .so lives outside the cache mount and remains in the image.
RUN --mount=type=cache,id=pow-cargo-debian-${TARGETARCH},target=/var/cache/cargo,sharing=locked \
    --mount=type=cache,id=pow-target-debian-${TARGETARCH},target=/src/target,sharing=locked \
    touch src/pow-gate-core/src/lib.rs src/ngx-http-pow-gate/src/lib.rs && \
    CARGO_HOME=/var/cache/cargo NGINX_SOURCE_DIR="/tmp/nginx-${NGINX_VERSION}" \
    cargo build --release --locked -p ngx-http-pow-gate && \
    cp target/release/libngx_http_pow_gate.so /ngx_http_pow_gate_module.so

# Failed reloads must not change the verifier policy inherited by respawned
# workers. Build the matching nginx executable and exercise this unprivileged.
FROM module-build-debian AS security-reload
ARG NGINX_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends python3 procps util-linux \
    && rm -rf /var/lib/apt/lists/*
RUN make -C "/tmp/nginx-${NGINX_VERSION}" -j"${CARGO_BUILD_JOBS:-2}"
RUN runuser -u nobody -- python3 /src/tests/pow-clearance/reload-test.py \
      /tmp/nginx-${NGINX_VERSION}/objs/nginx /ngx_http_pow_gate_module.so

# ──────────────────────── 2b. build the module (Alpine) ──────────────────────
FROM ${REGISTRY}/rust:${RUST_VERSION}-alpine@${RUST_ALPINE_DIGEST} AS module-build-alpine
ARG TARGETARCH
ARG CARGO_BUILD_JOBS
ARG NGINX_VERSION
ARG NGINX_SHA256
# musl toolchain: build-base (gcc/make/musl headers) + the -dev libs nginx's
# ./configure compiles against, plus a pinned clang/libclang for bindgen.
RUN apk add --no-cache \
      build-base linux-headers perl pcre2-dev zlib-dev openssl-dev \
      clang19-dev clang19-libclang llvm19-dev \
      curl ca-certificates
ENV LIBCLANG_PATH=/usr/lib/llvm19/lib
# `-crt-static`: the rust:alpine musl target defaults to a static CRT, which
# forbids cdylib output ("target ... does not support these crate types"). Turn
# it off so we get a .so dynamically linked against musl libc. The resulting
# module needs `ld-musl`, `libc.musl` and `libgcc_s.so.1` at load time — all
# present in the official nginx:alpine image (verified: `nginx -t` loads it).
ENV SOURCE_DATE_EPOCH=1700000000 \
    CARGO_INCREMENTAL=0 \
    LC_ALL=C \
    TZ=UTC \
    RUSTFLAGS="--remap-path-prefix=/var/cache/cargo=/cargo --remap-path-prefix=/src=/build -C codegen-units=1 -C target-feature=-crt-static"
WORKDIR /src
# Same recipe as Debian; the default host target here is x86_64-unknown-linux-musl,
# so the cdylib links musl and loads into nginx:alpine.
RUN set -eux; \
    curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o /tmp/nginx.tar.gz; \
    echo "${NGINX_SHA256}  /tmp/nginx.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/nginx.tar.gz -C /tmp; \
    cd "/tmp/nginx-${NGINX_VERSION}"; \
    ./configure --with-compat
COPY . .
# Reuse Cargo's complete cache/lock and target artifacts across source changes.
# Keep architectures and libc variants apart; nginx-sys tracks its source env.
# Touch crate roots so copied source timestamps cannot hide a changed module.
# The exported .so lives outside the cache mount and remains in the image.
RUN --mount=type=cache,id=pow-cargo-alpine-${TARGETARCH},target=/var/cache/cargo,sharing=locked \
    --mount=type=cache,id=pow-target-alpine-${TARGETARCH},target=/src/target,sharing=locked \
    touch src/pow-gate-core/src/lib.rs src/ngx-http-pow-gate/src/lib.rs && \
    CARGO_HOME=/var/cache/cargo NGINX_SOURCE_DIR="/tmp/nginx-${NGINX_VERSION}" \
    cargo build --release --locked -p ngx-http-pow-gate && \
    cp target/release/libngx_http_pow_gate.so /ngx_http_pow_gate_module.so

# ─────────────── 2c. export just the .so (for `--output type=local`) ──────────
# `docker build --target module-export-debian --output type=local,dest=dist .`
# writes the bare .so to ./dist — used by the release workflow to attest/sign it.
FROM scratch AS module-export-debian
COPY --from=module-build-debian /ngx_http_pow_gate_module.so /ngx_http_pow_gate_module.so

FROM scratch AS module-export-alpine
COPY --from=module-build-alpine /ngx_http_pow_gate_module.so /ngx_http_pow_gate_module.so

# ──────────────────────── 3. nginx load smoke (per libc) ──────────────────────
FROM ${REGISTRY}/rust:${RUST_VERSION}-trixie@${RUST_TRIXIE_DIGEST} AS test-tls
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/test-tls.sh /test-tls.sh
RUN bash /test-tls.sh /test-tls

# Shared config + fixtures, parameterised only by which base image / .so. The
# 32-byte key is world-readable (644) ONLY because this test container's nginx
# worker may run unprivileged and the gate fails closed if it can't read the key.
# Production guidance stays 600 + `chown nginx` (see docs/configuration.md).
FROM ${REGISTRY}/nginx:${NGINX_VERSION}@${NGINX_DEBIAN_DIGEST} AS nginx-smoke-debian
COPY --from=test-tls /test-tls /etc/pow/test-tls
COPY --from=module-build-debian /ngx_http_pow_gate_module.so /etc/nginx/modules/ngx_http_pow_gate_module.so
COPY docker/nginx.test.conf /etc/nginx/nginx.conf
RUN install -d -m 755 /etc/pow && head -c 32 /dev/urandom > /etc/pow/hmac.key && chmod 644 /etc/pow/hmac.key
RUN install -d /var/www \
 && printf 'ok\n' > /var/www/healthz.txt \
 && printf '{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"},{"ipv6Prefix":"::/0"}]}\n' > /var/www/ranges.json
# Fake upstream page; carries the "upstream-content" marker the e2e client
# greps for and renders the solver's sessionStorage("pow-result") stats.
# posted.html is the dev sandbox's landing page for a POST that got through
# (nginx.dev.conf maps the static handler's 405 to it) — how a human sees a
# replayed submission.
COPY docker/www/index.html /var/www/index.html
COPY docker/www/posted.html /var/www/posted.html
# Fails the build if the module is ABI-incompatible or any directive won't parse.
RUN nginx -t

FROM ${REGISTRY}/nginx:${NGINX_VERSION}-alpine@${NGINX_ALPINE_DIGEST} AS nginx-smoke-alpine
COPY --from=test-tls /test-tls /etc/pow/test-tls
COPY --from=module-build-alpine /ngx_http_pow_gate_module.so /etc/nginx/modules/ngx_http_pow_gate_module.so
COPY docker/nginx.test.conf /etc/nginx/nginx.conf
RUN install -d -m 755 /etc/pow && head -c 32 /dev/urandom > /etc/pow/hmac.key && chmod 644 /etc/pow/hmac.key
RUN install -d /var/www \
 && printf 'ok\n' > /var/www/healthz.txt \
 && printf '{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"},{"ipv6Prefix":"::/0"}]}\n' > /var/www/ranges.json
COPY docker/www/index.html /var/www/index.html
COPY docker/www/posted.html /var/www/posted.html
RUN nginx -t

# ───────────────────────────── 4. e2e test client ────────────────────────────
# Builds the black-box client that walks challenge → solve → verify → cleared,
# reusing pow-gate-core to solve the PoW and sign proofs (same crate the server
# uses). Run it against a live nginx via docker-compose.test.yml. The client is
# libc-agnostic; it exercises whichever nginx (glibc/musl) it's pointed at.
FROM ${REGISTRY}/rust:${RUST_VERSION}-trixie@${RUST_TRIXIE_DIGEST} AS e2e
ARG CARGO_BUILD_JOBS
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config ca-certificates nodejs python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY src/pow-gate-core/ src/pow-gate-core/
COPY tests/integration/ tests/integration/
COPY tests/pow-clearance/ tests/pow-clearance/
RUN python3 -m venv /opt/http3 && /opt/http3/bin/pip install --no-cache-dir -r tests/pow-clearance/http3-requirements.txt
COPY --from=test-tls /test-tls/cert.pem /test-tls/cert.pem
ARG TARGETARCH
# Keep the standalone client cache across core edits and nginx/libc test cells.
# Export the executable outside the mount so the test image remains runnable.
RUN --mount=type=cache,id=pow-registry-e2e-${TARGETARCH},target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=pow-target-e2e-${TARGETARCH},target=/src/tests/integration/target,sharing=locked \
    touch src/pow-gate-core/src/lib.rs tests/integration/src/main.rs && \
    cargo build --manifest-path tests/integration/Cargo.toml --release --locked && \
    cp tests/integration/target/release/pow-gate-e2e /usr/local/bin/pow-gate-e2e
ENV BASE_URL=http://nginx:8080
ENV HTTP3_BASE_URL=https://nginx:8443
CMD ["sh", "-c", "/usr/local/bin/pow-gate-e2e && node /src/tests/pow-clearance/security-test.mjs \"$BASE_URL\" && node /src/tests/pow-clearance/http2-test.mjs \"$BASE_URL\" && /opt/http3/bin/python /src/tests/pow-clearance/http3-test.py \"$HTTP3_BASE_URL\" --ca-file /test-tls/cert.pem"]

# ───────────────────────────── 5. perf load client ───────────────────────────
# Builds the load generator (docs/performance.md). Run against a live nginx via
# docker-compose.perf.yml. Knobs via PERF_DURATION / PERF_CONCURRENCY / PERF_MODES.
FROM ${REGISTRY}/rust:${RUST_VERSION}-trixie@${RUST_TRIXIE_DIGEST} AS perf
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY src/pow-gate-core/ src/pow-gate-core/
COPY perf/ perf/
RUN cd perf && cargo build --release
ENV BASE_URL=http://nginx:8080
CMD ["/src/perf/target/release/pow-gate-perf"]
