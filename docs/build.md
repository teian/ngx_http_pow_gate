# Building & installing

How to compile the module, match it to your nginx, install it, and load it.

- [The golden rule: ABI compatibility](#the-golden-rule-abi-compatibility)
- [Prerequisites](#prerequisites)
- [Build steps](#build-steps)
- [How the nginx source is selected](#how-the-nginx-source-is-selected)
- [Matching your running nginx](#matching-your-running-nginx)
- [Install & load](#install--load)
- [Reproducible build with Docker](#reproducible-build-with-docker)
- [Verifying & reloading](#verifying--reloading)
- [Troubleshooting](#troubleshooting)

---

## The golden rule: ABI compatibility

A dynamic nginx module is **not** portable across nginx builds. nginx records a
signature (version + key `./configure` options) and refuses any module whose
signature differs:

```
nginx: [emerg] module "/etc/nginx/modules/ngx_http_pow_gate_module.so" is not
binary compatible
```

So: **build the module against the exact nginx version and configure arguments of
the nginx that will load it.** Get those from `nginx -V` (see
[Matching your running nginx](#matching-your-running-nginx)).

---

## Prerequisites

- **Rust** ≥ 1.85 (`rustup` recommended; a transitive crypto dep uses edition
  2024). The crate builds a `cdylib`.
- A **C toolchain** and the libraries nginx itself needs, because the build
  compiles/inspects nginx source:
  - `cc`, `make`
  - `pcre2` (or `pcre`), `zlib`, `openssl` development headers
  - `libclang` (for `bindgen`, used by `nginx-sys` to generate FFI bindings)

On Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential libclang-dev libpcre2-dev zlib1g-dev libssl-dev
```

On Fedora:

```bash
sudo dnf install -y @development-tools clang-devel pcre2-devel zlib-devel openssl-devel
```

---

## Build steps

```bash
# 1. point the build at a CONFIGURED nginx source (nginx-sys needs its objs/)
curl -fsSL https://nginx.org/download/nginx-1.31.1.tar.gz | tar -xz -C "$HOME/src"
( cd "$HOME/src/nginx-1.31.1" && ./configure --with-compat )
export NGINX_SOURCE_DIR="$HOME/src/nginx-1.31.1"

# 2. build the optimized shared object (workspace: select the module crate)
cargo build --release -p ngx-http-pow-gate

# 3. the artifact (crate name → lib<name>.so), in the workspace target/
ls -l target/release/libngx_http_pow_gate.so
```

> The artifact is named after the crate (`libngx_http_pow_gate.so`). You rename
> it to whatever you reference in `load_module` — this project uses
> `ngx_http_pow_gate_module.so`.

---

## How the nginx source is selected

The `ngx` crate's build (via `nginx-sys`) needs nginx headers to generate
bindings and emit the correct module link flags. You control which nginx with
environment variables — set them before `cargo build`:

| Variable               | Effect                                                                   |
| ---------------------- | ------------------------------------------------------------------------ |
| `NGINX_SOURCE_DIR`     | Use an unpacked **and `./configure`-d** nginx tree (it needs the `objs/`). |
| `NGX_VERSION`          | Which nginx version to download if no source dir is given (needs `ngx/vendored`; defaults to `1.31.1` via [`.cargo/config.toml`](../.cargo/config.toml)). |
| `NGINX_BUILD_DIR`      | Where to place/find the configured build output (the `objs/` dir).       |
| `NGX_CONFIGURE_ARGS`   | The `./configure` flags — **must mirror your target nginx** (see below). |

> Mind the prefix split (it is **not** a typo): `NGINX_SOURCE_DIR` /
> `NGINX_BUILD_DIR` are read by `nginx-sys`, while `NGX_VERSION` /
> `NGX_CONFIGURE_ARGS` are read by the `nginx-src` crate it pulls in for the
> download path. Names have also shifted across releases; if a build can't find
> nginx, check those crates' README/build.rs for the exact names in the `ngx`
> version pinned in [`Cargo.toml`](../Cargo.toml) (`0.5`). The principle is
> constant: the module is bound to one nginx build.

---

## Matching your running nginx

1. Read the target's build config:

   ```bash
   nginx -V
   # nginx version: nginx/1.31.1
   # built with OpenSSL ...
   # configure arguments: --prefix=/etc/nginx --with-compat --with-http_ssl_module ...
   ```

2. **`--with-compat` is the easy path.** Distro and official nginx.org packages
   are almost always built with `--with-compat`, which enables a stable module
   ABI. If your target has it, build the module against a matching nginx version
   that *also* uses `--with-compat`, and you don't have to replicate every other
   flag:

   ```bash
   export NGX_VERSION=1.31.1   # defaults to 1.31.1 via .cargo/config.toml
   export NGX_CONFIGURE_ARGS="--with-compat"
   cargo build --release --features ngx/vendored
   ```

3. **Without `--with-compat`,** replicate the version *and* the full
   `configure arguments` from `nginx -V` into `NGX_CONFIGURE_ARGS`.

---

## Install & load

```bash
# copy + rename into nginx's modules directory
sudo cp target/release/libngx_http_pow_gate.so \
        /etc/nginx/modules/ngx_http_pow_gate_module.so

# create the server secret if you haven't
sudo install -d -m 700 /etc/pow
sudo head -c 32 /dev/urandom | sudo tee /etc/pow/hmac.key >/dev/null
sudo chmod 600 /etc/pow/hmac.key
sudo chown nginx:nginx /etc/pow/hmac.key
```

Load it at the **top** of `nginx.conf` (before the `http {}` block):

```nginx
load_module modules/ngx_http_pow_gate_module.so;
```

Then add the configuration from [examples/nginx.conf](../examples/nginx.conf).

---

## Reproducible build with Docker

Building inside an image that matches your runtime nginx is the most reliable way
to get the ABI right. **This repo already ships that** — see
[docker/Dockerfile](../docker/Dockerfile) (multi-stage: core tests → build →
`nginx -t` smoke → e2e) and [docs/testing.md](testing.md). The `module-build`
stage is the canonical reference; its essence:

```dockerfile
# Build against the same nginx version you deploy.
FROM rust:1.90-bookworm AS build
RUN apt-get update && apt-get install -y \
    build-essential perl libclang-dev clang libpcre2-dev zlib1g-dev libssl-dev \
    curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# nginx-sys needs a CONFIGURED nginx (the objs/ that ./configure produces):
RUN curl -fsSL https://nginx.org/download/nginx-1.31.1.tar.gz | tar -xz -C /tmp \
 && (cd /tmp/nginx-1.31.1 && ./configure --with-compat) \
 && NGINX_SOURCE_DIR=/tmp/nginx-1.31.1 cargo build --release

FROM nginx:1.31.1          # MUST match the nginx built against above
COPY --from=build /src/target/release/libngx_http_pow_gate.so \
     /etc/nginx/modules/ngx_http_pow_gate_module.so
# add your nginx.conf + /etc/pow/hmac.key via secrets/volume
```

Keep `NGINX_VERSION` (build stage) and the `nginx:` runtime tag locked to the
same value.

---

## Verifying & reloading

```bash
nginx -t            # validate config + that the module loads & is ABI-compatible
sudo nginx -s reload
```

`nginx -t` is the fast check for the "not binary compatible" error — it surfaces
at config-test time, before you touch live traffic.

---

## Troubleshooting

| Symptom                                              | Cause / fix                                                                 |
| ---------------------------------------------------- | --------------------------------------------------------------------------- |
| `module ... is not binary compatible`                | Built against a different nginx version/flags. Rebuild to match `nginx -V`. |
| `dlopen() ... undefined symbol`                      | Missing/extra nginx module in `configure` args, or wrong nginx source.      |
| `cannot find -lclang` / bindgen errors               | Install `libclang-dev` (Debian) / `clang-devel` (Fedora).                   |
| build can't locate nginx source                      | Set `NGINX_SOURCE_DIR`, or build `--features ngx/vendored` (downloads `NGX_VERSION`, default 1.31.1). |
| `load_module` → `unknown directive`                  | `load_module` must be in the **main** context, above `http {}`.             |
| 403 for everyone behind a load balancer              | Configure `set_real_ip_from` / `real_ip_header` so `$remote_addr` is real.  |
| Challenge never completes                             | Check the browser console + that `{endpoint}solver.js` / `challenge` / `verify` return 200; the clock skew vs `pow_gate_proof_skew`. |

For the deeper "why" behind any of this, see
[docs/architecture.md](architecture.md).
