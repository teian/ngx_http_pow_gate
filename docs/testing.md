# Testing & self-verification

The project verifies itself at three levels, each runnable on its own. The split
exists because the crypto can be tested anywhere, but the nginx module can only be
built and exercised against a real nginx — so that part runs in Docker.

```mermaid
flowchart TD
    A[core unit tests<br/>cargo test -p pow-gate-core] --> B[module-build-debian / -alpine<br/>compile .so vs pinned nginx, glibc + musl]
    B --> C[nginx-smoke-debian / -alpine<br/>load module, nginx -t]
    C --> D[e2e<br/>live challenge→solve→verify→cleared, per libc]
```

- [Layout: where tests live](#layout-where-tests-live)
- [1. Core unit tests (no Docker)](#1-core-unit-tests-no-docker)
- [2. Module build (Docker)](#2-module-build-docker)
- [3. nginx smoke (Docker)](#3-nginx-smoke-docker)
- [4. End-to-end (Docker Compose)](#4-end-to-end-docker-compose)
- [One command](#one-command)
- [Manual testing (browser / curl)](#manual-testing-browser--curl)
- [CI](#ci)
- [What each layer proves](#what-each-layer-proves)

---

## Layout: where tests live

All code lives under a crate's `src/`: the nginx module in
`src/ngx-http-pow-gate/src/`, the engine in `src/pow-gate-core/src/`.
**Tests are their own projects**, never mixed into the source files:

```text
src/pow-gate-core/tests/         integration tests for the engine — one crate per file
                    (target, codec, pow, clearance, proof, ranges), public API only
tests/integration/  the black-box e2e client — a standalone Cargo project that
                    is NOT a workspace member (no nginx dependency)
docker/             Dockerfile (multi-stage pipeline) + nginx.test.conf
docker-compose.test.yml   wires nginx + the e2e client together
scripts/test.sh     runs the whole thing locally
```

---

## 1. Core unit tests (no Docker)

The engine — PoW target math, the challenge handshake, clearance tokens, and the
ECDSA proof — is a pure-Rust crate (`src/pow-gate-core/`) with no nginx
dependency, so it runs on any machine in well under a second:

```bash
cd src/pow-gate-core && cargo test
# or from the repo root:
cargo test -p pow-gate-core
```

These tests pin the wire contract the browser must reproduce (the PoW hash, the
`difficulty → target` math) and prove the security properties: forged/expired/
tampered tokens are rejected, a client can't downgrade difficulty, and stale or
mismatched proofs fail.

---

## 2. Module build (Docker)

Compiles the dynamic module `.so` against a pinned nginx source. This is the step
you can't do without a matching nginx — it proves the FFI shell compiles and is
ABI-bound to that nginx. A dynamic module is libc-specific, so there is one stage
per target:

```bash
docker build -f docker/Dockerfile --target module-build-debian .   # glibc (Debian trixie)
docker build -f docker/Dockerfile --target module-build-alpine .   # musl  (Alpine)
```

Pin `NGINX_VERSION` (build arg) to the nginx you deploy; `--with-compat` gives a
stable module ABI (see [build.md](build.md)).

---

## 3. nginx smoke (Docker)

Loads the freshly built `.so` into the matching `nginx:<version>` image (Debian
or Alpine) and runs `nginx -t` against
[docker/nginx.test.conf](../docker/nginx.test.conf), which exercises **every**
directive. It fails if the module is ABI-incompatible or any directive won't
parse:

```bash
docker build -f docker/Dockerfile --target nginx-smoke-debian .   # glibc
docker build -f docker/Dockerfile --target nginx-smoke-alpine .   # musl
```

---

## 4. End-to-end (Docker Compose)

Brings up nginx with the module, then runs the black-box client
([tests/integration](../tests/integration)) which walks the full handshake —
fetch a challenge, **solve it with `pow-gate-core`**, submit, then make a cleared
request with a **`p256`-signed proof** (the same primitives the browser uses):

```bash
docker compose -f docker-compose.test.yml up --build \
  --abort-on-container-exit --exit-code-from e2e
```

Exit code is the client's, so it gates CI. The client asserts: excluded paths are
never gated, an uncleared request is challenged, `/verify` sets a clearance
cookie, a cleared request reaches the upstream, and a challenged `POST` (and
`PUT`) comes back inside the challenge page verbatim (`pow_gate_replay`) — with
`replay off` and an oversized body falling back to the plain page, and
`client_max_body_size` still rejecting ahead of the gate.

---

## One command

```bash
./scripts/test.sh          # core tests + full Docker pipeline
./scripts/test.sh core     # just the engine tests (fast)
./scripts/test.sh docker   # build + smoke + e2e
```

---

## Manual testing (browser / curl)

The automated e2e proves the protocol; the manual sandbox is for everything a
human notices — the challenge page rendering, solver progress, cookie behaviour
across reloads, a custom `pow_gate_page`. It publishes nginx + the module on
`http://localhost:12222` (an unassuming port, so it does not collide with the
usual 8080 tenants):

```bash
./scripts/dev.sh up       # build + start, prints what to try (default when run bare)
./scripts/dev.sh check    # smoke checks + full node handshake; exits 1 on any failure
./scripts/dev.sh reload   # nginx -t, then apply an edited docker/nginx.dev.conf (no rebuild)
./scripts/dev.sh logs     # follow nginx logs
./scripts/dev.sh down     # stop + remove, including volumes
```

The script needs `docker compose` and can be run from anywhere (it cd's to the
repo root itself). `check` needs node ≥ 20 for the handshake part; without node
it still runs the curl smoke checks and just skips the automated solve.

Open `http://localhost:12222/` in a browser: you get the challenge page, the
solver runs (a browser hashes far slower than native, so this
still shows the progress bar for a few seconds), and after
verification a reload serves the stubbed upstream page via the clearance
cookie. That page ([docker/www/index.html](../docker/www/index.html)) renders
the **computation result** of the solve — winning nonce, hashes tried, solve
time, hash rate, salt and the recomputed winning hash (leading zeros
highlighted) — from the `pow-result` record the solver leaves in
`sessionStorage`. Recording is **opt-in** (off by default, production never
records): pages opt in with `data-record-result` on the solver `<script>` tag.
The dev sandbox serves a generated copy of the embedded page with that
attribute added (`scripts/dev.sh` builds `docker/challenge.dev.html`, served
via `pow_gate_page` — which doubles as live coverage for that directive).
That page also carries the **POST replay** test — the one part of the flow no
headless client can exercise, because it runs in `solver.js`. Click *“Drop
clearance, then POST”*: the sandbox expires the cookie server-side (it is
HttpOnly), the form submits, the gate answers that POST with the challenge page,
and after the solve the solver re-issues the submission — you land on
**POST received** ([docker/www/posted.html](../docker/www/posted.html)) instead
of losing it. Open the Network tab to confirm the replayed request carries the
original payload. Without the drop, the same button set just POSTs while cleared
and goes straight there.

Useful curl checks (also printed by `dev.sh up`):

| Request | Expected |
| --- | --- |
| `curl -i localhost:12222/` | challenge HTML — no clearance |
| `curl localhost:12222/healthz` | `ok` — excluded path, never gated |
| `curl -A verifierbot localhost:12222/` | upstream content — verified good bot |
| `curl -iA denybot localhost:12222/` | denied |

`./scripts/dev.sh check` runs the same checks headlessly: curl smoke checks
(challenge served, endpoints up, excluded path, verifier allow, deny) plus the
full handshake via [tests/pow-clearance/solve-test.mjs](../tests/pow-clearance/solve-test.mjs) — a
node port of `assets/solver.js` that solves the PoW, posts `/verify`, replays
the clearance cookie as a top-level navigation and expects the upstream
marker. It needs only node ≥ 20, no cargo.

Unlike `nginx.test.conf` (baked into the image), [docker/nginx.dev.conf](../docker/nginx.dev.conf)
is **volume-mounted**: tweak difficulty, cookies, decisions, or point
`pow_gate_page` at a mounted custom page (see the commented lines there and in
[docker-compose.dev.yml](../docker-compose.dev.yml)), then `./scripts/dev.sh reload`.
Only module code changes need a rebuild (`./scripts/dev.sh up`). Knobs:
`DEV_PORT=9090` for another host port, `DEV_TARGET=nginx-smoke-alpine` for the
musl build.

---

## CI

CI is split across a few workflows:

- [ci.yml](../.github/workflows/ci.yml) — a fast `core` job (engine tests + e2e
  client compiles) and an `e2e` job (the live handshake) as a **matrix of
  `{libc × arch}`** (`debian`→glibc, `alpine`→musl, on `amd64` and `arm64`).
- [module-amd64.yml](../.github/workflows/module-amd64.yml) /
  [module-arm64.yml](../.github/workflows/module-arm64.yml) — build the `.so` +
  `nginx -t` for both libc on each architecture. Split per arch so each carries
  its own status badge (native arm runners, no QEMU; digest-pinned multi-arch
  base images resolve to the runner's arch).
- [release.yml](../.github/workflows/release.yml) — on a tag: reproducible double
  build + provenance + cosign + checksums for all four `{libc × arch}` `.so`s; see
  [build.md](build.md#verifiable-builds).

---

## What each layer proves

| Layer        | Proves                                                              | Needs   |
| ------------ | ------------------------------------------------------------------ | ------- |
| core tests   | the crypto/protocol is correct and the wire contract is pinned     | Rust    |
| module-build-{debian,alpine} | the FFI shell compiles + is ABI-bound to nginx, on glibc and musl | Docker  |
| nginx-smoke-{debian,alpine}  | the module loads and every directive parses, on both libc          | Docker  |
| e2e          | the live request flow works end to end against real nginx (per libc) | Docker  |

> Status (verified): **all four layers are green, nothing left as scaffold.** The
> engine is unit-tested, the module compiles against nginx 1.31.4, loads
> (`nginx -t`), and passes the full live handshake — an uncleared request is
> challenged, the client solves the PoW with `pow-gate-core`, `POST /verify`
> returns a clearance cookie, and a cleared request (cookie + `X-Pow-Proof`)
> reaches the upstream. The e2e also exercises the **good-bot verifier**: a
> `verify:<name>` UA is allowed via a live IP-range feed the refresher fetched.
