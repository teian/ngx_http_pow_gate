# Performance & bottlenecks

The PoW gate runs on **every** request to a gated location, so its per-request
cost matters. This suite measures that cost two ways and pinpoints the bottleneck:

1. **Microbenchmarks** of the engine crypto (Criterion) — isolate the cost of
   each operation the module performs per request.
2. **HTTP load test** against a live nginx — the real end-to-end impact, comparing
   gated request classes to an ungated baseline.

- [TL;DR — the bottleneck](#tldr--the-bottleneck)
- [Microbenchmarks](#microbenchmarks)
- [HTTP load test](#http-load-test)
- [Reading the results](#reading-the-results)
- [Recommendations](#recommendations)
- [Running it](#running-it)

---

## TL;DR — the bottleneck

- **Cookie-only gating is nearly free.** A cleared request (clearance cookie, no
  proof) costs an HMAC-SHA256 verify (~2 µs) on top of nginx — within noise of the
  ungated baseline.
- **The per-request ECDSA proof is the bottleneck.** Verifying the optional
  `X-Pow-Proof` is a P-256 signature check (~250 µs) — **~100× the HMAC**. When
  present on every request it caps throughput to roughly *cores × 4000 req/s*.
- **The challenge page serve** is a one-time-per-client cost (only uncleared
  clients pay it).

So: the steady state for ordinary page loads (top-level navigations, cookie only)
is cheap. The cost concentrates in the per-request proof, which is *opt-in*
hardening for `fetch`/XHR — see [Recommendations](#recommendations).

---

## Microbenchmarks

`cargo bench -p pow-gate-core` (Criterion). Representative figures from one dev
machine — **the ratios matter, not the absolute numbers**:

| Operation                | Cost     | When it runs                                  |
| ------------------------ | -------- | --------------------------------------------- |
| `difficulty_to_target`   | ~0.37 µs | per `/challenge` and per `/verify`            |
| `pow_hash` (1× SHA-256)  | ~0.32 µs | server: ~1 per `/verify`; client: ~difficulty |
| `pow_verify_solution`    | ~2.0 µs  | per `/verify`                                 |
| `clearance_issue` (HMAC) | ~2.2 µs  | per `/verify` (mint cookie)                   |
| `clearance_verify` (HMAC)| ~2.3 µs  | **per gated request** (cookie check)          |
| **`proof_verify` (ECDSA)** | **~255 µs** | **per gated request that sends a proof**  |

The lone outlier is `proof_verify`. Everything else is single-digit microseconds.

---

## HTTP load test

`./scripts/perf.sh` (or `docker compose -f docker-compose.perf.yml up`). It mints
one clearance via the real handshake, then hammers four request classes:

| Mode        | Request                                   | Measures                          |
| ----------- | ----------------------------------------- | --------------------------------- |
| `baseline`  | `GET` excluded path (gate off)            | bare nginx ceiling                |
| `challenge` | `GET /` with no cookie                    | serving the challenge page        |
| `cleared`   | `GET /` with the clearance cookie         | steady state (HMAC verify only)   |
| `proof`     | `GET /` with cookie + `X-Pow-Proof`       | adds the ECDSA proof verify       |

Representative run (8 connections, single small box — **relative, not absolute**):

| mode      | req/s  | p50    | p95    | p99    |
| --------- | ------ | ------ | ------ | ------ |
| baseline  | 24035  | 317 µs | 452 µs | 619 µs |
| cleared   | 21921  | 355 µs | 468 µs | 574 µs |
| challenge |  3669  | 2.5 ms | 3.6 ms | 4.5 ms |
| proof     |  3112  | 2.5 ms | 3.2 ms | 3.7 ms |

---

## Reading the results

- **`baseline` → `cleared`** is the cost of the gate on a normal cleared request:
  here ~9% throughput / ~38 µs p50. That is the HMAC clearance check plus reading
  the cookie and the `geo`/`map` variables — cheap. **Most real traffic is this.**
- **`cleared` → `proof`** is the cost of the per-request ECDSA proof: a ~7×
  throughput drop. This is the bottleneck, and it matches the microbench (255 µs
  ECDSA vs 2 µs HMAC). It is CPU-bound, so it scales with cores.
- **`challenge`** is paid only by uncleared clients, once, before they solve. With
  a 12 h clearance TTL ([`pow_gate_clearance_ttl`](configuration.md)), that is rare
  per visitor.

---

## Recommendations

The proof is **optional**: top-level navigations can't send custom headers, so
they're gated by the cookie alone (cheap). The proof hardens `fetch`/XHR against
cookie theft. If its cost is a problem:

1. **Lean on the cookie for navigations.** They're already cookie-only — no ECDSA.
   Most page-view traffic pays the cheap path.
2. **Sample the proof.** Verify it on a fraction of requests (e.g. 1-in-N) instead
   of every one — probabilistic theft detection at a fraction of the CPU. (A small
   `pow_gate_proof_sample` knob would express this; not yet implemented.)
3. **Give it cores.** ECDSA verify is CPU-bound and embarrassingly parallel; it
   scales linearly with `worker_processes` / cores.
4. **Consider a faster scheme.** Ed25519 verify is ~5× faster than P-256, but
   WebCrypto support is less universal — a future option, not a default.
5. **Keep difficulty sane.** Client solve time is the browser's cost, not the
   server's, but a too-high `pow_gate_difficulty` hurts the user experience on
   first visit. Tune per [configuration.md](configuration.md#tuning-pow_gate_difficulty).

The current allocation in `runtime::resolve` (owned `String`s per request) is a
minor, easily-removed cost if profiling ever shows the cookie path as hot; today
it is dwarfed by nginx's own per-request work.

---

## Running it

```bash
# microbenchmarks (no Docker) — find the per-op bottleneck
cargo bench -p pow-gate-core

# HTTP load test against a live module (needs Docker)
./scripts/perf.sh
# knobs: PERF_DURATION=10 PERF_CONCURRENCY=16 PERF_MODES=cleared,proof ./scripts/perf.sh
```

The load generator lives in [`perf/`](../perf) — a standalone project (not a
workspace member) that reuses `pow-gate-core` to mint a clearance and sign proofs,
exactly like the browser. It is **not** part of the correctness pipeline
([testing.md](testing.md)); run it when you care about throughput/latency.
