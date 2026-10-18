# Performance review

Client binding adds work to every cleared request. Protocol v2 authenticates both
an opaque address/UA/policy context and the clearance payload. Cookie-only access
avoids ECDSA and shared-table locking, but has a measurable cost. Redemption adds
one signature check and a bounded shared-memory transaction after validation.

## Local comparison, 2026-10-18

Compared v0.3.0 (git 162b3f4) with the reviewed v0.4.0 implementation, using the
same native nginx 1.31.7, four workers, eight load-generator clients, loopback
HTTP/1.1 keepalive, no TLS and access logging off. Three alternating old/new runs
measured each mode for two seconds; each cell below is its median. All recorded
requests returned the expected 200 body with zero client errors. These short,
local synthetic runs include client overhead and scheduling noise; they do not
predict production capacity or TLS/upstream latency. Both modules were built
against the same nginx source and toolchain.

| Mode | v0.3 req/s | v0.4 req/s | p50 old / new | p95 old / new | p99 old / new |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 74,098 | 73,681 | 101 / 100 µs | 157 / 160 µs | 204 / 213 µs |
| cleared | 59,446 | 51,449 | 123 / 142 µs | 201 / 244 µs | 258 / 299 µs |
| proof | 6,209 | 6,838 | 1191 / 1118 µs | 2094 / 1760 µs | 2155 / 2005 µs |

The bound-cookie mode measured 13.5% lower throughput than v0.3 in this
run. It performs more authentication than the old unbound cookie. The optional
per-request P-256 proof remains the dominant CPU cost. Context hashing streams
length-prefixed fields into HMAC, avoiding an intermediate serialized User-Agent
buffer; public keys are curve-validated at issuance and proof verification,
rather than re-parsed as a curve point on every cookie-only navigation.

## Microbenchmarks

Run `cargo bench -p pow-gate-core --bench engine`. The review uses Criterion,
20 samples, one-second warmup and one-second measurement per operation. Relevant
operations are `clearance_verify`, `context_binding`,
`bound_clearance_crypto_path` (context plus clearance), and `proof_verify`.
The combined path excludes nginx configuration resolution, scope construction,
request parsing, allocation outside the core, and network costs. It should not
be treated as total request latency. Local measured timings are recorded below.

| Operation | Local estimate |
| --- | ---: |
| Clearance authentication/parsing | 3.50 µs |
| Context binding | 2.20 µs |
| Context plus clearance crypto path | 6.20 µs |
| P-256 request-proof verification | 251.5 µs |

The combined benchmark is measured separately, so it need not equal the sum of
the isolated estimates. Short Criterion runs and host load introduce variation;
comparisons against saved runs are not evidence of a code change by themselves.

## Memory and bounded work

Replay protection reserves **one 2 MiB nginx shared zone per instance**, with
32,768 fixed 40-byte entries plus issuer/clock/allocator metadata. All workers
share it. A redemption checks at most 64 slots under the shared mutex, never
removes live entries, and returns 503 if that probe window is full. Expired
entries are reused without a background collector. Cookie checks do not acquire
this mutex. The 120-second PoW validity window and redemption rate determine
occupancy; 32,768 slots are a capacity ceiling, not a guaranteed acceptance rate.
Monitor 503s and retain headroom for uneven hash distribution and bursts.

The DNS fallback uses at most two resolver threads per worker, each with a
512 KiB configured stack, a 64-job queue shared by that worker's verifiers, and
2,048 cached verdicts per verifier/worker. These resources are lazy and bounded;
cache maintenance is throttled to once per second. Verification JSON is limited
to 8 KiB while streaming, including chunked HTTP/1.1 and unknown-length HTTP/2.
See [security.md](security.md) for failure semantics and remaining limitations.

One post-test process snapshot (master plus four workers, small local fixtures)
measured total proportional-set memory of 5,168 KiB for v0.3, 6,671 KiB for v0.4
mainline, and 6,803 KiB for v0.4 stable. PSS accounts for shared pages
proportionally; multiplying each process's RSS would double-count shared state.
These snapshots are not total-memory ceilings: nginx connection/body buffers,
range-feed downloads, allocator behavior, configured verifiers, and active DNS
work add memory. The optional [regular-traffic limits
include](../examples/regular-traffic-limits.conf) allocates another 5.125 MiB of
shared zones when installed.

## Reproducing the measurements

```bash
cargo bench -p pow-gate-core --bench engine
PERF_DURATION=10 PERF_CONCURRENCY=8 PERF_MODES=baseline,cleared,proof ./scripts/perf.sh
# Against an existing isolated fixture:
BASE_URL=http://127.0.0.1:18080 PERF_DURATION=10 cargo run --release --manifest-path perf/Cargo.toml
```

The standalone load generator performs the real handshake, validates response
status and an expected body marker in a bounded preview, drains the full response
body, and measures completed requests. Counting only headers or treating a
challenge/error response as a successful upstream response gives misleading
throughput, so the baseline comparison uses this corrected harness on both wire
protocols. Modes are `baseline` (excluded), `challenge` (uncleared), `cleared`
(bound cookie), and `proof` (cookie plus request signature).

Benchmark the actual application before selecting aggregate limits. Rate limits
and shorter clearances constrain continued scraping; increasing PoW difficulty
only raises the initial client solve cost. Proof checks consume server CPU and
need their own admission budget. Run longer production-like tests with TLS and
representative request sizes to select worker counts and headroom.
