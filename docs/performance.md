# Performance review

The v0.5.0 pass removes repeated configuration/key work from cleared requests,
uses native HMAC and P-256 routines, indexes crawler ranges, and shares the
content-fingerprinted solver between its page and workers. Protocol v2, client
binding, assurance/expiry checks, and consume-once/fencing rules are preserved.
[Raw measurements](performance-results.json) include the host, individual runs
and artifact hashes. All performance measurements were taken on Linux/amd64.
They are local comparisons, not production limits. ARM64 runs cover correctness only.

## Allocation follow-up, 2026-10-18

This Linux/amd64 follow-up compares the previous performance pass with the
allocation changes. Both modules were rebuilt in the same staging directory,
using the same compiler/profile and nginx 1.31.7 headers. The previous client
binary is shared by both. [Raw follow-up results](performance-allocation-results.json)
retain all samples, hashes, source hashes, CPU placement and correctness results.

Normal unescaped clearance validation drops from **six heap allocations to one**.
Tags, public keys and request signatures decode into fixed-width buffers; proof
verification reuses the key decoded by clearance validation. JSON strings borrow
from a 512-byte normal-token buffer; larger authenticated payloads retain a
bounded fallback under the existing 4 KiB token limit. Escaped strings remain
compatible. The owned public API remains available. Authentication, context,
assurance, lifetime and proof checks still run for every request.

Literal policy values borrow configuration bytes, and trusted-variable checks
compare bytes directly. Immutable configuration-pool pages and the embedded
solver use fresh per-request read-only nginx buffer metadata, eliminating their
body-sized request-pool allocation and copy. Generated JSON, no-JS grants and
replay-injected pages retain their required request-owned storage.

### Original four-worker layout

Three alternating five-second runs per mode, eight clients, four nginx workers,
loopback HTTP/1.1 keepalive, no TLS/access log, and a 30-second proof warmup.
Values are medians. The host also runs desktop workloads; small changes should
be interpreted against the baseline control. All responses passed validation.

| Mode | Previous req/s | Follow-up req/s | Change | Worker CPU µs/request previous / follow-up |
| --- | ---: | ---: | ---: | ---: |
| baseline | 64,641 | 65,260 | +1.0% | 41.3 / 41.2 |
| challenge | 56,866 | 59,351 | +4.4% | 35.4 / 32.8 |
| cleared | 51,711 | 52,613 | +1.7% | 59.0 / 58.2 |
| proof | 10,530 | 10,965 | +4.1% | 196.1 / 191.7 |

### Separate physical cores and concurrency sweep

The second layout uses one nginx worker on CPU 0. The client uses CPUs 1–5 and
7–11, on separate physical cores; CPU 6 is CPU 0's SMT sibling and is excluded
from both sets. Three alternating three-second runs compare 1, 4 and 16 clients
following a 30-second proof warmup. These values apply to this one-worker layout.
The tool rejects overlapping physical-core placement and records actual worker
affinities. CPU use is CPU seconds divided by timed elapsed seconds, in logical
CPU equivalents; client CPU includes handshake and statistics work.

| Clients | Mode | Previous req/s | Follow-up req/s | Worker CPU µs/request previous / follow-up | Follow-up server CPU use | Follow-up client CPU use |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | cleared | 15,630 | 14,517 | 33.7 / 35.4 | 0.52 | 0.38 |
| 1 | proof | 2,568 | 2,558 | 107.7 / 105.5 | 0.28 | 0.60 |
| 4 | cleared | 25,904 | 25,345 | 31.5 / 32.3 | 0.82 | 0.99 |
| 4 | proof | 6,915 | 7,062 | 122.9 / 119.4 | 0.84 | 2.41 |
| 16 | cleared | 26,008 | 25,564 | 31.4 / 32.0 | 0.82 | 1.05 |
| 16 | proof | 7,909 | 7,509 | 116.2 / 121.9 | 0.92 | 2.74 |

The isolated core clearance benchmark measures 1.842 µs before and
1.797 µs after at the medians of three alternating pairs. Both use the
same prepared native HMAC backend; the reference retains the previous owned
JSON/base64 decoding. CPU frequency/cache effects still affect these timings.

The shared layout shows modest median gains and about 7.4% lower challenge CPU.
The isolated sweep does not establish a general cleared-cookie/proof throughput
improvement: results vary with concurrency and the baseline control also varies.
Treat those small throughput changes as provisional. The allocation count and
elimination of the immutable-body allocation/copy are directly established.

### Validation and reproduction

This follow-up passes **78 portable / 79 native-crypto tests**, including an
independent pre-optimization verifier, signed malformed/escaped JSON, duplicate
fields, expiry/assurance/key boundaries, exact 4 KiB tokens, tampering and allocation
counts. Native HTTP/1.1, HTTP/2, real HTTP/3, failed reload, feed, browser and Redis
suites pass on nginx 1.31.7 and 1.30.6. Redis checks include previous/current module
compatibility. The read-only body regression covers gzip, HEAD, repeated reads
and a slow reader of a 736 KiB rendered custom page. All four amd64 glibc/musl
Docker end-to-end cells and both failed-reload Docker targets pass. These are
Linux/amd64 follow-up checks; earlier ARM64 results below belong to the first pass.

```bash
python3 scripts/compare-performance.py \
  --nginx /path/to/matching/nginx \
  --before /path/to/previous.so --after /path/to/follow-up.so \
  --client target/release/pow-gate-perf --workers 1 \
  --server-cpus 0 --client-cpus 1-5,7-11 \
  --concurrency-list 1 4 16 --seconds 3 --rounds 3 --warmup-seconds 30 \
  --output /tmp/pow-allocation-sweep.json

POW_BENCH_CPU=1 cargo bench --locked -p pow-gate-core --features native-crypto \
  --bench engine -- 'clearance_verify_(reference|borrowed)' \
  --sample-size 30 --warm-up-time 1 --measurement-time 2
```

Choose CPU lists using your own topology (`lscpu -e=CPU,CORE,SOCKET`); these
particular IDs describe the measured host. For the original layout, use
`--workers 4 --concurrency 8 --seconds 5` and omit the CPU-placement and
`--concurrency-list` options. All performance measurements require Linux/amd64.

## HTTP comparison, 2026-10-18

Three alternating before/after runs on Linux/amd64 measure each mode for five
seconds, with the local build matrix held between stages. The
retained before module is the v0.5.0 working tree before this performance pass;
the after module includes all changes below. Both use the same native nginx
1.31.7, four workers, eight clients, loopback HTTP/1.1 keepalive, no TLS and no
access log. Each cell is its median. All recorded responses passed validation
with zero errors. The JSON includes exact request counts and binary hashes.
The host also runs desktop/background workloads; paired controls help expose
that variation, and these results should not be read as production capacity.

| Mode | Before req/s | After req/s | p50 µs before / after | p95 µs before / after | Worker CPU µs/request before / after |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 58,952 | 56,368 | 124 / 129 | 182 / 195 | 43.9 / 44.2 |
| challenge | 53,184 | 52,356 | 138 / 139 | 201 / 207 | 37.6 / 37.2 |
| cleared | 44,922 | 46,775 | 162 / 149 | 251 / 238 | 68.7 / 63.4 |
| proof | 6,518 | 10,922 | 1189 / 728 | 1686 / 881 | 524.9 / 192.0 |

A 45-second signed-proof warmup precedes these samples to reduce initial
clock/thermal settling effects. The initial unwarmed run is retained in the raw
JSON as well; it showed large early variation on challenge and cleared traffic.

Warmed medians show about 68% higher proof throughput and 63% less worker
CPU per proof request. Cleared-cookie worker CPU falls about 8%; its 4% median
throughput gain is close to the baseline variation. Challenge CPU is essentially
unchanged, with no repeatable challenge-page CPU regression.

The baseline path is excluded from the gate. `cleared` validates a bound cookie;
`proof` also checks a fresh request signature. The generator signs each proof
in the client, validates response status and body, and drains the complete body.
Its CPU, network and scheduling overhead limit throughput too; a faster verifier
does not imply the same multiplier in end-to-end requests per second.

Worker CPU sums user/system ticks for the four nginx workers. It excludes client
signing and descheduled time, but includes the fixed handshake cost. Tick
resolution and short runs add uncertainty. Baseline validation requires exactly
`ok` or `ok\n`; a challenge/error page cannot count as an excluded response.

## Changes in the request path

* Resolved configuration, policy-scope fields and initialized HMAC key schedules
  are retained per location/worker in a cycle-owned cache. Keys still load after
  fork under worker permissions. Cache cleanup follows nginx cycle lifetimes.
  Cleared requests no longer lock the key cache or clone configuration strings.
* Cookie/header/method/path reads borrow nginx memory where possible. Existing
  lossy UTF-8 header handling is preserved. Oversized tokens are rejected before
  computing client context. Disabled requests do not allocate outcome state.
* The module enables `native-crypto` for ring's HMAC-SHA-256 and fixed-width
  P-256/SHA-256 verification. The standalone core keeps its pure Rust default.
  Every request still authenticates the token and current address/UA/policy/store
  binding; successful verification results are not cached.
* Crawler CIDRs compile into sorted, merged intervals. Membership is O(log n),
  with feed validation, source isolation and stale-snapshot rejection unchanged.

## CPU measurements

Criterion uses 20 samples, a one-second wall-clock warmup and a one-second
wall-clock target for sample calibration; samples measure thread CPU time. These
CPU samples were collected while local matrix builds were running, using Linux
`CLOCK_THREAD_CPUTIME_ID` to exclude scheduler wait. Frequency, shared CPU/cache
resources and thermal limits still affect CPU time; do not compare their absolute
values with earlier idle-host measurements. Values below are medians of three
runs. The prepared HMAC backend comparison alternates the two binaries.

| Operation | Reference | Optimized | Approximate ratio |
| --- | ---: | ---: | ---: |
| P-256 verification, RustCrypto / ring | 448 µs | 108 µs | 4.2× |
| Context + clearance, prepared portable / native HMAC | 12.9 µs | 8.7 µs | 1.5× |
| Missing address in 10,000 ranges, linear / indexed | 12.7 µs | 40.7 ns | 310× |

These crypto operations exclude nginx configuration resolution, request parsing,
response generation and network costs. Portable/native compatibility tests cover
independent HMAC framing, existing signed tokens, JSON scope serialization,
mutated signatures, malformed keys/signatures, high-S/low-S encodings and both
SEC1 key forms. Module admission still requires canonical uncompressed keys.

## Browser transfer and nginx filters

The solver URL contains the package version plus a SHA-256 content fingerprint.
Only that exact query has `public, max-age=31536000, immutable`. Unversioned,
obsolete or modified queries return the current code with `no-store`.
Challenge, verification/status/pass and error responses remain `no-store`.
The public cached script contains no client state.

With eight workers and difficulty 2,000, Chromium and Firefox each made nine
origin script requests before the change and one afterward. Script bodies fell
from 267,858 to 29,762 bytes without gzip. With the optional public-solver gzip
location, both browsers transferred about 11.8 KB, a 95.6% reduction from the
original nine downloads. Counts cover origin response bodies, not TCP/TLS headers.

Generated responses now populate nginx's native MIME and charset metadata.
Previously they only added a raw Content-Type header, which prevented configured
gzip from recognizing the script. The gzip regression verifies one Content-Type,
byte-exact decompression, `gzip;q=0`, charset, Vary and HEAD. Compression remains
controlled by nginx; [solver-gzip.conf](../examples/solver-gzip.conf) enables it
for the public script. Retain the full version query in cache keys and honor
`Vary: Accept-Encoding`.

## Builds and bounds

`.nginx`, node_modules and Python caches are excluded from Docker contexts. One
cold-context comparison transferred 433 MB before and about 0.6 MB afterward.
Module Cargo caches are separated by architecture/libc; the standalone test
client has an architecture-specific cache. Exported binaries are copied outside
the cache mounts. Touching source crate roots prevents old copied timestamps
from hiding code changes. Configured nginx sources are cached before source COPY.
See Docker's [cache guidance](https://docs.docker.com/build/cache/optimize/).

The default local backend still reserves one 2 MiB shared zone per nginx
instance, with 32,768 fixed 40-byte entries and at most 64 probes under its
shared mutex. Cookie checks do not lock this zone. Slots are a capacity ceiling,
not a guaranteed acceptance rate; probe-window saturation returns 503 without
evicting live entries. Redis mode omits the local zone and uses the bounded
native-event transport described in [redis.md](redis.md).

DNS fallback retains at most two resolver threads per worker with 512 KiB stacks,
a shared 64-job queue and 2,048 cached verdicts per verifier/worker. Resources are
lazy; cache maintenance is throttled to once per second. The streaming 8 KiB
verification-body limit, feed bounds and fail-closed behavior are unchanged.

A separate Linux/amd64 memory snapshot after handshake and one second of signed
requests measured 6,318 KiB before and 6,804 KiB after for the master plus four
workers: about 486 KiB additional proportional-set size (PSS). This includes
resident code and data, so it does not isolate cache allocations. PSS accounts
for shared pages proportionally; summing RSS would double-count them. These
small-fixture snapshots are not memory ceilings: nginx buffers, feed downloads,
active DNS work and allocator behavior add memory. The optional
[regular-traffic limits include](../examples/regular-traffic-limits.conf) reserves
an additional 5.125 MiB of shared zones when installed.

## Reproducing

```bash
cargo test --locked -p pow-gate-core
cargo test --locked -p pow-gate-core --features native-crypto
cargo bench --locked -p pow-gate-core --features native-crypto --bench engine
# Linux thread CPU instead of wall time:
POW_BENCH_CPU=1 cargo bench --locked -p pow-gate-core --features native-crypto --bench engine -- --sample-size 20 --warm-up-time 1 --measurement-time 1

CARGO_TARGET_DIR=target cargo build --release --locked --manifest-path perf/Cargo.toml
python3 scripts/compare-performance.py \
  --nginx /path/to/matching/nginx \
  --before /path/to/retained-before.so --after /path/to/optimized.so \
  --client target/release/pow-gate-perf --seconds 5 --rounds 3 --warmup-seconds 45 \
  --output /tmp/pow-performance.json
```

Performance tests run only on Linux/amd64. The HTTP comparison rejects other
platforms. Retain an ABI-compatible before module built against the same
nginx/toolchain.
The comparison starts isolated servers, alternates module order, checks every
response, reports exact completed-request counts and stops on validation errors.
Run it on a quiet host. ARM64 Docker validation under QEMU checks correctness;
its speed is not a native ARM capacity result. Select production worker counts,
rate limits and headroom using representative TLS, upstream and Redis latency.

## Correctness validation

Portable and native-crypto core suites passed 73 and 74 tests. Native checks on
nginx 1.31.7 and 1.30.6 passed HTTP/1.1, HTTP/2, real TLS/QUIC HTTP/3, failed
reload, feed, gzip, Redis cross-node/failure/compatibility, and Chromium/Firefox
recovery suites. These checks cover both local and Redis replay backends.

| Docker platform | End-to-end cells passed | Failed-reload cells passed |
| --- | ---: | ---: |
| Linux/amd64 | 4/4 | 2/2 |
| Linux/arm64 under QEMU | 4/4 | 2/2 |

The eight end-to-end cells span both nginx channels and glibc/musl. ARM64
results are correctness checks only; no ARM64 performance tests were run.
