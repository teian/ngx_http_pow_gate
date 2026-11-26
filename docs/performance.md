# Performance review

The v0.5.0 pass removes repeated configuration/key work from cleared requests,
uses native HMAC and P-256 routines, indexes crawler ranges, and shares the
content-fingerprinted solver between its page and workers. Protocol v2, client
binding, assurance/expiry checks, and consume-once/fencing rules are preserved.
[Raw measurements](performance-results.json) include the host, individual runs
and artifact hashes. All performance measurements were taken on Linux/amd64.
They are local comparisons, not production limits. ARM64 runs cover correctness only.

The most recent run compares v0.6.2 with v0.7.0 and finds no measurable change
in the module. The sections after it are earlier passes, measured on a different
host.

## v0.7.0 comparison, 2026-11-26

This Linux/amd64 run compares the released v0.6.2 module with v0.7.0. It checks
two things that changed on the request path: the outcome counter that now runs
in the LOG phase for every gated request, and the dependency upgrades (`ureq` 3,
`p256` 0.14, `sha2` 0.11, `hmac` 0.13). Both modules were built in release
profile with Rust 1.100 against the same native nginx 1.31.10, and the v0.7.0
load generator drives both. [Raw results](performance-0.7.0-results.json)
retain every run, the binary hashes, CPU placement and the host's load.

The host is an AMD Ryzen 7 5800X desktop, not the machine used for the sections
below, so absolute numbers are not comparable across sections. Other workloads
were running: the one-minute load average was between 3 and 8 during the HTTP
runs. Read the tables as before/after comparisons on one host. All responses
passed validation with zero errors.

**Result: no measurable change in the module.** Every gated mode stays within
1% of v0.6.2 in the four-worker layout, and the ungated baseline control moves
by the same amount.

The v0.7.0 column in the three tables below is the build before the
[request-path tuning](#request-path-tuning) that the release also contains;
that tuning is measured separately, against this build.

### Four-worker layout

Three alternating five-second runs per mode, eight clients, four nginx workers,
loopback HTTP/1.1 keepalive, no TLS/access log, and a 30-second proof warmup.
Values are medians.

| Mode | v0.6.2 req/s | v0.7.0 req/s | Change | p50 µs v0.6.2 / v0.7.0 | p95 µs v0.6.2 / v0.7.0 | Worker CPU µs/request v0.6.2 / v0.7.0 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 140,997 | 139,854 | −0.8% | 48 / 49 | 73 / 73 | 18.0 / 18.2 |
| challenge | 135,539 | 134,555 | −0.7% | 50 / 50 | 73 / 74 | 14.2 / 14.3 |
| cleared | 114,733 | 115,084 | +0.3% | 57 / 58 | 91 / 90 | 24.6 / 24.6 |
| proof | 33,465 | 33,378 | −0.3% | 207 / 208 | 308 / 310 | 81.9 / 81.4 |

The baseline path is excluded from the gate and is not counted, so it is the
control for host variation. Counting an outcome is one lookup in a worker-local
index and one atomic increment; the shared-memory mutex is taken only the first
time a worker sees a new `(result, reason)` pair.

### Separate physical cores and concurrency sweep

One nginx worker on CPU 0; the client on CPUs 1–7 and 9–15, with CPU 8 (CPU 0's
SMT sibling) excluded from both. Three alternating three-second runs at 1, 4 and
16 clients after a 30-second proof warmup.

| Clients | Mode | v0.6.2 req/s | v0.7.0 req/s | Change | Worker CPU µs/request v0.6.2 / v0.7.0 |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | baseline | 27,124 | 27,341 | +0.8% | 16.1 / 15.8 |
| 1 | challenge | 25,365 | 25,308 | −0.2% | 12.7 / 12.9 |
| 1 | cleared | 21,805 | 22,840 | +4.7% | 22.6 / 21.9 |
| 1 | proof | 5,169 | 5,351 | +3.5% | 79.3 / 78.5 |
| 4 | baseline | 71,821 | 69,477 | −3.3% | 10.7 / 11.0 |
| 4 | challenge | 83,680 | 86,068 | +2.9% | 8.4 / 8.2 |
| 4 | cleared | 51,537 | 49,326 | −4.3% | 15.8 / 16.5 |
| 4 | proof | 15,872 | 15,783 | −0.6% | 58.6 / 58.9 |
| 16 | baseline | 73,717 | 74,892 | +1.6% | 10.3 / 10.1 |
| 16 | challenge | 91,957 | 91,843 | −0.1% | 7.6 / 7.6 |
| 16 | cleared | 52,258 | 52,338 | +0.2% | 15.6 / 15.5 |
| 16 | proof | 16,057 | 15,901 | −1.0% | 57.9 / 58.4 |

The differences run in both directions and the baseline control moves by up to
3.3%, so this sweep does not establish a change in either direction.

### Engine CPU

Criterion thread-CPU time, 20 samples, medians of three alternating runs per
tree, `native-crypto` enabled.

| Operation | v0.6.2 | v0.7.0 | Change |
| --- | ---: | ---: | ---: |
| PoW hash | 55.7 ns | 56.8 ns | +1.9% |
| PoW solution verification | 502 ns | 505 ns | +0.5% |
| Clearance issue | 686 ns | 693 ns | +1.0% |
| Clearance verification | 790 ns | 794 ns | +0.5% |
| Context binding | 401 ns | 407 ns | +1.3% |
| Context + clearance, prepared key | 1.197 µs | 1.218 µs | +1.8% |
| P-256 proof verification, ring (used by the module) | 39.6 µs | 39.7 µs | +0.4% |
| P-256 proof verification, RustCrypto (portable core) | 182.0 µs | 203.2 µs | +11.7% |
| Range lookup, 10,000 ranges, miss | 12.3 ns | 12.3 ns | −0.2% |

One real difference: **portable P-256 verification is about 12% slower with
`p256` 0.14**, consistently across all three runs. The nginx module does not
use that path; it verifies with ring through the `native-crypto` feature, which
is unchanged. It affects only code that uses `pow-gate-core` without that
feature. The remaining rows differ by 2% or less, which is within the spread
between runs on this host.

### Request-path tuning

A sampling profile of one worker serving cleared requests (`perf record -e
cpu-clock:u`, user-space samples only) put 33% of the worker's user-space CPU
in the module. The two HMAC-SHA-256 computations were the largest part, as
expected. The rest pointed at glue rather than cryptography:

| Finding | Change |
| --- | --- |
| Header values were converted with `String::from_utf8_lossy`, which walks every byte through the slow chunk iterator | Valid UTF-8 takes the fast validation path and borrows; only invalid input is converted lossily |
| `User-Agent` and `Cookie` were found by scanning all request headers | Read through nginx's own `headers_in` pointers |
| serde's derived reader for the tagged `assurance` object buffered it on the heap first | A hand-written reader with the same wire format; any key order and unknown keys are still accepted |
| The client address was formatted through `Display` and the binding returned as a `String` | IPv4 is written directly into a stack buffer; the binding is held inline |
| A variable-driven `pow_gate_decision` was copied into a new `String` | Borrowed from the request pool |
| All workers incremented the same outcome counter | One row of counters per worker, summed by `pow_gate_status` |

Clearance validation still reads the system clock rather than nginx's cached
time. The clock read was 0.15% of the profile, and a cached second that trails
the clock could make a clearance just issued by another worker look issued in
the future.

After the changes the module's share of user-space CPU on cleared requests is
25%. Measured against the build before the tuning, with zero errors in every
run:

| Measurement | Before | After | Change |
| --- | ---: | ---: | ---: |
| Cleared, one pinned worker, 16 clients | 52,884 req/s | 54,605 req/s | +3.3% |
| Cleared, worker CPU per request | 15.38 µs | 14.82 µs | −3.6% |
| Cleared, four workers, 8 clients | 129,968 req/s | 132,386 req/s | +1.9% |
| Proof, one pinned worker, 16 clients | 15,910 req/s | 16,087 req/s | +1.1% |
| Baseline control, one pinned worker, 16 clients | 74,457 req/s | 74,456 req/s | 0.0% |
| Context binding (engine) | 407 ns | 353 ns | −13% |
| Context + clearance, prepared key (engine) | 1.218 µs | 1.117 µs | −8% |
| Clearance verification (engine) | 794 ns | 770 ns | −3% |

The gain on cleared requests is about 0.56 µs of worker CPU, roughly a tenth of
what the gate adds to an ungated request (5.1 µs before, 4.6 µs after). Challenge pages
and the ungated control are unchanged. Signed-proof requests gain the same
absolute amount, which is small next to the 39.7 µs signature verification.
The per-worker counters cannot show a difference in a four-worker run; they
matter on hosts with many more workers. The four-worker figures are higher
than in the table above because the host was less busy during this run.

### State file

`pow_gate_state_file` keeps the store identity (65 bytes) on disk. nginx reads
it once when the master creates the shared-memory zone and never while serving
requests, so no request-path cost is expected. This run checks that: the same
module, one pinned worker, without the directive and with it pointing at an
existing file, which is the restored case where challenges from before the
restart are refused.

| Mode | Without | With state file | Paired difference |
| --- | ---: | ---: | ---: |
| Cleared, 16 clients, 8 rounds | 49,942 req/s | 50,099 req/s | 0.0% (−3.3% to +3.4%) |
| Challenge page, 16 clients, 8 rounds | 84,004 req/s | 83,334 req/s | −0.5% (−4.4% to +6.8%) |
| Proof, 16 clients, 5 rounds | 14,424 req/s | 14,417 req/s | −0.6% (−2.3% to +2.1%) |
| Baseline control, 16 clients, 5 rounds | 67,339 req/s | 67,608 req/s | +0.2% (−1.4% to +1.1%) |
| Full solve, 2 clients, 7 rounds | 2,745 /s | 2,719 /s | −1.3% (−6.2% to +6.8%) |
| Configuration start-up (`nginx -t`), median of 200 | 2.97 ms | 2.94 ms | none |

**Result: no measurable impact.** The differences are smaller than the spread
between rounds and have no consistent sign; the ungated control moves as much.
Columns two and three are medians; the last column is the mean and range of the
per-round differences. Creating the file on first start measured 0.05 ms more
than a start without it, on tmpfs; on a disk the single `fsync` at creation
adds its usual few milliseconds, once.

"Full solve" is the load generator's `solve` mode: one challenge, nonce search
and redemption per iteration, the only path that consults the pre-restart
floor. Its rate is limited by the client's solving work, and it is kept low on
purpose: the local store holds 32,768 redeemed challenges until they expire, so
a sustained rate above that capacity per challenge lifetime is refused with
503 by design.

```bash
python3 scripts/compare-performance.py \
  --nginx /path/to/nginx-1.31.10/objs/nginx \
  --before module.so --after module.so \
  --after-directive "pow_gate_state_file /path/to/existing-state-file;" \
  --settle-seconds 1.2 --workers 1 --server-cpus 0 --client-cpus 1-7,9-15 \
  --client target/release/pow-gate-perf --concurrency 16 --seconds 5 --rounds 8 \
  --modes challenge cleared --output /tmp/pow-state.json
```

### Reproduction

```bash
# one native nginx, two modules built against it with the same toolchain
python3 scripts/compare-performance.py \
  --nginx /path/to/nginx-1.31.10/objs/nginx \
  --before /path/to/v0.6.2.so --after /path/to/v0.7.0.so \
  --client target/release/pow-gate-perf --workers 4 --concurrency 8 \
  --seconds 5 --rounds 3 --warmup-seconds 30 --output /tmp/pow-shared.json

python3 scripts/compare-performance.py \
  --nginx /path/to/nginx-1.31.10/objs/nginx \
  --before /path/to/v0.6.2.so --after /path/to/v0.7.0.so \
  --client target/release/pow-gate-perf --workers 1 \
  --server-cpus 0 --client-cpus 1-7,9-15 \
  --concurrency-list 1 4 16 --seconds 3 --rounds 3 --warmup-seconds 30 \
  --output /tmp/pow-sweep.json
```

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
