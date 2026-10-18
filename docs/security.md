# Client binding, one-use redemption and cluster coordination

## Implemented: one nginx instance, multiple workers

Protocol v2 binds challenges to the canonical P-256 public key, canonical client
address/network, exact User-Agent, issuing policy/scope and redemption-store
identity. Redemption also requires a signature by the committed key. Clearances
carry the same context and authenticated assurance (PoW difficulty or no-JS wait).
A lower assurance cannot satisfy a stronger policy. Legacy unbound tokens fail.

Address binding defaults to exact IPv4 /32 and IPv6 /128. Configure
`pow_gate_ipv4_prefix` / `pow_gate_ipv6_prefix` to deliberately allow a network;
for example IPv6 /64 tolerates privacy-address rotation within that subnet, but
also allows cookie sharing inside it. IPv4-mapped IPv6 is canonicalized to IPv4.
IP changes cause a fresh challenge. Set up trusted nginx realip processing before
the gate when using a load balancer; arbitrary forwarding headers are not trusted.

`pow_gate_policy` names an operator-controlled policy scope. The context also
includes cookie domain (or normalized request host), name/path, and endpoint.
Difficulty is checked separately as authenticated assurance. A domain cookie can
span subdomains only when their context/policy settings match. Configure matching
endpoints when a protected location overrides its difficulty or scope.

One fixed **2 MiB shared-memory zone for the entire nginx instance** contains
32,768 entries (40 bytes each, approximately 1.25 MiB) plus its issuer and nginx
allocator metadata. It is not a 2 MiB allocation per worker. Critical sections
are bounded to 64 probes, and the hot clearance path does not lock the table.
Only fully verified JS/no-JS redemptions enter it; each stores a SHA-256 token
identifier and expiry. Another valid nonce for the same challenge is still a
replay. Expired slots are reusable; live entries are never evicted. Capacity or
probe-window exhaustion returns 503 instead of growing memory or allowing reuse.
A streaming filter stops verification bodies above 8 KiB before the nginx save
filter buffers/spools them, including unknown-length HTTP/2 and chunked HTTP/1.1
bodies. An additional bounded collector protects the JSON parsing buffer.

The nginx shared mutex serializes redemptions across workers. Expiry is sampled
inside that lock using a shared clock high-water mark, so scheduling delays or
backward wall-clock adjustments cannot reopen reclaimed challenges. Graceful reloads
reuse the zone, keeping outstanding challenges, cookies and spent tokens valid.
A full restart creates a fresh random issuer and invalidates older tokens.
Independent nginx instances reject each other's tokens even if keys match;
configure sticky routing if deploying the current implementation behind a load
balancer. Upgrade the module with a full nginx process/container restart, deploying the
module and embedded solver together. Do not overwrite a live mapped `.so`; use
atomic file installation or a rebuilt container image. A rolling protocol-v1/v2
deployment requires routing isolation because
v1 nodes do not enforce these guarantees. The documented custom-page solver src
`{{endpoint}}solver.js` is automatically versioned during template rendering.
Custom pages with hardcoded solver URLs should add a version query or purge the
old script cache when upgrading.

The FCrDNS fallback also has explicit resource bounds: at most two resolver
threads per nginx worker, a shared per-worker queue of 64 jobs, 512 KiB configured
stack per resolver thread, and 2,048 cached verdicts per verifier/worker. Pending
lookups are deduplicated; full queues/caches fail closed to challenge. Cache
sweeps run at most once per second, and late results cannot recreate discarded
entries. This replaces the old thread-per-IP and unbounded-cache behavior.
Resolver threads and cache entries are allocated lazily. System-resolver delays
can still reduce DNS-verification availability, but cannot create more threads.
Configured IP-range feeds and normal nginx connection/body buffers have their
own memory costs; the 2 MiB bound refers specifically to replay state.

Verifier definitions and the replay-zone reference belong to their nginx
configuration cycle. A failed reload must not change policy or leave discarded
configuration pointers in a respawned worker. Definitions are activated after
fork from that worker's active cycle, with configuration-pool cleanup.

## Security review (2026-10-18)

The review checked token authentication/domain separation, public-key possession,
address/UA/scope/assurance binding, one-use races, expiry/reclamation, nginx reload
lifetime, request-body allocation and verifier concurrency. In addition to the
original reuse/sharing fixes, it corrected unbounded DNS threads/cache, streaming
verification-body buffering, and verifier mutation during failed reloads. The
failed-reload verifier test reproduces the policy leak on v0.3.0 and passes on
v0.4.0. A later-stage failed reload also tests replay-zone lifetime and one-use
state after worker respawn.

Native nginx 1.31.7 and 1.30.6 tests exercise four workers, 16 simultaneous
redemptions, HTTP/1.1 and multiplexed HTTP/2, JS/no-JS flows, source-address and UA
changes, policy/difficulty downgrade, independent issuer separation,
graceful reload, and exact 8 KiB body boundaries. Core tests cover table
saturation, collision bounds and late DNS replies. This is an implementation
review and regression suite, not an independent audit or proof of DoS resistance.

HTTP/3 follow-up on the same date passed on both versions over real TLS/QUIC,
using both the existing distributable modules and modules rebuilt against
HTTP/3-enabled nginx. The suite verifies `h3` negotiation, multiplexed and
cross-connection one-use races reaching all four workers, key substitution,
client-context/difficulty checks, request proofs, and no-JS reuse. It also
requires rejection of an 8,193-byte body before QUIC stream FIN while accepting
8,192 bytes. No module changes were required. See [testing.md](testing.md) for
reproduction and untested transport features.

## Operational limits

Navigation cookies remain bearer credentials inside the allowed address/network
and User-Agent context. Mandatory fetch proofs depend on client-controlled fetch
metadata. These mechanisms cannot distinguish cooperating clients that share an
allowed address, UA, cookies and keys. They add no request budget or rate limit.

## Proposed: Redis backend for multiple proxy instances

This is a design proposal, **not an available directive/backend**. Keep the
current shared-memory implementation as the default for a single nginx instance.

All instances in one trust domain would use the same HMAC key, address policy,
policy scope, protocol version and cluster issuer/epoch. Keep the shared issuer
in a Redis control key, created once with SET NX and read by every instance.
Do not reuse the process-local zone's issuer for cluster tokens. Independent
sites/policies use separate namespaces. A controlled epoch change invalidates
outstanding tokens when necessary.

After checking the token, binding, key-possession signature, expiry and PoW, send
a single command to the authoritative Redis primary:

```text
SET powgate:<namespace>:<epoch>:spent:<sha256-authenticated-token> 1 NX EX <ttl>
```

`ttl` should cover the entire remaining validity window plus allowed inter-node
clock skew (for example `exp - local_now + skew_budget`); synchronize clocks.
Use the token ID, not the solution nonce. Only an `OK` reply permits minting the
clearance; an existing key returns 409. A timeout, OOM, unavailable store or
ambiguous reply returns 503. Retrying after an ambiguous reply may require a
fresh challenge; never delete the marker to retry or fall back to local memory.
The no-JS endpoint must use the same backend.

SET combines conditional creation and TTL atomically. Do not implement separate
GET/check/SET operations. [Redis SET documentation](https://redis.io/docs/latest/commands/set/)

Use asynchronous nginx socket integration, bounded per-worker connection pools,
short timeouts and a capped queue. Keep Redis off the ordinary clearance-validation
path: validating a bound HMAC cookie should require no per-request Redis lookup.
Issuer/epoch publication and changes must be coordinated and fenced across nodes;
a node with a stale epoch must stop serving cluster verification. The shared
issuer is stable during ordinary reloads/restarts.

### Memory budget

Use a dedicated Redis instance with an explicit maxmemory and
`maxmemory-policy noeviction`. Never evict live spent markers to make room: that
would re-enable replay. OOM must fail verification closed. Reserve additional
process/container memory for replication and persistence buffers; maxmemory is
not a total RSS ceiling. [Redis eviction documentation](https://redis.io/docs/latest/develop/reference/eviction/)

Size using measured per-key overhead: `peak successful redemptions/second *
(validity + skew budget) * measured bytes/key`, plus headroom and the control key.
As an illustration, 100 redemptions/second * 125 seconds * 200 bytes is about
2.5 MB of marker data. Measure with MEMORY USAGE before selecting a budget;
16 MiB could be a starting data budget for that example, not a universal limit.

### Failover and durability

Redis replication is asynchronous. An acknowledged write can be absent after
failover; WAIT reduces risk but does not turn Redis into a strongly consistent
store. [Redis replication documentation](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/)

For strict replay protection, either use storage with the required durable,
linearizable guarantees, or fence verification during failover/recovery, retire
the old primary, generate a new epoch, and resume only when every serving proxy
uses that epoch. Invalidate pre-failover tokens if spent-state continuity cannot
be guaranteed. Persistence or replication alone is not a strict exactly-once
contract. Never silently recreate a missing issuer under an old epoch.
