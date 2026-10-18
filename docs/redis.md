# Redis coordination for multiple gateways

`pow_gate_redis` selects a shared Redis primary for one-use JS/no-JS redemption.
The default, with this block absent, remains the fixed 2 MiB nginx shared-memory
ledger. Redis mode allocates no local replay ledger and never falls back to one.
This coordinates multiple proxy instances; it is not a Redis Cluster/Sentinel
client and does not follow MOVED/ASK redirects or discover/promote replicas.

## Configure

Use a dedicated authoritative primary with an explicit memory budget and
`maxmemory-policy noeviction`. For an isolated test instance:

```sh
docker run --name pow-redis -d -p 127.0.0.1:6379:6379 redis:8-alpine \
  redis-server --maxmemory 16mb --maxmemory-policy noeviction
```

Provision the epoch **once**, explicitly, before starting the proxies:

```sh
python3 scripts/redis-epoch.py --address 127.0.0.1:6379 \
  --namespace mysite --output /etc/pow/cluster.epoch
```

The helper checks the memory policy, initializes epoch/clock control keys in a
single script, and atomically writes a mode-0600 file. Re-running it against an
intact namespace exports the existing epoch. Copy that same file to every proxy.
Use a deployment-owned output directory and set its ownership/read permissions
so the nginx master can read it. The epoch is an identity, not the HMAC secret.

Inside `http {}`:

```nginx
pow_gate_redis {
    address 127.0.0.1:6379;
    namespace mysite;
    epoch_file /etc/pow/cluster.epoch;
    timeout 500;       # milliseconds, INCLUDING time in the queue
    connections 4;    # active redemption sockets per nginx worker
    queue 64;         # additional queued redemptions per worker
    clock_skew 5;     # maximum difference from Redis TIME, in seconds
    # username powgate;
    # password_file /etc/pow/redis.password;
}
```

The block is `http`-only, may appear once, and applies to the entire nginx
instance. Required fields are `address`, `namespace`, and `epoch_file`. Defaults
for the other fields are shown above. `timeout` accepts 10..5000 milliseconds,
`connections` 1..32, `queue` 0..1024, and `clock_skew` 1..60 seconds. These numbers
are bare integers. Namespace accepts 1..64 ASCII letters/digits/underscores/
hyphens. Address must be a numeric IPv4/IPv6 address and port (IPv6 in brackets).
The epoch file must contain 64 hexadecimal characters, with optional surrounding
whitespace. Invalid or duplicate settings fail `nginx -t`.

Every proxy must also have matching HMAC keys, protocol version, client-address
prefixes, User-Agent handling, cookie settings, endpoint and policy. Keep client
address resolution consistent behind trusted load balancers. After setup,
challenges and cookies can cross proxy instances without sticky routing. Initial
worker health checks are asynchronous; a worker refuses new challenges until its
first successful check, normally within a second. Switching between local and
Redis backends invalidates existing tokens and requires a fresh solve.

The transport is plain TCP with optional Redis AUTH/ACL. Put remote connections
behind a trusted private network or a local TLS tunnel. This implementation does
not provide Redis TLS, Unix sockets, logical database selection, or topology
management. Passwords are read at configuration time, capped at 512 bytes, and
never included in logs. One trailing LF is stripped. A username requires a
password file. Use an ACL restricted to the namespace keys and `AUTH`, `EVAL`,
`GET`, `SET`, and `TIME`; the provisioning helper separately needs `CONFIG GET`.

## Atomicity and resource bounds

After token/context/assurance, key-possession signature and PoW validation, the
module sends one bounded `EVAL` operation. It atomically checks the configured
epoch, checks Redis/client clock skew, applies a shared nondecreasing clock, and
executes `SET spent-key 1 NX EX ttl`. The marker key is SHA-256 of the authenticated
challenge token, never the solution nonce. Different valid nonces still compete
for the same marker. TTL covers remaining validity, skew and a one-second margin.

Keys use one Redis hash tag per namespace:

```text
powgate:{mysite}:epoch
powgate:{mysite}:clock
powgate:{mysite}:<epoch>:spent:<sha256-token>
```

Epoch and clock keys never expire. A missing clock or changed/missing epoch
permanently fences that worker until reload/restart with a correctly provisioned
configuration. Runtime code never creates control keys. A Redis clock correction
cannot reopen a challenge reclaimed under the shared clock high-water mark.

The socket pool uses nginx nonblocking connect/write/read events. Each worker
has at most `connections` redemption sockets plus one reserved health socket,
and at most `queue` waiting requests. Slots are reused; TCP connections are
closed after each operation. Each job has one deadline covering its entire
lifetime. Replies are limited to 1 KiB; request bodies retain the 8 KiB streaming
limit. Client cancellation cancels queued/active I/O without deleting markers.

Only confirmed acceptance mints a clearance. A known duplicate returns 409;
expiry returns 400; queue saturation, timeout, protocol error, Redis OOM, auth
failure, clock-skew rejection or unavailable primary returns 503. Ambiguous
replies never retry the same redemption or undo a possibly committed marker.
The browser obtains a fresh challenge instead.

Clearance checks remain local HMAC/context checks with no per-request Redis
lookup. Health checks run once per second. Transport failures stop new issuance
and verification but permit existing valid clearances. A *known* epoch/clock
loss fences local validation too, until the worker is reconfigured. This is
bounded detection, not instantaneous fleet-wide cookie revocation.

## Failover, state loss and epoch rotation

Redis replication is asynchronous. An acknowledged marker can be lost during
failover; persistence and `WAIT` alone do not make this an exactly-once durable
store. The backend assumes one authoritative primary and intact spent state.
Do not automatically fail over behind the same address with the old epoch.

If continuity is uncertain:

1. Fence verification/traffic at **all** proxies and retire the old primary.
2. Restore a single authoritative primary with `noeviction` and sufficient memory.
3. Explicitly rotate the epoch while fenced:

   ```sh
   python3 scripts/redis-epoch.py --address 127.0.0.1:6379 --namespace mysite \
     --rotate "$(cat /etc/pow/cluster.epoch)" --output /etc/pow/cluster.epoch
   ```

4. Deploy the new epoch file to every proxy, reload/restart every proxy, and resume
   traffic only after all serving nodes use it. Old cookies/challenges fail.

Rotation compares the expected old epoch atomically. If the epoch key itself was
lost, `--rotate` refuses; while the fleet is fenced, run the initialization command
to explicitly create a **new random** epoch and distribute that instead. Never
restore the previous epoch when its spent-state continuity is unknown.

For stricter failover guarantees, use storage offering the required durable,
linearizable contract. The implementation does not automate fleet fencing.

## Sizing and validation

Measure marker overhead with `MEMORY USAGE`; size approximately as peak successful
redemptions/second × (validity + skew margin) × bytes/marker, plus control keys and
headroom. Reserve process/container memory for replication and persistence buffers
outside Redis `maxmemory`. Sixteen MiB is a test starting point, not a capacity
recommendation. Never evict live spent markers.

Run `tests/pow-clearance/cluster-test.mjs` against an **isolated** Redis primary:
it deliberately pauses the primary and temporarily sets its maxmemory to 1 byte.
The suite uses a random namespace and two or more isolated nginx masters. It
covers cross-node races, portable cookies, JS/no-JS, HTTP/2, reload/restart, AUTH,
OOM, deadlines, queue saturation, disconnects, clock rollback and epoch fencing.

References: [Redis scripting atomicity](https://redis.io/docs/latest/develop/programmability/eval-intro/),
[SET NX/EX](https://redis.io/docs/latest/commands/set/),
[replication limits](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/),
[noeviction](https://redis.io/docs/latest/develop/reference/eviction/).
