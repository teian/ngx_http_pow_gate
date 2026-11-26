# How to run several gateways with Redis

One nginx instance needs nothing extra: a 2 MiB shared-memory ledger makes every
solution redeemable once across its workers and survives graceful reloads.

Add Redis when

- several nginx instances serve the same site without sticky routing, or
- clearances must survive a full nginx restart.

Redis here is a single authoritative primary. The module is **not** a Redis
Cluster or Sentinel client, and it does not speak TLS to Redis — keep the
connection on a private network or a local tunnel.

## 1. Run a dedicated Redis

It must never evict:

```bash
docker run --name pow-redis -d -p 127.0.0.1:6379:6379 redis:8-alpine \
  redis-server --maxmemory 16mb --maxmemory-policy noeviction
```

16 MiB is a test value, not a sizing recommendation — see
[redis.md › Sizing](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/redis.md#sizing-and-validation).

## 2. Provision the epoch once

```bash
python3 scripts/redis-epoch.py --address 127.0.0.1:6379 \
  --namespace mysite --output /etc/pow/cluster.epoch
```

Copy the **same** file to every gateway. It identifies the deployment; it is
not the HMAC secret. Running the helper again against an intact namespace
exports the existing epoch.

## 3. Configure every gateway identically

In `http {}`:

```nginx
pow_gate_redis {
    address    127.0.0.1:6379;      # numeric address and port
    namespace  mysite;
    epoch_file /etc/pow/cluster.epoch;
    # timeout 500;  connections 4;  queue 64;  clock_skew 5;
    # username powgate;
    # password_file /etc/pow/redis.password;
}
```

All gateways must also share

- the same HMAC key file content,
- the same `pow_gate_endpoint`, `pow_gate_policy`, cookie settings and address
  prefixes, and
- the same [client-address handling](Howto-Run-behind-a-load-balancer).

## 4. Reload and check

```bash
sudo nginx -t && sudo nginx -s reload
```

Switching between the local ledger and Redis invalidates existing clearances;
every client solves once more. A worker refuses new challenges until its first
successful Redis health check, normally within a second.

Then solve on one gateway and send the next request to another: it must pass
without a second challenge.

## When Redis is unavailable

The gate fails closed — it never falls back to the local ledger. New
challenges and redemptions answer `503` and the
[logs](Howto-Read-the-gate-logs) show `pow=error` with
`reason=issuer_unavailable` or `reason=redemption_unavailable`. Clients that
already hold a valid clearance keep passing: clearance checks are local and
make no Redis lookup.

## Failover

Redis replication is asynchronous, so a promoted replica may have lost spent
markers. Do not fail over automatically behind the same address. If continuity
is uncertain, fence all gateways, restore one primary, **rotate the epoch** and
redeploy it everywhere — the exact procedure is in
[redis.md › Failover](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/redis.md#failover-state-loss-and-epoch-rotation).
