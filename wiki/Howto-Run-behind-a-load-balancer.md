# How to run behind a load balancer or CDN

The gate decides and binds on the **client address**: `geo` trust, good-bot
verification and the address binding of every clearance. Behind a proxy that
address is the proxy's unless you restore it.

## 1. Restore the client address

With nginx's stock realip module, in `http` or `server`:

```nginx
set_real_ip_from 10.0.0.0/8;          # your load balancer / CDN ranges only
real_ip_header   X-Forwarded-For;
real_ip_recursive on;
```

List **only** addresses you control or your CDN publishes. Trusting the header
from anyone lets a client claim any address — including one inside your
`geo $pow_trusted` ranges.

For a PROXY-protocol load balancer use `listen … proxy_protocol;` with
`real_ip_header proxy_protocol;` instead.

## 2. Check what the gate sees

```nginx
log_format pow '$remote_addr "$request" $status pow=$pow_gate_result reason=$pow_gate_reason';
```

`$remote_addr` must show real client addresses. If every line shows the proxy:

- everyone shares one address binding,
- verified bots are never verified, and
- a trusted proxy range makes every visitor trusted.

## 3. Keep the address stable per client

A clearance is bound to the address it was issued for. If your edge reaches you
over changing egress addresses and you do not restore the client address,
visitors are challenged again and again. Restoring the real address fixes that.
For clients whose own address rotates, see
[Tune difficulty and clearance lifetime](Howto-Tune-difficulty-and-clearance-lifetime#address-binding).

## 4. Caching layers

- Challenge pages and protocol responses are sent `Cache-Control: no-store`.
  Make sure the layer in front honours it and never caches a `200 text/html`
  challenge under the URL of real content.
- The solver script (`/.pow/solver.js?v=…`) is content-hashed and immutable; it
  may be cached freely.
- The cookie name carries a scope suffix. Where an edge rule needs it, take it
  from `$pow_gate_cookie_name` rather than hard-coding a name.
- Do not let the edge strip the clearance cookie or the `/.pow/` requests.

## 5. More than one nginx

Several nginx instances behind the balancer need a shared redemption store and
identical settings — see
[Run several gateways with Redis](Howto-Run-several-gateways-with-Redis).

Reference: [configuration.md › Common mistakes](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/configuration.md#common-mistakes).
