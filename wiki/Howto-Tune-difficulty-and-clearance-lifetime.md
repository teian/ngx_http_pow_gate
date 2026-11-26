# How to tune difficulty and clearance lifetime

Two numbers set the price of your site: how much work one clearance costs, and
how long it lasts.

## Difficulty

`pow_gate_difficulty N` is the **expected number of hashes** per solve. Cost is
linear in `N` — for the attacker and for the honest visitor alike.

| `N` | Typical wait on a laptop | Use when |
| --- | --- | --- |
| `50000` (default) | imperceptible | light deterrence only |
| `500000` | ~0.1–0.5 s | sensible starting point |
| `2000000` | ~0.5–2 s | active scraping, some human delay is acceptable |
| `10000000`+ | several seconds | targeted abuse; slow devices will complain |

The solver hashes on all cores through Web Workers. A low-end phone is roughly
ten times slower than a laptop, so test your choice on the slowest device you
care about. The compiled-in default of `50000` is low for the current solver —
set the value explicitly.

Raise the price for suspicious clients only, instead of for everyone:
[Block or slow down crawlers](Howto-Block-or-slow-down-crawlers).

### Solves are much slower than the table

A `Content-Security-Policy` that does not allow `worker-src 'self'` stops the
solver from starting workers. It still works, on one core. The browser console
shows the CSP violation.

## Clearance lifetime

`pow_gate_clearance_ttl` (default `12h`) is how long one solve lasts.

- Shorter: a scraper pays more often — and so do your visitors.
- Longer: fewer challenges, and a longer free ride after one solve.

Lowering the value also shortens clearances that were already issued.

## Address binding

A clearance is bound to the exact client address, the User-Agent and the policy.
A visitor whose address changes solves again. If your audience moves between
addresses a lot — mobile networks, IPv6 privacy addresses — widen the binding:

```nginx
pow_gate_ipv6_prefix 64;    # default 128
pow_gate_ipv4_prefix 32;    # default 32
```

Everyone inside the prefix then shares the same address binding, so do not go
wider than you need. Changing a prefix renames the cookie; clients solve once
more.

## Invalidate everything on purpose

- Change `pow_gate_policy <name>` to drop the clearances of that scope.
- Replace the HMAC key to drop all of them.

## Measure before and after

Log `$pow_gate_result` and `$pow_gate_difficulty`
([Read the gate logs](Howto-Read-the-gate-logs)) and compare `issued`
(challenges fetched) with `accepted` (challenges solved). Many fetched and few
solved means clients give up or run out of time — on real browsers, a sign the
difficulty is too high for their devices.

Reference:
[configuration.md › Tuning](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/configuration.md#tuning-pow_gate_difficulty).
