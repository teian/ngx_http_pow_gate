# How to read the gate logs

Goal: see for every request what the gate decided and why. The module exposes
that as nginx variables; you put them in an access log.

## 1. Add a log format

```nginx
http {
    log_format pow '$remote_addr "$request" $status '
                   'pow=$pow_gate_result reason=$pow_gate_reason '
                   'difficulty=$pow_gate_difficulty ua="$http_user_agent"';

    access_log /var/log/nginx/pow.log pow;
}
```

## 2. Read a line

```text
203.0.113.9 "GET / HTTP/2.0" 200 pow=challenge reason=no_clearance difficulty=500000 ua="Mozilla/5.0 …"
203.0.113.9 "GET /.pow/challenge HTTP/2.0" 200 pow=issued reason=pow difficulty=500000 ua="Mozilla/5.0 …"
203.0.113.9 "POST /.pow/verify HTTP/2.0" 204 pow=accepted reason=pow difficulty=500000 ua="Mozilla/5.0 …"
203.0.113.9 "GET / HTTP/2.0" 200 pow=bypass reason=clearance difficulty=500000 ua="Mozilla/5.0 …"
```

That is one visitor being challenged, fetching a challenge, solving it, and
getting in. The lines are illustrative; the values are the ones the module
writes.

| `$pow_gate_result` | Meaning | Reasons |
| --- | --- | --- |
| `off` | gate disabled for this location | `disabled` |
| `bypass` | let through to your upstream | `trusted`, `allow`, `verified_range`, `verified_dns`, `clearance` |
| `deny` | refused with `403`, or the status of a `deny:<status>` decision | `policy` |
| `honeypot` | the hidden trap link on the challenge page was requested | `trap` |
| `challenge` | a challenge page was served | `no_clearance`, `verifier_unconfirmed`, `feed_stale`, `proof_skew` |
| `issued` | a challenge (or no-JS grant) was handed out | `pow`, `nojs` |
| `accepted` | a solution was accepted and a clearance minted | `pow`, `nojs` |
| `rejected` | a submission or status probe was refused | `wrong_solution`, `challenge_expired`, `bad_token`, `replay`, `expired`, `invalid_key`, `invalid_submission`, `invalid_grant`, `body_too_large`, `proof_skew` |
| `error` | the gate could not do its job | `issuer_unavailable`, `redemption_unavailable` |
| `asset` | the solver script was served | `solver` |

A cleared visitor is `bypass` with `reason=clearance` — `accepted` appears only
once per solve, on `/.pow/verify` (or `/.pow/pass` for the no-JS tier).

## 3. Answer the usual questions

```bash
# What is the gate doing overall?
grep -o 'pow=[a-z]*' /var/log/nginx/pow.log | sort | uniq -c | sort -rn

# Why are requests being refused or failing?
grep -E 'pow=(rejected|error)' /var/log/nginx/pow.log \
  | grep -o 'reason=[a-z_]*' | sort | uniq -c | sort -rn

# Which addresses are challenged most?
grep 'pow=challenge' /var/log/nginx/pow.log | cut -d' ' -f1 | sort | uniq -c | sort -rn | head

# How many challenges were fetched, and how many were solved?
grep -c 'pow=issued' /var/log/nginx/pow.log
grep -c 'pow=accepted' /var/log/nginx/pow.log
```

## What the patterns mean

| You see | Likely cause |
| --- | --- |
| Many `challenge`, few `issued` | clients that never run the page's JavaScript — the gate is working. |
| Many `issued`, few `accepted` | clients that start and do not finish. If real users complain, the difficulty is too high for their devices. |
| `challenge reason=no_clearance` on every request of one browser | the cookie is not coming back: blocked cookies, a `Secure` cookie on plain HTTP, the client address changing, or an edge stripping it. |
| Real crawlers with `verifier_unconfirmed` | the client address is the proxy's ([fix](Howto-Run-behind-a-load-balancer)), or the operator's ranges/suffixes are missing from the verifier. |
| `feed_stale` | an IP-range feed has not refreshed within `ip_ranges_max_stale`. Check outbound HTTPS from the nginx host. |
| A steady stream of `proof_skew` or `challenge_expired` | client clocks are wrong, or a custom client ignores the server time. |
| `redemption_unavailable`, `issuer_unavailable` | the redemption store is full or Redis is unreachable; the gate fails closed. |
| `replay` | a solution or grant was submitted twice. Occasional double-submits are normal; a stream of them is someone reusing solutions. |
| Every asset of a page comes back as `text/html` | assets are being challenged — see [troubleshooting.md](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/troubleshooting.md). |

## Notes

- The variables are diagnostic output. Do not feed them back into `map` to make
  decisions.
- No token, cookie value, key or Redis credential appears in them.
- `$pow_gate_cookie_name` gives the effective cookie name, useful for edge rules.

Reference:
[configuration.md › Outcome logging](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/configuration.md#outcome-logging).
