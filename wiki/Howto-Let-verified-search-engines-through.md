# How to let verified search engines through

Goal: Googlebot, Bingbot and similar crawlers pass without a challenge — but
only when the request really comes from them. A User-Agent alone proves
nothing; anyone can send `Googlebot`.

The gate verifies in two ways, and either is enough:

- the client address is in the operator's **published IP ranges**, or
- **forward-confirmed reverse DNS**: the address has a PTR name under an allowed
  suffix, and that name resolves back to the same address.

## 1. Define a verifier

In `http {}`:

```nginx
pow_gate_verifier search_engines {
    ip_ranges_url     https://developers.google.com/static/crawling/ipranges/common-crawlers.json;
    ip_ranges_url     https://www.bing.com/toolbox/bingbot.json;
    ip_ranges_refresh 12h;
    fcrdns_suffix     .googlebot.com .google.com .search.msn.com;
    fcrdns_ttl        1h;
}
```

Suffixes match on a DNS label boundary: `googlebot.com` accepts
`crawl-1.googlebot.com` and rejects `evilgooglebot.com`.

## 2. Route the claimed User-Agents to it

```nginx
map $http_user_agent $pow_decision {
    default                  challenge;
    ~*(googlebot|bingbot)    verify:search_engines;
}
```

A `verify:` that **fails** falls through to a normal challenge. It never denies
and never allows, so a typo or a spoofed User-Agent cannot open the gate.

## 3. Check it

```bash
sudo nginx -t && sudo nginx -s reload
curl -s -o /dev/null -w '%{content_type}\n' -A Googlebot https://example.com/
```

From your own machine this prints `text/html` — the challenge page — because
your address is not Google's. That is the verifier working. Confirm the real
thing in the [logs](Howto-Read-the-gate-logs): genuine crawler requests show
`pow=bypass reason=verified_range` or `reason=verified_dns`, impostors show
`pow=challenge reason=verifier_unconfirmed`.

## What to expect

- **Right after a start or reload of a fresh worker** the range list is empty
  until the first fetch completes, so crawlers are challenged for a moment.
- **The first request from a new address** on the DNS path is challenged while
  the lookup runs in the background; the verdict is cached for `fcrdns_ttl`.
  The IP-range path has no such delay.
- **A feed that stops updating** keeps its last good snapshot for
  `ip_ranges_max_stale` (default `48h`), then expires — logged as
  `pow=challenge reason=feed_stale`. Other feeds are unaffected.
- **Behind a load balancer** the verifier sees the proxy's address unless you
  [restore the client address](Howto-Run-behind-a-load-balancer).

Use several `pow_gate_verifier` blocks with different names for different bot
classes. Reference:
[configuration.md › The pow_gate_verifier block](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/configuration.md#the-pow_gate_verifier-block).
