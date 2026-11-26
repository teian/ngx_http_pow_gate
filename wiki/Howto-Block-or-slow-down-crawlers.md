# How to block or slow down crawlers

Goal: decide per client how much it costs to get in — from "nothing" to "no".
All of it is one stock nginx `map`; the gate only reads the result.

## The values

| `$pow_decision` | Effect |
| --- | --- |
| `allow` | pass, no challenge |
| `deny` | `403`, no challenge offered |
| `challenge` | proof-of-work at `pow_gate_difficulty` |
| `challenge:<N>` | proof-of-work at difficulty `N` for this client |
| `challenge:js` | only prove JavaScript runs; no measurable work |
| `challenge:nojs` / `challenge:nojs:<secs>` | wait page without JavaScript (default 2 s, 1–30 s) |
| `verify:<name>` | [verified good bot](Howto-Let-verified-search-engines-through), else challenge |

An empty or unrecognised value is treated as `challenge`.

## A graded policy

```nginx
map $http_user_agent $pow_decision {
    default                            challenge;          # normal browsers
    ~*(gptbot|ccbot|bytespider)        deny;               # declared AI crawlers
    ~*(python|curl|go-http|scrapy)     challenge:2000000;  # tools pay 4× more
    ~*(lynx|w3m|links|elinks)          challenge:nojs;     # text browsers
    ~*(googlebot|bingbot)              verify:search_engines;
}
```

Things to know:

- **`deny` only stops honest bots.** A crawler that lies about its User-Agent
  lands in `default` and is challenged — which is the point of the gate.
- **`challenge:nojs` is the weakest tier.** A headless browser simply waits. It
  is reachable only for clients your `map` sends there; never make it the
  default.
- **A cheaper clearance never unlocks a stricter one.** A client cleared at
  `challenge:js` is challenged again where the policy demands real work.

## Decide on more than the User-Agent

Any nginx variable can feed the map. By network, with the optional GeoIP2
module ([examples/asn-policy.conf](https://github.com/teian/ngx_http_pow_gate/blob/main/examples/asn-policy.conf)):

```nginx
map "$pow_network_tier:$http_user_agent" $pow_decision {
    default                        challenge;
    ~*:(gptbot|bytespider|ccbot)   deny;
    ~^elevated:                    challenge:2000000;
}
```

## A harder gate for one path

```nginx
location /search/ {
    pow_gate_policy     search;
    pow_gate_difficulty 2000000;
    pow_gate_endpoint   /search/.pow/;
    proxy_pass http://backend;
}
```

Give such a location its own `pow_gate_endpoint`: the endpoint that issues a
clearance must resolve to the same policy and difficulty as the content it
protects.

## Do not stop at the gate

A solved challenge buys a clearance for `pow_gate_clearance_ttl`. Cap what a
cleared client can do with ordinary `limit_req` / `limit_conn` —
[examples/regular-traffic-limits.conf](https://github.com/teian/ngx_http_pow_gate/blob/main/examples/regular-traffic-limits.conf)
is a complete include that starts in dry-run mode.

Check the effect in the [logs](Howto-Read-the-gate-logs): `pow=deny`,
`pow=challenge` and the `difficulty=` each request was given.

`map` checks exact strings first and then regexes in file order, so list the
stricter patterns above the broader ones.
