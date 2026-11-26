# ngx_http_pow_gate

A native **nginx dynamic module** that puts a proof-of-work gate in front of your
sites: scrapers and abusive bots pay CPU for every clearance, while real
browsers, trusted networks and verified good bots get through.

New here? Follow these three in order:

1. [Install a released module](Howto-Install-a-released-module)
2. [Set up your first gate](Howto-Set-up-your-first-gate)
3. [Read the gate logs](Howto-Read-the-gate-logs)

## How-tos

| I want to… | Page |
| --- | --- |
| Install the prebuilt `.so` for my nginx | [Install a released module](Howto-Install-a-released-module) |
| Gate a site for the first time | [Set up your first gate](Howto-Set-up-your-first-gate) |
| Keep Googlebot and Bingbot working | [Let verified search engines through](Howto-Let-verified-search-engines-through) |
| Deny AI crawlers or make tools pay more | [Block or slow down crawlers](Howto-Block-or-slow-down-crawlers) |
| Pick a difficulty and clearance lifetime | [Tune difficulty and clearance lifetime](Howto-Tune-difficulty-and-clearance-lifetime) |
| Keep APIs, webhooks, feeds and ACME reachable | [Exclude paths and APIs](Howto-Exclude-paths-and-APIs) |
| Start from maintained crawler lists | [Use the bundled rules](Howto-Use-the-bundled-rules) |
| Keep chat and social link previews | [Keep link previews working](Howto-Keep-link-previews-working) |
| Run behind a load balancer or CDN | [Run behind a load balancer](Howto-Run-behind-a-load-balancer) |
| Run more than one nginx instance | [Run several gateways with Redis](Howto-Run-several-gateways-with-Redis) |
| Brand the "Just a moment…" page | [Customize the challenge page](Howto-Customize-the-challenge-page) |
| See what the gate decided and why | [Read the gate logs](Howto-Read-the-gate-logs) |
| Graph challenge and solve rates, react to load and traps | [Monitor the gate](Howto-Monitor-the-gate) |
| Move to a new nginx or module version | [Upgrade nginx and the module](Howto-Upgrade-nginx-and-the-module) |
| Try it locally without touching a server | [Try it in the local sandbox](Howto-Try-it-in-the-local-sandbox) |

## Reference

The reference documentation lives in the repository and is versioned with the
code:

- [README](https://github.com/teian/ngx_http_pow_gate/blob/main/README.md) — overview, decision flow, handshake
- [Configuration](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/configuration.md) — every directive
- [Protocol](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/protocol.md) — endpoints and token formats
- [Security](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/security.md) — guarantees and limits
- [Redis](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/redis.md) — multi-gateway coordination
- [Challenge page](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/challenge-page.md) — page contract
- [Build](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/build.md) — building from source, verifiable builds
- [Troubleshooting](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/troubleshooting.md) — field symptoms
- [Releases](https://github.com/teian/ngx_http_pow_gate/releases) — signed modules and release notes

> These wiki pages are generated from the [`wiki/`](https://github.com/teian/ngx_http_pow_gate/tree/main/wiki)
> directory of the repository. Edit them there through a pull request; direct
> edits in the wiki are overwritten by the next sync.
