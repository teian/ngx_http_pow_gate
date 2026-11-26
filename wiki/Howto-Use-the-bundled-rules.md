# How to use the bundled rules

Goal: start from maintained crawler lists instead of writing every `map` entry
yourself. The repository's [`rules/`](https://github.com/teian/ngx_http_pow_gate/tree/main/rules)
directory is plain nginx configuration.

## 1. Copy the rules to the server

```bash
git clone --depth 1 https://github.com/teian/ngx_http_pow_gate.git
sudo cp -r ngx_http_pow_gate/rules /etc/nginx/pow-rules
```

## 2. Include them

```nginx
http {
    include /etc/nginx/pow-rules/verifiers.conf;

    map $http_user_agent $pow_decision {
        default challenge;
        # your own entries go here; they win over the includes below
        include /etc/nginx/pow-rules/ai-crawlers.map;
        include /etc/nginx/pow-rules/search-engines.map;
        # include /etc/nginx/pow-rules/automation.map;
    }
}
```

| File | Effect |
| --- | --- |
| `verifiers.conf` | defines the `search_engines`, `ai_search` and `ai_user_fetch` verifiers |
| `search-engines.map` | search-engine User-Agents → `verify:search_engines` |
| `ai-crawlers.map` | AI training crawlers → `deny`; AI search indexes → verified; the rest → `challenge` |
| `automation.map` | optional: HTTP libraries, headless browsers and empty User-Agents → `deny` |

nginx tries the regular expressions of a map in the order they appear, so the
order of the `include` lines decides which file wins.

Leave `automation.map` out if the same decision covers an API or a feed that
scripts are meant to fetch. [Turn the gate off](Howto-Exclude-paths-and-APIs)
for those paths instead.

## 3. Add what your robots.txt already asks for

```bash
./scripts/robots2map.py /var/www/robots.txt | sudo tee /etc/nginx/pow-rules/robots.map
```

Every `User-agent` group with `Disallow: /` becomes a `deny` entry. Pass
`--action challenge:500000` to make those crawlers pay instead. Include the
file like the others.

## 4. Check and reload

```bash
sudo nginx -t && sudo nginx -s reload
```

Then watch [the gate log](Howto-Read-the-gate-logs): `pow=deny reason=policy`
lines are the refused crawlers, `reason=verified_range` and `verified_dns` are
confirmed good bots, and `reason=verifier_unconfirmed` is a client that claimed
a crawler's name from the wrong network.

## Upgrading

The lists change with module releases. Copy the new files, read the diff, and
run `nginx -t`. A User-Agent is a claim: these rules stop crawlers that say who
they are. One that pretends to be a browser gets your default decision.
