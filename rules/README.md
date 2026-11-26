# Bundled rules

Ready-made policy for `ngx_http_pow_gate`, as plain nginx configuration.
Copy the directory to the server (for example `/etc/nginx/pow-rules/`) and
include what you want.

| File | Include in | What it does |
| --- | --- | --- |
| `verifiers.conf` | `http {}` | `pow_gate_verifier` blocks for search engines, AI search indexes and user-triggered AI fetchers. |
| `search-engines.map` | your decision `map` | Routes search-engine User-Agents to `verify:search_engines`. |
| `ai-crawlers.map` | your decision `map` | Refuses AI training crawlers, verifies AI search indexes, challenges the rest. |
| `automation.map` | your decision `map` | Optional. Refuses HTTP libraries, headless browsers and empty User-Agents. |

```nginx
http {
    include /etc/nginx/pow-rules/verifiers.conf;

    map $http_user_agent $pow_decision {
        default challenge;
        include /etc/nginx/pow-rules/ai-crawlers.map;
        include /etc/nginx/pow-rules/search-engines.map;
        # include /etc/nginx/pow-rules/automation.map;
    }
}
```

nginx tries a map's regular expressions in the order they appear, so the
order of the `include` lines is the precedence between files. Put your own
entries before the includes to override a bundled one.

The lists change with each module release. Review the diff when you upgrade;
`nginx -t` validates the result. `scripts/robots2map.py` turns the
`Disallow: /` groups of an existing `robots.txt` into the same format.
