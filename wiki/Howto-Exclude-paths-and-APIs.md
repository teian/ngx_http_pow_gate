# How to exclude paths and APIs

Goal: keep everything that cannot run JavaScript working. A client without
JavaScript cannot solve a challenge — it receives the challenge page as
`200 text/html` instead of what it asked for.

There is no special syntax. An exclusion is a `location` with the gate off:

```nginx
server {
    pow_gate          on;
    pow_gate_trusted  $pow_trusted;
    pow_gate_decision $pow_decision;

    location / { proxy_pass http://backend; }

    location = /robots.txt     { pow_gate off; proxy_pass http://backend; }
    location = /favicon.ico    { pow_gate off; proxy_pass http://backend; }
    location ^~ /.well-known/  { pow_gate off; proxy_pass http://backend; }
    location ^~ /api/          { pow_gate off; proxy_pass http://backend; }
    location = /healthz        { pow_gate off; proxy_pass http://backend; }
}
```

## What to exclude

| Path | Why |
| --- | --- |
| `/.well-known/` | ACME certificate renewal fails behind a challenge |
| `/robots.txt`, sitemaps | crawlers read these before anything else |
| Health checks, uptime monitors | they see `200` from the challenge page and report a healthy site that is not |
| Webhooks and callbacks (payment, OAuth, CI) | the sender is a server |
| Credentialed APIs, mobile-app backends | the API key is the access control |
| RSS/Atom feeds, podcast enclosures, oEmbed | feed readers do not run JavaScript |
| Assets referenced by a custom challenge page | or the page cannot load its own CSS |

## Exclude by client instead of by path

When the consumer is identifiable, exempt the client and keep the path gated:

```nginx
# by network — the monitoring host, the office
geo $pow_trusted {
    default        0;
    203.0.113.5/32 1;
}

# by a shared secret header
map $http_x_internal_token $pow_trusted {
    default        0;
    "s3cr3t-xyz"   1;
}

# by client certificate
map $ssl_client_verify $pow_trusted { default 0; SUCCESS 1; }
```

Use `geo` for address ranges — it is the only stock matcher that understands
CIDR — and `map` for everything else. Pick one source for `$pow_trusted`.

## Your own pages' fetch/XHR calls

A logged-in browser that already holds a clearance passes with its cookie, AJAX
included. Two cases still need care:

- **The clearance expires while a page is open.** The next `fetch`/XHR call gets
  the challenge page as its response and cannot solve it from there; the user
  has to navigate or reload once. A form `POST` is different: the gate keeps the
  submitted body and re-sends it after the solve (`pow_gate_replay`, on by
  default).
- **Upload endpoints.** Set `pow_gate_replay off;` there so the gate never reads
  the body of an uncleared client.

Leave `pow_gate_require_proof` at `off` unless your pages sign their own
requests; with `on` and no integration, every AJAX call is challenged. See
[troubleshooting.md](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/troubleshooting.md).

## Check an exclusion

```bash
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' https://example.com/api/status
```

`text/html` where you expected JSON means that path is still gated. In the logs
an excluded request shows `pow=off`.
