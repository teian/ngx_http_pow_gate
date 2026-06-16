# Configuration reference

Every directive the module adds: context, arguments, default, inheritance, and
how it interacts with the rest. The companion native directives (`geo`, `map`,
`set_real_ip_from`) are stock nginx and are covered only where they matter to the
gate.

- [Quick map](#quick-map)
- [Core directives](#core-directives)
- [Decision values](#decision-values)
- [The `pow_gate_verifier` block](#the-pow_gate_verifier-block)
- [Inheritance & how `off` wins](#inheritance--how-off-wins)
- [Recipes](#recipes)
- [Tuning `pow_gate_difficulty`](#tuning-pow_gate_difficulty)
- [Common mistakes](#common-mistakes)

---

## Quick map

| Directive                  | Context           | Args         | Default     | Backed by                  |
| -------------------------- | ----------------- | ------------ | ----------- | -------------------------- |
| `pow_gate`                 | http, server, location    | `on`\|`off`  | `off`       | `LocationConf.enabled`          |
| `pow_gate_trusted`         | server, location          | `$var`       | (unset)     | `LocationConf.trusted`          |
| `pow_gate_decision`        | server, location          | `$var`       | `challenge` | `LocationConf.decision`         |
| `pow_gate_page`            | http, server, location    | `<file>`     | embedded    | `LocationConf.page_path`        |
| `pow_gate_difficulty`      | http, server, location    | `N`          | `50000`     | `LocationConf.difficulty`       |
| `pow_gate_hmac_key_file`   | http, server, location    | `<file>`     | —           | `LocationConf.hmac_key_file`    |
| `pow_gate_clearance_ttl`   | http, server, location    | `<time>`     | `12h`       | `LocationConf.clearance_ttl`    |
| `pow_gate_proof_skew`      | http, server, location    | `<time>`     | `5s`        | `LocationConf.proof_skew`       |
| `pow_gate_require_proof`   | http, server, location    | `on`\|`off`  | `on`        | `LocationConf.require_proof`    |
| `pow_gate_endpoint`        | http, server, location    | `<prefix>`   | `/.pow/`    | `LocationConf.endpoint`         |
| `pow_gate_cookie_name`     | http, server, location    | `<name>`     | `pow_clearance` | `LocationConf.cookie_name`  |
| `pow_gate_cookie_domain`   | http, server, location    | `<domain>`   | host-only   | `LocationConf.cookie_domain`    |
| `pow_gate_cookie_path`     | http, server, location    | `<path>`     | `/`         | `LocationConf.cookie_path`      |
| `pow_gate_cookie_samesite` | http, server, location    | `Lax\|Strict\|None` | `Lax` | `LocationConf.cookie_samesite`   |
| `pow_gate_cookie_secure`   | http, server, location    | `on`\|`off`  | `on`        | `LocationConf.cookie_secure`    |
| `pow_gate_cookie_httponly` | http, server, location    | `on`\|`off`  | `on`        | `LocationConf.cookie_httponly`  |
| `pow_gate_verifier <name>` | http (block)      | `{ … }`      | —           | `MainConf.verifiers`       |

Defaults marked `—` are required when the feature is used. **Every directive
except the `pow_gate_verifier` block inherits** down `http → server → location`
and can be overridden at any level (standard nginx merge, just like `proxy_*`).
The verifier block stays `http`-only because it registers a *global* named
allowlist referenced by `verify:<name>` from anywhere. The command table that
encodes these contexts lives in [`src/config.rs`](../src/ngx-http-pow-gate/src/config.rs).

---

## Core directives

### `pow_gate on | off;`

> Context: `http`, `server`, `location` · Default: `off` · Inheritable flag

The master switch for a location. `off` makes the handler return `NGX_DECLINED`
immediately — the request goes straight to your upstream with zero gate overhead.
Because it's a standard nginx flag, you set it broadly and turn it off precisely:

```nginx
server {
    location / { pow_gate on;  proxy_pass http://backend; }
    location = /healthz { pow_gate off; return 200; }   # excluded
}
```

### `pow_gate_trusted $var;`

> Context: `server`, `location` · Argument: a complex value (literal or `$variable`)

The gate allows the request and stops when this evaluates to `"1"`. It is
**source-agnostic** — any variable works. `geo` is the recommended default for
**IP ranges** (it is the only stock matcher that understands CIDR / longest-prefix):

```nginx
geo $pow_trusted {
    default        0;
    10.0.0.0/8     1;     # internal
    203.0.113.5/32 1;     # office egress
}
location / {
    pow_gate         on;
    pow_gate_trusted $pow_trusted;
}
```

#### Alternative: `map` (when trust is not a CIDR range)

`map` matches a variable **as a string** — it has no CIDR/subnet math, so use it
when trust keys off something other than an IP range (mTLS, a header, an API
token, `$server_name`) or off a short list of exact IPs. The output must be
`"1"`/`"0"` just like `geo`.

```nginx
# 1) mTLS client certificate
map $ssl_client_verify $pow_trusted {
    default  0;
    SUCCESS  1;
}

# 2) shared internal header / API token
map $http_x_internal_token $pow_trusted {
    default       0;
    "s3cr3t-xyz"  1;
}

# 3) a handful of exact IPs (no ranges)
map $remote_addr $pow_trusted {
    default      0;
    203.0.113.5  1;
    198.51.100.7 1;
}

# 4) coarse octet-boundary prefixes via anchored regex (fragile — prefer geo)
map $remote_addr $pow_trusted {
    default      0;
    ~^10\.       1;     # ≈ 10.0.0.0/8
    ~^192\.168\. 1;     # ≈ 192.168.0.0/16
}
```

Rule of thumb: **IP ranges → `geo`**; **mTLS / header / token / exact IPs →
`map`**. You can also layer them (`geo $ip_zone; map $ip_zone $pow_trusted`).
Either way `pow_gate_trusted` only sees the resolved `$pow_trusted` value.

### `pow_gate_decision $var;`

> Context: `server`, `location` · Argument: a complex value · Default: `challenge`

The per-request verdict, normally produced by a `map`. See
[Decision values](#decision-values). If unset/empty, the client is challenged.

```nginx
map $http_user_agent $pow_decision {
    default                  challenge;
    ~*(gptbot|bytespider)    deny;
    ~*(googlebot|bingbot)    verify:search_engines;
}
location / {
    pow_gate          on;
    pow_gate_decision $pow_decision;
}
```

### `pow_gate_page <file>;`

> Context: `http`, `server`, `location` · Default: embedded `challenge.html`

Path to a custom challenge/progress page. Loaded and cached once at config time;
`{{difficulty}}` and `{{endpoint}}` placeholders are substituted before caching.
If omitted, the page compiled into the module
([`assets/challenge.html`](../assets/challenge.html)) is used, so the module works
with zero extra files.

Your page only needs these hook IDs for the solver to drive it: `#pow-status`,
`#pow-progress`, `#pow-percent`, `#pow-error`. Everything else is yours. Full
guide — contract, placeholders, minimal template, reload caveat — in
[docs/challenge-page.md](challenge-page.md).

> The **solver** (`{endpoint}solver.js`) is **always provided by the module** from
> its embedded copy — there is no override directive. It is the client half of the
> proof-of-work protocol and must stay in lockstep with the engine, so it ships
> with the module. You customize the *page*; the solver is fixed.

### `pow_gate_difficulty N;`

> Context: `http`, `server`, `location` · Argument: integer

The *expected number of hashes* a client performs per solve. The module converts
it to a 256-bit target (`target = 2^256 / N`). Higher = more client CPU = more
friction. See [Tuning](#tuning-pow_gate_difficulty). Inherits and is overridable
per server/location, so you can run a harder gate on a hot path
(`location /search/ { pow_gate_difficulty 200000; }`) than on the rest of the site.

### `pow_gate_hmac_key_file <file>;`

> Context: `http`, `server`, `location` · Argument: file path · **Required wherever `pow_gate on`**

The server secret used to HMAC-sign clearance cookies and challenge salts.

> **Fail-closed.** Wherever the gate is enabled, this must point to a readable
> file of **at least 16 bytes** (use 32+). If it is missing, unset, or too short,
> nginx **refuses to start** (`nginx -t` fails) rather than running with an empty
> key — an empty/known key would make every clearance and challenge token
> forgeable. The worker also re-checks at request time: if *it* cannot read the
> file (e.g. wrong ownership, see below), the gate fails closed — clients are
> challenged and `/.pow/` returns `503` — instead of falling open. Run the worker
> as the key file's owner.

Set it once at `http` and let it inherit — that keeps a single key everywhere, which is
what you want: the `pow_gate_endpoint` location that *issues* a clearance and the
gated location that *verifies* it must resolve to the **same** key (and the same
`pow_gate_endpoint`), or clearances won't validate. Override per server/location
only for deliberate isolation between vhosts. Generate 32+ random bytes and lock
it down:

```bash
head -c 32 /dev/urandom > /etc/pow/hmac.key
chmod 600 /etc/pow/hmac.key
chown nginx:nginx /etc/pow/hmac.key
```

Rotating the key invalidates all outstanding clearances (clients re-solve once).

### `pow_gate_clearance_ttl <time>;`

> Context: `http`, `server`, `location` · Default: `12h`

How long a clearance stays valid after a solve — i.e. how long until a returning
visitor is challenged **again**. This is a UX knob, not a security one: once a
human solves the PoW, re-challenging them every half hour is a nuisance, so the
default is a generous **12h** (covers a working day). Bump it higher (`24h`,
`72h`) for a friendlier site; lower it only if you have a specific reason.

Length trades UX against the replay window of a leaked clearance cookie. With
`pow_gate_require_proof on` (default), non-navigation requests (fetch/XHR) still
need a fresh `pow_gate_proof_skew`-bounded proof signed by the client's private
key (see [docs/architecture.md](architecture.md#the-two-token-security-model)),
so a stolen cookie cannot be replayed over those. **Top-level navigations are
gated by the cookie alone** — they cannot carry the proof header — so a longer TTL
does widen the window in which a leaked cookie could be replayed as a navigation.
A long clearance spares the user from redoing the *work*, not the *proof*. Keep
the default unless you have a reason; lower it if cookie leakage is a concern in
your environment.

nginx time syntax: `30m`, `12h`, `72h`, `90s`.

### `pow_gate_proof_skew <time>;`

> Context: `http`, `server`, `location` · Default: `5s`

The validity window for the per-request proof timestamp. Must absorb realistic
clock skew and network delay between client and server, but small enough that a
captured proof can't be meaningfully replayed. `5s` is a sane start; raise it if
you see legitimate failures from clients with bad clocks.

### `pow_gate_require_proof on | off;`

> Context: `http`, `server`, `location` · Default: `on`

Controls whether a valid per-request proof (`X-Pow-Proof`) is **required** on
non-navigation requests that present a clearance cookie.

- `on` (default) — a request the browser marks as a sub-resource fetch/XHR
  (`Sec-Fetch-Mode` present and not `navigate`) must carry a valid proof signed by
  the clearance-bound key; the cookie alone is **not** enough. This is what stops
  a leaked clearance cookie from being replayed by `fetch`/XHR/CLI tooling.
- `off` — the cookie alone is accepted on every request (the proof is still
  verified when present, but never demanded). Use only if a legitimate client
  cannot run the solver's `fetch` wrapper yet must reuse a clearance.

Top-level navigations (`Sec-Fetch-Mode: navigate`) and clients that send **no**
`Sec-Fetch-*` metadata at all (older browsers, non-browser agents) are always
allowed on the cookie alone — they cannot attach a custom header on a navigation,
so requiring one would lock them out. The hardening therefore targets exactly the
fetch/XHR replay vector without breaking navigation.

### `pow_gate_endpoint <prefix>;`

> Context: `http`, `server`, `location` · Default: `/.pow/`

The URL prefix for the three internal routes the module serves
(`challenge`, `solver.js`, `verify`). Change it if `/.pow/` collides with your
app. Must start and end with `/`. The same value is injected into the page as
`{{endpoint}}`.

---

## Clearance-cookie directives

Control the name and attributes of the `Set-Cookie` the module emits after a
solve. All are valid in `http`, `server`, and `location` (they inherit and
override like the rest) and are assembled in
[`engine::clearance::build_set_cookie`](../src/ngx-http-pow-gate/src/engine/clearance.rs). Defaults are
hardened (`Secure`, `HttpOnly`, `SameSite=Lax`, host-only) — change them only
with reason.

### `pow_gate_cookie_name <name>;`

> Default: `pow_clearance`

The cookie name. The same name is used when *reading* the cookie on later
requests, so changing it does not strand existing clients beyond one re-solve.
Use this to avoid collisions or to obscure the mechanism.

### `pow_gate_cookie_domain <domain>;`

> Default: *(unset — host-only cookie)*

Sets the cookie `Domain=`. Leave unset for a **host-only** cookie (matches only
the exact host that served `/verify`) — the safest default and correct for a
single hostname. Set it to a parent domain to **share one clearance across
subdomains**:

```nginx
pow_gate_cookie_domain .example.com;   # app.example.com + www.example.com share clearance
```

Don't set a domain you don't control or a public suffix — browsers reject those.

### `pow_gate_cookie_path <path>;`

> Default: `/`

The cookie `Path=`. `/` (whole site) is almost always right. Narrow it only if
the gate guards a sub-tree and you want the cookie scoped to it.

### `pow_gate_cookie_samesite Lax | Strict | None;`

> Default: `Lax`

The `SameSite` attribute.

- `Lax` — sent on top-level navigations; good default, survives clicking a link
  to your site.
- `Strict` — never sent cross-site; can cause an extra challenge when arriving
  from an external link.
- `None` — sent on all cross-site requests; **requires** `Secure`, so the module
  forces `Secure` on when you pick `None`. Use only if the gated origin is loaded
  cross-site (embedded, third-party context).

### `pow_gate_cookie_secure on | off;`

> Default: `on`

Adds the `Secure` flag (cookie only sent over HTTPS). Keep `on` in production.
Turning it `off` is for plain-HTTP local testing only. Forced `on` when
`SameSite=None`.

### `pow_gate_cookie_httponly on | off;`

> Default: `on`

Adds `HttpOnly` (JavaScript cannot read the cookie). Keep `on` — the solver never
needs to read the clearance cookie from JS; the browser sends it automatically.
Only turn `off` if some client-side code must inspect it (rare, discouraged).

> **Max-Age** is not a separate directive — it tracks `pow_gate_clearance_ttl`,
> so the cookie expires exactly when the clearance does.

Example — share clearance across subdomains, relax SameSite for an embedded app:

```nginx
http {
    pow_gate_cookie_name     gate_clearance;
    pow_gate_cookie_domain   .example.com;
    pow_gate_cookie_samesite None;          # forces Secure on
    pow_gate_clearance_ttl   1h;            # → cookie Max-Age=3600
}
```

Resulting header:

```
Set-Cookie: gate_clearance=<token>; Path=/; Domain=.example.com; Max-Age=3600; SameSite=None; Secure; HttpOnly
```

---

## Decision values

`pow_gate_decision` understands exactly these:

| Value           | Effect                                                                 |
| --------------- | ---------------------------------------------------------------------- |
| `allow`         | Pass to upstream. No challenge.                                        |
| `deny`          | `403 Forbidden`. No challenge offered.                                 |
| `challenge`     | Must solve PoW (unless already cleared). The default.                  |
| `verify:<name>` | Run `pow_gate_verifier <name>`; pass if it confirms the IP, else challenge. |
| *(empty)*       | Treated as `challenge`.                                                |

`verify:<name>` that *fails* falls through to a challenge — it does **not** deny.
That way a real client behind an odd UA still has a route through.

---

## The `pow_gate_verifier` block

> Context: `http` · Form: `pow_gate_verifier <name> { … }`

Defines a named good-bot verifier referenced as `verify:<name>` from a `map`.

```nginx
pow_gate_verifier search_engines {
    ip_ranges_url     https://developers.google.com/static/crawling/ipranges/common-crawlers.json;
    ip_ranges_url     https://www.bing.com/toolbox/bingbot.json;
    ip_ranges_refresh 12h;
    fcrdns_suffix     .googlebot.com .google.com .search.msn.com;
    fcrdns_ttl        1h;
}
```

Inner directives:

| Inner directive     | Args                 | Meaning                                                        |
| ------------------- | -------------------- | ------------------------------------------------------------- |
| `ip_ranges_url`     | `<url>` (repeatable) | Official JSON IP-range feed to fetch and merge.               |
| `ip_ranges_refresh` | `<time>`             | How often to re-fetch the feeds (e.g. `12h`).                 |
| `fcrdns_suffix`     | `<suffix> …`         | Allowed reverse-DNS suffixes (matched on a DNS **label boundary**). |
| `fcrdns_ttl`        | `<time>`             | How long to cache an FCrDNS verdict per IP.                   |

A verifier passes a client if its IP is in the merged ranges **or** FCrDNS
confirms it. Both are cache-backed; the request hot path never makes a network
or DNS call. Refreshers run per worker (`init_process`). Define multiple blocks
with different names for different bot classes.

`fcrdns_suffix` matches on a **DNS label boundary**, so `googlebot.com` accepts
`crawl-1.googlebot.com` but rejects the look-alike `evilgooglebot.com`. A leading
dot is optional (`.googlebot.com` and `googlebot.com` behave identically). FCrDNS
still requires the forward lookup of the PTR name to resolve back to the same IP,
so a matching suffix alone is never sufficient.

---

## Inheritance & how `off` wins

`pow_gate`, `pow_gate_page`, and `pow_gate_difficulty` inherit from `http` →
`server` → `location` using nginx's standard merge. The interesting case:

```nginx
server {
    pow_gate on;                              # default for the whole server
    location / { proxy_pass http://backend; } #  → inherits ON
    location = /robots.txt {                  #  → explicit OFF wins
        pow_gate off;
        proxy_pass http://backend;
    }
}
```

This works because `create_location_conf` marks `enabled` as `NGX_CONF_UNSET` and
`merge_location_conf` calls `ngx_conf_merge_value` — set-here beats inherited, and the
final fallback default is `off`. `pow_gate_trusted` and `pow_gate_decision`
**do** inherit too (set them once at `server` and every location picks them up;
override in a specific location if needed) — they're valid in `server` and
`location`.

---

## Recipes

**Protect everything, exclude well-known paths:**

```nginx
server {
    # set once at server level — every location inherits it
    pow_gate          on;
    pow_gate_trusted  $pow_trusted;
    pow_gate_decision $pow_decision;

    location /               { proxy_pass http://backend; }   # inherits: gated
    location = /robots.txt   { pow_gate off; proxy_pass http://backend; }
    location = /favicon.ico  { pow_gate off; proxy_pass http://backend; }
    location ^~ /.well-known/ { pow_gate off; proxy_pass http://backend; }
}
```

Because `pow_gate`, `pow_gate_trusted`, and `pow_gate_decision` now inherit, you
declare them once on the `server` and only flip `pow_gate off;` on the
exceptions — no repetition.

**Credentialed API — gate off, upstream validates the key:**

```nginx
location ^~ /api/ { pow_gate off; proxy_pass http://backend; }
```

**Behind a load balancer — fix the client IP first (or `geo`/verifiers see the LB):**

```nginx
set_real_ip_from 10.0.0.0/8;
real_ip_header   X-Forwarded-For;
```

**Harder gate for a hot path, softer elsewhere:**

```nginx
location /        { pow_gate on; pow_gate_difficulty 50000;  pow_gate_decision $pow_decision; }
location /search/ { pow_gate on; pow_gate_difficulty 200000; pow_gate_decision $pow_decision; }
```

---

## Tuning `pow_gate_difficulty`

`N` is the expected hash count. Rough intuition (SHA-256 in WebCrypto, modern laptop
≈ a few hundred k hashes/s, much less on low-end phones):

| `N`        | ~Human wait      | Use when                                         |
| ---------- | ---------------- | ------------------------------------------------ |
| `10000`    | barely noticeable | light deterrence, very latency-sensitive pages   |
| `50000`    | ~0.1–0.5 s        | sensible default                                 |
| `200000`   | ~0.5–2 s          | aggressive scraping, you accept some human delay |
| `1000000+` | several seconds   | targeted abuse; expect complaints from slow devices |

Pick the smallest `N` that meaningfully taxes a scraping farm. Cost is linear in
`N` for the attacker *and* the honest visitor — there's no free lunch, so combine
with `limit_req` rather than cranking difficulty to extremes.

---

## Common mistakes

- **No `set_real_ip_from` behind a proxy** → `geo`/verifiers match the load
  balancer's IP, so everyone looks trusted or nobody does. Configure realip.
- **Gating `/.well-known/` or ACME paths** → breaks cert issuance/renewal.
  Exclude them.
- **World-readable HMAC key** → anyone who reads it forges clearances. `chmod 600`.
- **HMAC key the worker can't read** → with `chmod 600` owned by `root`, an
  unprivileged nginx worker can't read it and the gate **fails closed** (clients
  stuck on the challenge, `/.pow/` returns `503`). `chown nginx:nginx` the key so
  the worker user owns it. Missing/short key now makes `nginx -t` fail outright.
- **`pow_gate_proof_skew` too low** → clients with skewed clocks fail forever.
  `5s`–`30s` is reasonable.
- **Expecting non-JS clients to pass a challenge** → they can't. `allow` or
  exclude feeds, monitors, and other scripted-but-legitimate consumers.
- **Different `pow_gate_hmac_key_file` / `pow_gate_endpoint` on the issuing vs.
  gated location** → clearances won't validate. Set them at `http` and let them
  inherit unless you deliberately want per-vhost isolation.
