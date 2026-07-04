# Troubleshooting

Field-debugging guide: symptoms as they actually present in the browser and on
the wire, what they mean, and the fastest way to confirm the cause. Build and
install problems (`nginx -t` failures, ABI mismatches) are in
[build.md](build.md#troubleshooting); challenge-page pitfalls in
[challenge-page.md](challenge-page.md).

---

## Page loads, but every asset fails (CSS/JS/images broken)

**Seen in the field (2026-07, first production deployment).** The gated site's
HTML rendered, but *every* subresource — stylesheets, scripts, images — failed.
Depending on browser/build the console showed `net::ERR_HTTP2_PROTOCOL_ERROR
200 (OK)` per asset, or MIME-type refusals and `Uncaught SyntaxError:
Unexpected token '<'` from script tags. The error strings pointed at the HTTP/2
transport; the transport was fine.

### What was actually happening

Every asset request was being answered with **the challenge page** (`200`,
`text/html`) instead of the asset. The gate demanded the per-request proof
(`X-Pow-Proof`) from every non-navigation request — but subresource loads
issued by HTML tags (`<link>`, `<script src>`, `<img>`, fonts) **can never
carry a custom header**. Only page JavaScript (`fetch`/XHR) can attach one.
So a fully cleared browser passed the gate on the navigation, then flunked it
on all of the page's assets, forever.

Two design facts to keep in mind (both encoded in
[`can_carry_proof`](../src/ngx-http-pow-gate/src/engine/clearance.rs)):

- **`Sec-Fetch-Dest: empty` is the only reliable marker** for
  "this request could have carried a custom header" (fetch/XHR).
- **`Sec-Fetch-Mode` is a trap**: fonts, `<script type="module">`, and
  preloads are `mode: cors` — same mode as fetch/XHR — yet still cannot carry
  headers. Keying the proof requirement off the mode re-breaks exactly those.

Since the fix, the proof is demanded only from `Sec-Fetch-Dest: empty`
requests, and only with `pow_gate_require_proof on` (default `off`; see
[configuration.md](configuration.md#pow_gate_require_proof-on--off)).

### How to confirm in one command

Request a broken asset directly and look at the `content-type`:

```bash
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' \
  -H 'sec-fetch-mode: no-cors' -H 'sec-fetch-dest: image' \
  -H 'cookie: pow_clearance=<paste from browser devtools>' \
  https://example.com/some/image.png
```

- `200 text/html; charset=utf-8` → the gate served the challenge page: the
  request failed clearance. Check `pow_gate_require_proof`, cookie validity,
  and whether the request could carry a proof at all.
- `200 image/png` → the gate passed it; the breakage is elsewhere
  (upstream, proxy buffering, TLS…).

The `content-length` of the challenge page is a useful fingerprint too: every
"asset" coming back with the *same* byte size is the same challenge page.

### Why the browser said "HTTP/2 protocol error"

Don't chase the transport error first. In this incident curl, an h2 client
library, and a scripted Chrome all received the challenge-page responses with
clean HTTP/2 framing — the protocol-error strings came from the client's own
state (most plausibly a pre-`v0.1.2` module build whose `/verify` handler
leaked a request reference and wedged the connection, poisoning in-flight
streams). The durable lesson: **`ERR_HTTP2_PROTOCOL_ERROR 200 (OK)` on many
same-origin subresources means "inspect what those responses contain", not
"debug HTTP/2"** — the content check above settles it in seconds.

### Related mistake: enabling `pow_gate_require_proof` without page integration

`on` only works when the site's own pages attach proofs to their `fetch`/XHR
calls (the embedded solver's wrapper exists only on the challenge page, and it
does not cover `XMLHttpRequest`, i.e. jQuery). Until such integration exists,
`on` challenges all of a site's AJAX even though static assets now pass.

---

## Solve is much slower than the difficulty table predicts

The solver normally hashes in parallel Web Workers (it loads
`{endpoint}solver.js` a second time *as* the worker script). If your site's
`Content-Security-Policy` blocks that — a `worker-src` (or fallback
`child-src`/`script-src`/`default-src`) that doesn't allow `'self'` — worker
spawning fails and the solver silently drops to its single-threaded in-page
loop: correct, but one core instead of all of them. The browser console shows
the CSP violation. Fix: allow `worker-src 'self'` (the worker is the same
same-origin file; no `blob:` needed).

The last-resort fallback (pure-JS hasher fails its startup self-test) uses
`crypto.subtle` per hash and is ~30× slower still — if you ever see that,
something is very wrong with the client's JS engine, not with the gate.
