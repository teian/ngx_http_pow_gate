# Protocol v2: the `/.pow/` endpoints

The embedded solver and module must be upgraded together. V1 challenges and
clearance cookies are rejected. Documented solver template URLs receive a
module-version query during rendering to bypass cached legacy solvers. All PoW keys use canonical 65-byte uncompressed
SEC1 P-256 encoding; signatures are WebCrypto's 64-byte raw `r || s` ECDSA/SHA-256.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `{endpoint}challenge` | Issue a key-bound challenge |
| GET / HEAD | `{endpoint}solver.js` | Embedded protocol client |
| POST | `{endpoint}verify` | Authenticate and atomically redeem a solution |
| GET | `{endpoint}pass` | Atomically redeem a no-JS grant |

Unsupported methods return 405. Endpoints must resolve to the same policy and
configuration as the protected content. For a different location's difficulty,
configure a matching endpoint inside that location (for example
`pow_gate_endpoint /search/.pow/;` on `/search/`). A weaker endpoint cannot mint a
clearance that satisfies the stronger location.

## GET {endpoint}challenge

Generate/load the client's keypair first. Send its public key in
`X-Pow-Key: <base64url SEC1>`. Missing/malformed keys return 400.

Response: `200 application/json`, `Cache-Control: no-store`:

```json
{
  "version": 2,
  "salt": "random-16-byte-hex",
  "exp": 1792302000,
  "difficulty": 500000,
  "token": "base64url-authentication-tag"
}
```

The HMAC covers the domain-separated JSON tuple:
`("pow-gate-challenge-v2", salt, exp, difficulty, base64url(public_key), context)`.
The context streams length-prefixed fields into an HMAC: canonical client
address/network, exact User-Agent,
address-prefix policy, cookie domain (or normalized request host), cookie name,
cookie path, endpoint, `pow_gate_policy`, and the shared replay store's issuer ID.
Raw addresses and User-Agents are not embedded in tokens.

Find `nonce` such that `SHA256(utf8(salt) || utf8(decimal_nonce))` is below
`floor(2^256 / difficulty)`. Challenges expire after 120 seconds. Expiry prevents
long-term precomputation, but cannot prevent a client outsourcing computation.

## POST {endpoint}verify

Send JSON (maximum 8192 bytes):

```json
{
  "version": 2,
  "salt": "from-challenge",
  "exp": 1792302000,
  "difficulty": 500000,
  "token": "from-challenge",
  "nonce": 12345,
  "pubkey": "base64url-public-key-committed-at-issuance",
  "signature": "base64url-raw-ecdsa-signature"
}
```

Sign the exact UTF-8 string `pow-gate-redeem-v2 <token>` with the committed
private key. All fields are required. Verification checks version, public key,
current client/policy context, exact current issuing difficulty, HMAC, expiry,
PoW and key possession. Only then does it atomically consume the challenge token.
The ledger key excludes the solution nonce: another valid nonce cannot redeem
that challenge again. Invalid submissions never consume a valid challenge.

| Outcome | Status |
| --- | --- |
| Accepted; clearance in Set-Cookie | 204 |
| Invalid key, signature, binding, token, solution or expiry | 400 |
| Challenge already redeemed | 409 |
| Body exceeds 8192 bytes (declared or streamed) | 413 |
| Signing key/store unavailable or replay table saturated | 503 |

A request-body filter rejects oversized decoded chunks before nginx buffers or
spools them. A second bounded collector protects the JSON parsing buffer.
Verification responses that mint cookies carry `Cache-Control: no-store`.

## GET {endpoint}pass

No-JS grants bind a random ID, context, version 2, return path, issue time and
minimum wait using the separate `nojs-v2|` HMAC domain. They expire after 120
seconds. Redemption requires the current no-JS policy/delay, matching client
context and an unused token. Too-early requests receive a fresh wait page;
accepted requests set a bound no-JS clearance and redirect to the signed return
path. Reuse returns 409. A no-JS clearance never satisfies a PoW policy.

## The captured request (`pow-replay`)

Not an endpoint — a block the module injects into the challenge page when the
challenged request carried a body (`pow_gate_replay`, default on). It is how a
form `POST` survives a challenge: the request comes back to the client that
sent it, and the solver re-issues it after `/verify` succeeds.

Injected immediately before the page's closing `</body>`:

```html
<script id="pow-replay" type="application/json">
{"method":"POST","url":"/order?ref=mail","type":"application/x-www-form-urlencoded","body":"cXR5PTI"}
</script>
```

| Field    | Type   | Meaning                                                        |
| -------- | ------ | -------------------------------------------------------------- |
| `method` | string | The original method, verbatim (case-sensitive). Any data-carrying verb — `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `PROPFIND`, … — but never `GET`/`HEAD`/`TRACE`/`CONNECT` |
| `url`    | string | The original request target, verbatim: an absolute same-site path with its query string, still percent-encoded |
| `type`   | string | The original `Content-Type` (may be empty)                      |
| `body`   | string | The original body, base64url, no padding                        |

Response headers: `Cache-Control: no-store` — the page carries request data.

Client contract (`assets/solver.js`):

1. after the clearance cookie is set, read the block; absent → plain
   `location.reload()`, nothing was captured;
2. `application/x-www-form-urlencoded` + `POST` → rebuild a hidden `<form>` and
   submit it, so the browser owns redirects, history and rendering exactly as it
   would have for the original submit;
3. anything else → `fetch` the raw bytes back with the original `Content-Type`,
   then follow `res.redirected` or write the returned document out.

`<`, `>` and `&` are emitted as `\uXXXX` escapes, so the JSON can never close
its own `<script>` block; `url` is rejected unless it is an absolute same-site
path free of quotes, angle brackets and control bytes. The payload is **not**
signed — it never leaves the client that produced it, and a client that edits it
merely sends a different request of its own, which a cleared client may do
anyway. See [`core/replay.rs`](../src/pow-gate-core/src/replay.rs).

---

## Clearance cookies

The cookie value is `base64url(JSON) + "." + base64url(tag)`, where the tag is
`HMAC-SHA256(key, "pow-gate-clearance-v2|" + base64url(JSON))`.

| Field | Meaning |
| --- | --- |
| version | Exactly 2 |
| pk | Committed public key; empty only for no-JS grants |
| context | Opaque client/policy/store binding |
| assurance | `{ "kind": "pow", "difficulty": N }` or `{ "kind": "no_js", "delay": S }` |
| iat, exp | Issued-at and expiry, in Unix seconds |

A clearance must match the current context and assurance type, and meet or exceed
the current difficulty/delay. Its issue time cannot be in the future. Both its
embedded expiry and the location's current `pow_gate_clearance_ttl` are enforced,
so reducing TTL also restricts existing cookies. Changing `pow_gate_policy`
invalidates existing clearances for that scope.

## Per-request proofs and limits

`X-Pow-Proof: <base64url-signature>.<unix-seconds>` signs the exact UTF-8 message
`<METHOD> <nginx-normalized-path> <unix-seconds>`. Present proofs are always
verified against the clearance's public key and `pow_gate_proof_skew`.

With `pow_gate_require_proof on`, absent proofs fail for fetch/XHR
(`Sec-Fetch-Dest: empty`). Navigations/tag loads still use the context-bound
cookie, because browsers cannot attach arbitrary headers to those loads.
Fetch metadata is client-controlled outside browsers: this option is not a
universal key-possession guarantee. Clients sharing an allowed address/network
and User-Agent can still copy bearer cookies; cooperating clients can also share
private keys. PoW and rate limiting remain necessary.

## Worker coordination and deployment

A fixed 2 MiB nginx shared-memory zone stores at most 32,768 live challenge
redemptions. It uses the nginx process-shared mutex, checks at most 64 slots per
operation, reuses expired slots and never evicts a live entry. Saturation returns
503, including when a probe window fills before the theoretical slot limit.
Both JS and no-JS redemption use this ledger. No per-client heap table grows in
workers. Graceful reloads preserve the zone, issuer identity, spent challenges
and cookies. Full restarts generate a fresh issuer, invalidating old tokens.
Independent nginx instances have different issuers and reject each other's
tokens even with the same HMAC key. The optional [Redis backend](redis.md) uses
an explicitly provisioned namespace/epoch and an authoritative consume-once ledger
to coordinate separate nginx instances. It does not allocate the local zone.


## Browser clearance confirmation

`GET {endpoint}status` returns 204 when the currently sent clearance and optional
request proof satisfy the endpoint's policy, or 409 otherwise. It never consumes
a challenge or mints a cookie. The solver signs this request when confirming a
PoW clearance. All protocol responses, including rejections,
carry `Cache-Control: no-store`.

Protocol v2 token formats are unchanged in 0.5.0. Scoped cookie names require one
fresh solve on upgrade. With Redis enabled, the namespace/epoch identify the
issuer across nginx instances; switching backend or epoch invalidates existing
credentials. [Redis coordination](redis.md) defines distributed redemption.

The rendered solver URL includes the package version and a SHA-256 fingerprint
of its contents. Only that exact URL has `Cache-Control: public,
max-age=31536000, immutable`, allowing the page and its workers to share the
static script. Unversioned, obsolete or modified queries return the current
script with `no-store`. Challenges, verification/status/pass responses and
challenge pages remain `no-store`; the cached script contains no client state.
