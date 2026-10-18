#!/usr/bin/env node
// Full pow_gate handshake against a live gate, without a browser:
// challenge → brute-force nonce (SHA-256 < 2^256/difficulty) → ECDSA keypair
// → POST verify → expect clearance cookie → GET / with cookie → expect the
// backend marker. Mirrors assets/solver.js; used by `./scripts/dev.sh check`.
//
// Usage: node tests/pow-clearance/solve-test.mjs [base-url]   (default http://localhost:12222)
// Env:   POW_COOKIE_NAME  exact clearance cookie name (otherwise accepts scoped names,
//                         keep in sync with pow_gate_cookie_name)
//        POW_MARKER       string expected in the backend body
//                         (default "upstream-content", see docker/www/index.html)

const BASE = process.argv[2] ?? "http://localhost:12222";
const COOKIE_NAME = process.env.POW_COOKIE_NAME;
const MARKER = process.env.POW_MARKER ?? "upstream-content";
const die = (msg) => { console.error(`FAIL  ${msg}`); process.exit(1); };

const b64url = (bytes) =>
  Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function difficultyToTarget(difficulty) {
  const t = new Uint8Array(32);
  if (difficulty <= 1) { t.fill(0xff); return t; }
  let q = (1n << 256n) / BigInt(difficulty);
  for (let i = 31; i >= 0; i--) { t[i] = Number(q & 0xffn); q >>= 8n; }
  return t;
}
const below = (hash, target) => {
  for (let i = 0; i < 32; i++) if (hash[i] !== target[i]) return hash[i] < target[i];
  return false;
};

const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));

// 1. challenge
const ch = await (await fetch(`${BASE}/.pow/challenge`, { headers: { "X-Pow-Key": b64url(pubRaw), "User-Agent": "pow-solve-test" } })).json();
if (!ch.salt || !ch.token) die(`challenge malformed: ${JSON.stringify(ch)}`);
console.log(`ok    challenge issued (difficulty ${ch.difficulty})`);

// 2. solve
const enc = new TextEncoder();
const target = difficultyToTarget(ch.difficulty);
const t0 = Date.now();
let nonce = 0;
for (;;) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(ch.salt + nonce)));
  if (below(hash, target)) break;
  nonce++;
}
console.log(`ok    solved: nonce=${nonce} in ${Date.now() - t0} ms`);

// 3. keypair + verify
const res = await fetch(`${BASE}/.pow/verify`, {
  method: "POST",
  headers: { "Content-Type": "application/json", "User-Agent": "pow-solve-test" },
  body: JSON.stringify({ version: ch.version, signature: b64url(new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey,
      enc.encode("pow-gate-redeem-v2 " + ch.token)))), salt: ch.salt, exp: ch.exp, token: ch.token, nonce, pubkey: b64url(pubRaw), difficulty: ch.difficulty }),
});
if (!res.ok) die(`verify rejected: HTTP ${res.status}`);
// Anchored so a prefixed cookie name can't slip through as a partial match.
const setCookie = res.headers.get("set-cookie") ?? "";
const clearance = setCookie.split(";")[0];
const name = clearance.split("=")[0];
if (COOKIE_NAME ? name !== COOKIE_NAME : !/^pow_clearance(?:_[0-9a-f]{24})?$/.test(name))
  die(`unexpected clearance cookie (got: ${name || "none"})`);

console.log("ok    verify accepted, clearance cookie set");

// 4. navigation with clearance → must reach the backend.
// NOT via fetch(): undici force-sends `sec-fetch-mode: cors` (forbidden
// header, cannot be overridden), which the gate correctly treats as a
// non-navigation without proof and rejects. node:http sends only what we
// set — like a browser top-level navigation (no sec-fetch metadata).
const { request } = await import("node:http");
// Connection: close — a keep-alive agent would hold the event loop open
// and the script would never exit.
const get = (headers) =>
  new Promise((resolve, reject) => {
    const req = request(`${BASE}/`, { headers: { ...headers, "User-Agent": "pow-solve-test", Connection: "close" } }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve(data));
    });
    req.on("error", reject);
    req.end();
  });
const body = await get({ Cookie: clearance });
if (!body.includes(MARKER)) die(`backend not reached after clearance; got: ${body.slice(0, 120)}`);
console.log("ok    backend reached with clearance cookie");

// 5. without cookie must still be challenged
const unauth = await get({});
if (unauth.includes(MARKER)) die("gate let an uncleared request through");
console.log("ok    uncleared request still challenged");

console.log("PASS  full pow handshake works");
// undici's global agent may keep pooled sockets alive — exit explicitly.
process.exit(0);
