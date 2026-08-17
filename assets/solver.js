/*
 * solver.js — the browser side of the PoW gate. Served by the module at
 * {endpoint}solver.js and loaded by the challenge page.
 *
 * Reads its config from the <script> data-attributes:
 *     <script src="/.pow/solver.js" data-difficulty="50000" data-endpoint="/.pow/">
 *
 * Flow (matches ../core and ../docs/protocol.md):
 *   1. generate an ECDSA P-256 keypair (non-extractable private key, stored in
 *      IndexedDB so it survives the reload and can sign per-request proofs)
 *   2. GET  {endpoint}challenge        → { salt, exp, difficulty, token }
 *   3. find nonce: SHA-256(utf8(salt + nonce)) < target,  target = 2^256/difficulty
 *      — parallel across Web Workers (one per core, striding the nonce space),
 *      falling back to a single-threaded loop where workers are unavailable
 *      (CSP worker-src, file://, ancient browsers)
 *   4. POST {endpoint}verify { salt, exp, token, nonce, pubkey } → Set-Cookie
 *   5. optionally record the solve result in sessionStorage("pow-result") —
 *      OPT-IN via data-record-result / window.__POW_RECORD_RESULT__, off by
 *      default; lets a landing page display nonce/hash/solve time (the dev
 *      sandbox result page does)
 *   6. re-issue the captured request if the page carries one (see "captured
 *      request" below — this is what keeps a challenged POST alive), else
 *      location.reload() into the now-cleared origin
 *
 * Worker trick: this same file doubles as the worker script (new Worker(SRC)).
 * A worker has no `document`, takes the branch right below the shared helpers,
 * and just grinds nonces it receives via postMessage. Same-origin script, so
 * no blob: URL and no extra CSP allowance beyond script-src 'self'.
 *
 * Hashing is a pure-JS SHA-256: at 32-byte inputs the per-call overhead of
 * awaited crypto.subtle.digest dominates the actual hashing by 1-2 orders of
 * magnitude, and workers get a synchronous loop with no promise churn. A
 * startup self-test guards it — on mismatch the solver falls back to the
 * subtle-based single-threaded loop, so a broken JIT can slow us down but
 * never lock anyone out.
 *
 * After clearance it installs a fetch() wrapper that attaches the per-request
 * proof header (X-Pow-Proof) to same-origin requests. (Top-level navigations
 * can't carry custom headers — the clearance cookie gates those; the proof
 * hardens fetch/XHR. See docs/protocol.md.)
 *
 * Page hook IDs updated: #pow-status #pow-progress #pow-percent #pow-error.
 * Status strings are localized via window.__POW_I18N__ (set by the page).
 */
(function () {
  "use strict";

  // ─────────────────── shared (page + worker): SHA-256 ────────────────────
  // Pure-JS SHA-256 over an ASCII string (salt is base64url, nonce is decimal
  // digits — never anything outside 0x00-0x7f). Scratch buffers are reused;
  // the returned Uint8Array is valid only until the next call.
  var SHA_K = new Int32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  var shaBuf = new Uint8Array(128);
  var shaW = new Int32Array(64);
  var shaOut = new Uint8Array(32);

  function sha256Str(msg) {
    var len = msg.length;
    var total = ((len + 9 + 63) >> 6) << 6;
    if (total > shaBuf.length) shaBuf = new Uint8Array(total);
    var b = shaBuf;
    b.fill(0, 0, total);
    for (var i = 0; i < len; i++) b[i] = msg.charCodeAt(i);
    b[len] = 0x80;
    var bits = len * 8;
    b[total - 4] = (bits >>> 24) & 255;
    b[total - 3] = (bits >>> 16) & 255;
    b[total - 2] = (bits >>> 8) & 255;
    b[total - 1] = bits & 255;

    var h0 = 0x6a09e667 | 0, h1 = 0xbb67ae85 | 0, h2 = 0x3c6ef372 | 0, h3 = 0xa54ff53a | 0;
    var h4 = 0x510e527f | 0, h5 = 0x9b05688c | 0, h6 = 0x1f83d9ab | 0, h7 = 0x5be0cd19 | 0;
    var w = shaW;

    for (var off = 0; off < total; off += 64) {
      for (i = 0; i < 16; i++) {
        var j = off + (i << 2);
        w[i] = (b[j] << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3];
      }
      for (i = 16; i < 64; i++) {
        var x = w[i - 15], y = w[i - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[i] = (((w[i - 16] + s0) | 0) + ((w[i - 7] + s1) | 0)) | 0;
      }
      var a = h0, bb = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
      for (i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (((((hh + S1) | 0) + ((ch + SHA_K[i]) | 0)) | 0) + w[i]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & bb) ^ (a & c) ^ (bb & c);
        var t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = bb; bb = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + bb) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + hh) | 0;
    }

    var o = shaOut;
    o[0] = h0 >>> 24; o[1] = (h0 >>> 16) & 255; o[2] = (h0 >>> 8) & 255; o[3] = h0 & 255;
    o[4] = h1 >>> 24; o[5] = (h1 >>> 16) & 255; o[6] = (h1 >>> 8) & 255; o[7] = h1 & 255;
    o[8] = h2 >>> 24; o[9] = (h2 >>> 16) & 255; o[10] = (h2 >>> 8) & 255; o[11] = h2 & 255;
    o[12] = h3 >>> 24; o[13] = (h3 >>> 16) & 255; o[14] = (h3 >>> 8) & 255; o[15] = h3 & 255;
    o[16] = h4 >>> 24; o[17] = (h4 >>> 16) & 255; o[18] = (h4 >>> 8) & 255; o[19] = h4 & 255;
    o[20] = h5 >>> 24; o[21] = (h5 >>> 16) & 255; o[22] = (h5 >>> 8) & 255; o[23] = h5 & 255;
    o[24] = h6 >>> 24; o[25] = (h6 >>> 16) & 255; o[26] = (h6 >>> 8) & 255; o[27] = h6 & 255;
    o[28] = h7 >>> 24; o[29] = (h7 >>> 16) & 255; o[30] = (h7 >>> 8) & 255; o[31] = h7 & 255;
    return o;
  }

  function below(hash, target) {
    for (var i = 0; i < 32; i++) {
      if (hash[i] !== target[i]) return hash[i] < target[i];
    }
    return false;
  }

  // NIST vectors: one-block ("abc") and two-block (56-char) message. Guards
  // the hand-rolled hasher above; on mismatch the page falls back to the
  // crypto.subtle loop and never spawns workers.
  function shaSelfTest() {
    var hex = function (u8) {
      var s = "";
      for (var i = 0; i < u8.length; i++) s += (u8[i] < 16 ? "0" : "") + u8[i].toString(16);
      return s;
    };
    return (
      hex(sha256Str("abc")) ===
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" &&
      hex(sha256Str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ===
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
  }
  var PUREJS = shaSelfTest();

  // ───────────────────────────── worker mode ──────────────────────────────
  // Loaded via new Worker({endpoint}solver.js): no document, just grind.
  // Message in:  { salt, target: Uint8Array(32), start, stride, every }
  // Messages out: { h: N } every N hashes (progress) · { n: nonce } on success
  //               · { e: 1 } if the pure-JS hasher failed its self-test here
  if (typeof document === "undefined") {
    self.onmessage = function (ev) {
      var m = ev.data || {};
      if (!PUREJS) { self.postMessage({ e: 1 }); return; }
      var salt = m.salt, target = m.target, stride = m.stride, every = m.every;
      var nonce = m.start, count = 0;
      for (;;) {
        if (below(sha256Str(salt + nonce), target)) { self.postMessage({ n: nonce }); return; }
        nonce += stride;
        if (++count === every) { self.postMessage({ h: count }); count = 0; }
      }
    };
    return;
  }

  // ───────────────────────────── page mode ────────────────────────────────
  var el = document.currentScript;
  var SRC = (el && el.src) || "";
  var ENDPOINT = (el && el.dataset.endpoint) || "/.pow/";
  var DIFFICULTY = parseInt((el && el.dataset.difficulty) || "50000", 10);
  // Solve-result recording (sessionStorage "pow-result") is OPT-IN — off by
  // default because normal deployments have no consumer for it. Enable via
  // `data-record-result` on this script tag (test setups serve a page copy
  // with it — the dev sandbox generates docker/challenge.dev.html) or, for
  // pages that decide at runtime, `window.__POW_RECORD_RESULT__ = true`.
  var RECORD_RESULT = !!(
    (el && el.dataset.recordResult != null && el.dataset.recordResult !== "off") ||
    window.__POW_RECORD_RESULT__ === true
  );

  var I18N = (typeof window !== "undefined" && window.__POW_I18N__) || {};
  var tr = function (k, fallback) { return I18N[k] || fallback; };

  var $ = function (id) { return document.getElementById(id); };
  var status = function (t) { var n = $("pow-status"); if (n) n.textContent = t; };
  var percent = function (p) {
    var bar = $("pow-progress");
    if (bar) { ("value" in bar) ? (bar.value = p) : (bar.style.width = p + "%"); }
    var num = $("pow-percent"); if (num) num.textContent = String(Math.floor(p));
  };
  var fail = function () { var n = $("pow-error"); if (n) n.style.display = "block"; };

  // ───────────────────────── byte / base64url helpers ─────────────────────────
  function b64url(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // target = floor(2^256 / difficulty) as 32 big-endian bytes.
  function difficultyToTarget(difficulty) {
    var t = new Uint8Array(32);
    if (difficulty <= 1) { t.fill(0xff); return t; }
    var q = (1n << 256n) / BigInt(difficulty);
    for (var i = 31; i >= 0; i--) { t[i] = Number(q & 0xffn); q >>= 8n; }
    return t;
  }

  var enc = new TextEncoder();
  async function sha256Subtle(str) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(str)));
  }

  // ───────────────────────── keypair (persisted) ──────────────────────────────
  var DB = "pow-gate", STORE = "keys", KEYID = "proof-key";

  function idb() {
    return new Promise(function (res, rej) {
      var r = indexedDB.open(DB, 1);
      r.onupgradeneeded = function () { r.result.createObjectStore(STORE); };
      r.onsuccess = function () { res(r.result); };
      r.onerror = function () { rej(r.error); };
    });
  }
  function idbGet(db, key) {
    return new Promise(function (res) {
      var t = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
      t.onsuccess = function () { res(t.result); }; t.onerror = function () { res(null); };
    });
  }
  function idbPut(db, key, val) {
    return new Promise(function (res) {
      var t = db.transaction(STORE, "readwrite").objectStore(STORE).put(val, key);
      t.onsuccess = function () { res(true); }; t.onerror = function () { res(false); };
    });
  }

  // Returns { privateKey: CryptoKey, pubRaw: Uint8Array(65) }, reusing a stored
  // non-extractable key if present.
  async function getKeypair() {
    var db = null;
    try { db = await idb(); } catch (e) { /* private mode: fall back to ephemeral */ }
    if (db) {
      var saved = await idbGet(db, KEYID);
      if (saved && saved.privateKey && saved.pubRaw) {
        return { privateKey: saved.privateKey, pubRaw: new Uint8Array(saved.pubRaw) };
      }
    }
    var pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    var pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    if (db) await idbPut(db, KEYID, { privateKey: pair.privateKey, pubRaw: pubRaw });
    return { privateKey: pair.privateKey, pubRaw: pubRaw };
  }

  // ───────────────────────── per-request proof (fetch) ────────────────────────
  // WebCrypto ECDSA(P-256, SHA-256) emits raw r‖s (64 bytes) — exactly what the
  // server's p256 verifier expects.
  async function signProof(privateKey, method, path) {
    var ts = Math.floor(Date.now() / 1000);
    var msg = method + " " + path + " " + ts;
    var sig = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, privateKey, enc.encode(msg)));
    return b64url(sig) + "." + ts;
  }

  function installProofFetch(privateKey) {
    var orig = window.fetch;
    window.fetch = async function (input, init) {
      init = init || {};
      try {
        var url = new URL((typeof input === "string" ? input : input.url), location.href);
        if (url.origin === location.origin) {
          var method = (init.method || (typeof input !== "string" && input.method) || "GET").toUpperCase();
          var headers = new Headers(init.headers || (typeof input !== "string" && input.headers) || {});
          headers.set("X-Pow-Proof", await signProof(privateKey, method, url.pathname));
          init.headers = headers;
        }
      } catch (e) { /* never block a request because proofing failed */ }
      return orig.call(this, input, init);
    };
  }

  // ─────────────────────── captured request (replay) ──────────────────────────
  // A POST — or any other request that carried data — would be lost to the
  // reload below, so the module captures it into this page (pow_gate_replay) as
  //   <script id="pow-replay" type="application/json">
  //   {"method":"POST","url":"/order","type":"<content-type>","body":"<base64url>"}
  // and we re-issue it here, once the clearance cookie is set. Absent tag →
  // nothing was captured (a GET, replay off, body too large) → plain reload.
  function readReplay() {
    var n = document.getElementById("pow-replay");
    if (!n) return null;
    try {
      var rq = JSON.parse(n.textContent);
      return rq && rq.method && rq.url ? rq : null;
    } catch (e) { return null; }
  }

  function unb64url(s) {
    s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // Form-encoded bodies go back as a real form submit: the browser then owns
  // redirects, history, rendering and downloads exactly as it would have for
  // the original submit. Re-encoding is byte-identical for UTF-8 forms, which
  // is all a browser produces.
  function replayAsForm(rq, bytes) {
    var f = document.createElement("form");
    f.setAttribute("method", "post");
    f.setAttribute("action", rq.url);
    f.setAttribute("enctype", "application/x-www-form-urlencoded");
    f.setAttribute("accept-charset", "utf-8");
    f.style.display = "none";
    new URLSearchParams(new TextDecoder().decode(bytes)).forEach(function (v, k) {
      var i = document.createElement("input");
      i.setAttribute("type", "hidden");
      i.setAttribute("name", k);
      i.setAttribute("value", v);
      f.appendChild(i);
    });
    document.body.appendChild(f);
    // A field named "submit" would shadow the form's own method, so call the
    // prototype's.
    HTMLFormElement.prototype.submit.call(f);
  }

  // Everything else (multipart uploads, JSON, and every method a form cannot
  // express — PUT, PATCH, DELETE, PROPFIND, …) goes back
  // byte-for-byte through fetch — which also carries the per-request proof,
  // since installProofFetch() has wrapped it by now. The address bar already
  // shows the original URL (this page WAS the answer to that request), so
  // writing the response document out lands the user where they expected.
  async function replayAsFetch(rq, bytes) {
    var res = await fetch(rq.url, {
      method: rq.method,
      headers: rq.type ? { "Content-Type": rq.type } : {},
      body: bytes.length ? bytes : undefined,
      credentials: "same-origin",
    });
    if (res.redirected && res.url) { location.replace(res.url); return; }
    var text = await res.text();
    var html = /html/i.test(res.headers.get("Content-Type") || "")
      ? text
      : "<pre>" + text.replace(/&/g, "&amp;").replace(/</g, "&lt;") + "</pre>";
    document.open(); document.write(html); document.close();
  }

  async function replay(rq) {
    var bytes = unb64url(rq.body);
    var form = /^application\/x-www-form-urlencoded\b/i.test(rq.type || "");
    if (form && rq.method.toUpperCase() === "POST") return replayAsForm(rq, bytes);
    return replayAsFetch(rq, bytes);
  }

  // ───────────────────────────────── main ─────────────────────────────────────
  // Solve+verify attempt. The challenge token is only valid for a short grace
  // window (server-side, ~2 min): a slow device or a background tab can run
  // past it, in which case /verify rejects with 4xx and we must fetch a fresh
  // challenge and try again — NOT dead-end into the error box.
  async function attempt(kp) {
    status(tr("requesting", "Requesting challenge…"));
    var ch = await fetch(ENDPOINT + "challenge", { credentials: "same-origin" })
      .then(function (r) { return r.json(); });

    status(tr("verifying", "Verifying…"));
    var difficulty = ch.difficulty || DIFFICULTY;
    var t0 = performance.now();
    var nonce = await solve(ch.salt, difficulty, percent);
    var solveMs = Math.round(performance.now() - t0);

    var res = await fetch(ENDPOINT + "verify", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        salt: ch.salt, exp: ch.exp, token: ch.token,
        nonce: nonce, pubkey: b64url(kp.pubRaw),
        // echoed but HMAC-bound by `token` — the server holds us to exactly
        // the difficulty it issued (per-decision overrides, challenge:<N>)
        difficulty: difficulty,
      }),
    });
    if (res.ok && RECORD_RESULT) recordResult(ch.salt, difficulty, nonce, solveMs);
    return res.ok;
  }

  // Leave the solve result behind for the page the post-clearance reload lands
  // on (e.g. the dev-sandbox backend renders nonce, winning hash and solve
  // time from it — see docker/www/index.html). Same-origin sessionStorage,
  // gone with the tab. Purely informational: a storage failure (private mode,
  // quota) must never break the clearance flow. Only runs when RECORD_RESULT
  // opted in (see above).
  function recordResult(salt, difficulty, nonce, solveMs) {
    try {
      sessionStorage.setItem("pow-result", JSON.stringify({
        salt: salt, difficulty: difficulty, nonce: nonce,
        solveMs: solveMs, finishedAt: new Date().toISOString(),
      }));
    } catch (e) { /* informational only */ }
  }

  var RETRIES = 3;
  async function run() {
    try {
      status(tr("preparing", "Preparing…"));
      var kp = await getKeypair();

      var ok = false;
      for (var i = 0; i < RETRIES && !ok; i++) {
        if (i > 0) percent(0);
        ok = await attempt(kp);
      }
      if (!ok) throw new Error("verify rejected " + RETRIES + " times");

      installProofFetch(kp.privateKey);
      status(tr("done", "Done"));
      percent(100);

      // Re-issue the captured request if there was one; a failure there must
      // still land the (now cleared) client on the page, so fall back to the
      // reload rather than into the error box.
      var rq = readReplay();
      if (rq) {
        status(tr("resending", "Resending your request…"));
        try { await replay(rq); return; }
        catch (e) { console.error("[pow] replay", e); }
      }
      location.reload();
    } catch (e) {
      console.error("[pow]", e);
      fail();
    }
  }

  // Yield to the event loop without setTimeout: background tabs clamp timers
  // to >= 1s, which would stretch the solve past the challenge grace window.
  // MessageChannel posts are not throttled by tab visibility.
  var yieldChannel = typeof MessageChannel !== "undefined" ? new MessageChannel() : null;
  function yieldNow() {
    if (!yieldChannel) return new Promise(function (r) { setTimeout(r, 0); });
    return new Promise(function (r) {
      yieldChannel.port1.onmessage = function () { r(); };
      yieldChannel.port2.postMessage(null);
    });
  }

  // Progress = P(solution found by now) = 1 - (1-1/d)^n ≈ 1 - e^(-n/d).
  // A linear n/d estimate parks at 99% for the ~37% of solves that need more
  // than `difficulty` hashes (the search is memoryless); the CDF keeps the bar
  // moving for the whole solve instead.
  function cdfPercent(hashes, difficulty) {
    return 99 * (1 - Math.exp(-hashes / difficulty));
  }

  // One worker per core (capped), each striding the nonce space: worker i
  // tries i, i+W, i+2W, … First hit wins; everyone else is terminated. Any
  // full-crew failure (CSP worker-src, spawn error, self-test) rejects and
  // the caller falls back to the in-page loop.
  function solveParallel(salt, target, difficulty, onProgress) {
    return new Promise(function (resolve, reject) {
      var W = Math.min(navigator.hardwareConcurrency || 4, 8);
      // Progress granularity: ~50 updates per expected solve, bounded so slow
      // devices still see movement and fast ones don't flood the channel.
      var every = Math.max(256, Math.min(65536, (difficulty / 50) | 0));
      var workers = [], total = 0, failed = 0, settled = false;

      var finish = function (fn, arg) {
        if (settled) return;
        settled = true;
        for (var k = 0; k < workers.length; k++) workers[k].terminate();
        fn(arg);
      };
      var oneFailed = function () {
        if (++failed >= W) finish(reject, new Error("all workers failed"));
      };

      for (var i = 0; i < W; i++) {
        var w;
        try { w = new Worker(SRC); }
        catch (e) { finish(reject, e); return; }
        w.onmessage = function (ev) {
          var m = ev.data || {};
          if (m.n != null) finish(resolve, m.n);
          else if (m.h) { total += m.h; onProgress(cdfPercent(total, difficulty)); }
          else if (m.e) oneFailed();
        };
        w.onerror = oneFailed;
        w.postMessage({ salt: salt, target: target, start: i, stride: W, every: every });
        workers.push(w);
      }
    });
  }

  // In-page fallback, chunked so the UI thread can paint progress between
  // batches. Uses the pure-JS hasher when it passed its self-test, else the
  // (much slower, but battle-tested) crypto.subtle path.
  async function solveSequential(salt, target, difficulty, onProgress) {
    var nonce = 0;
    var batch = PUREJS ? 4096 : 500;
    while (true) {
      for (var i = 0; i < batch; i++) {
        var h = PUREJS ? sha256Str(salt + nonce) : await sha256Subtle(salt + nonce);
        if (below(h, target)) return nonce;
        nonce++;
      }
      onProgress(cdfPercent(nonce, difficulty));
      await yieldNow();
    }
  }

  async function solve(salt, difficulty, onProgress) {
    var target = difficultyToTarget(difficulty);
    if (PUREJS && SRC && typeof Worker !== "undefined") {
      try { return await solveParallel(salt, target, difficulty, onProgress); }
      catch (e) { /* workers unavailable (CSP, spawn failure) — fall back */ }
    }
    return solveSequential(salt, target, difficulty, onProgress);
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", run);
  else run();
})();
