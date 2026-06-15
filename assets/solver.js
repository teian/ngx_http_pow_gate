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
 *   4. POST {endpoint}verify { salt, exp, token, nonce, pubkey } → Set-Cookie
 *   5. location.reload() into the now-cleared origin
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

  var el = document.currentScript;
  var ENDPOINT = (el && el.dataset.endpoint) || "/.pow/";
  var DIFFICULTY = parseInt((el && el.dataset.difficulty) || "50000", 10);

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

  function below(hash, target) {
    for (var i = 0; i < 32; i++) {
      if (hash[i] !== target[i]) return hash[i] < target[i];
    }
    return false;
  }

  var enc = new TextEncoder();
  async function sha256(str) {
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

  // ───────────────────────────────── main ─────────────────────────────────────
  async function run() {
    try {
      status(tr("preparing", "Preparing…"));
      var kp = await getKeypair();

      status(tr("requesting", "Requesting challenge…"));
      var ch = await fetch(ENDPOINT + "challenge", { credentials: "same-origin" })
        .then(function (r) { return r.json(); });

      status(tr("verifying", "Verifying…"));
      var difficulty = ch.difficulty || DIFFICULTY;
      var nonce = await solve(ch.salt, difficulty, percent);

      var res = await fetch(ENDPOINT + "verify", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          salt: ch.salt, exp: ch.exp, token: ch.token,
          nonce: nonce, pubkey: b64url(kp.pubRaw),
        }),
      });
      if (!res.ok) throw new Error("verify rejected: " + res.status);

      installProofFetch(kp.privateKey);
      status(tr("done", "Done"));
      percent(100);
      location.reload();
    } catch (e) {
      console.error("[pow]", e);
      fail();
    }
  }

  // Chunked search so the UI thread can paint progress between batches.
  async function solve(salt, difficulty, onProgress) {
    var target = difficultyToTarget(difficulty);
    var nonce = 0;
    var batch = 500;
    while (true) {
      for (var i = 0; i < batch; i++) {
        if (below(await sha256(salt + nonce), target)) return nonce;
        nonce++;
      }
      onProgress(Math.min(99, (nonce / difficulty) * 100));
      await new Promise(function (r) { setTimeout(r, 0); });
    }
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", run);
  else run();
})();
