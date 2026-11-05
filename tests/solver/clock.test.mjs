// Unit tests for the solver's server-anchored clock and proof-fetch retry.
// Run: node --test tests/solver/
//
// The region between `@clock-begin` and `@clock-end` in assets/solver.js is
// evaluated against a mocked browser (controllable Date.now/performance.now,
// scripted fetch), so no browser or nginx is needed.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, "../../assets/solver.js"), "utf8");
const begin = source.indexOf("// @clock-begin");
const end = source.indexOf("// @clock-end");
assert.ok(begin > 0 && end > begin, "clock markers present in solver.js");
const region = source.slice(begin, end);

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");

/**
 * Build an isolated instance. `wall` is the device clock (ms), `mono` the
 * monotonic timer (ms); both are driven by the test.
 */
function harness({ deviceOffsetSec = 0, serverNow = 1_800_000_000 } = {}) {
  const t = {
    server: serverNow,                       // true server time, seconds
    wall: (serverNow + deviceOffsetSec) * 1000,
    mono: 1000,
    listeners: [],
    fetches: [],
    script: [],                              // queued fetch responses
  };
  const advance = (ms, { wallToo = true } = {}) => {
    t.mono += ms;
    t.server += ms / 1000;
    if (wallToo) t.wall += ms;
  };
  const els = { "pow-clock": { hidden: true, textContent: "" } };
  const sandbox = {
    $: (id) => els[id] || null,
    tr: (_k, fallback) => fallback,
    ENDPOINT: "/.pow/",
    window: {},
    document: {
      visibilityState: "visible",
      addEventListener: (type, fn) => t.listeners.push([type, fn]),
    },
    location: { href: "https://example.test/", origin: "https://example.test" },
    performance: { now: () => t.mono },
    Date: Object.assign(function () {}, { now: () => t.wall, parse: Date.parse }),
    console: { warn() {}, error() {} },
    enc: new TextEncoder(),
    b64url,
    setTimeout, clearTimeout, AbortController, URL, Headers, Object, Math, Number,
    crypto: { subtle: { sign: async () => new Uint8Array(64) } },
  };
  // Scripted fetch: each call shifts one queued response.
  sandbox.window.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input.url;
    t.fetches.push({ url, init, headerTs: init && init.headers && init.headers.get && init.headers.get("X-Pow-Proof") });
    const next = t.script.shift() || { status: 200 };
    return {
      ok: next.status >= 200 && next.status < 300,
      status: next.status,
      headers: new Headers(next.headers || {}),
    };
  };
  const names = [
    "syncClock", "syncFromHeader", "clockStale", "resyncClock", "clockSkew",
    "clockHint", "reportClock", "nowSec", "signProof", "installProofFetch",
  ];
  const factory = new Function(
    ...Object.keys(sandbox),
    `${region}\nreturn { ${names.join(", ")} };`,
  );
  const api = factory(...Object.values(sandbox));
  return { t, advance, els, api, sandbox };
}

test("a device clock 3 h ahead is corrected to server time", () => {
  const { t, api } = harness({ deviceOffsetSec: 3 * 3600 });
  api.syncClock(t.server, t.mono, t.mono);
  assert.ok(Math.abs(api.nowSec() - (t.server + 0.5)) < 1);
  assert.ok(Math.abs(api.clockSkew() + 3 * 3600) < 1);
});

test("hint appears from 60 s of skew, not below, in both directions", () => {
  for (const [offset, expected] of [[0, ""], [30, ""], [59, ""], [61, "1 min"], [-300, "5 min"], [7200, "2 h"], [-90000, "25 h"]]) {
    const { t, api, els } = harness({ deviceOffsetSec: offset });
    api.syncClock(t.server, t.mono, t.mono);
    api.reportClock();
    const shown = !els["pow-clock"].hidden;
    assert.equal(shown, expected !== "", `offset ${offset}`);
    if (expected) assert.ok(els["pow-clock"].textContent.includes(expected), `offset ${offset}: ${els["pow-clock"].textContent}`);
  }
});

test("round-trip time is split evenly and the whole-second server stamp is centered", () => {
  const { t, advance, api } = harness();
  const sent = t.mono;
  advance(800);                                  // 800 ms RTT
  api.syncClock(Math.floor(t.server - 0.4), sent, t.mono);
  assert.ok(Math.abs(api.nowSec() - t.server) <= 0.6);
});

test("wall-clock jumps do not move the anchored clock", () => {
  const { t, advance, api } = harness({ deviceOffsetSec: 0 });
  api.syncClock(t.server, t.mono, t.mono);
  const before = api.nowSec();
  t.wall += 6 * 3600 * 1000;                     // user changes the clock
  advance(10_000, { wallToo: false });
  assert.ok(Math.abs(api.nowSec() - (before + 10)) < 0.01);
  assert.equal(api.clockStale(), true);          // drift triggers a resync
});

test("stale after a long age or a paused monotonic timer", () => {
  const a = harness();
  a.api.syncClock(a.t.server, a.t.mono, a.t.mono);
  assert.equal(a.api.clockStale(), false);
  a.advance(121_000);
  assert.equal(a.api.clockStale(), true);

  const b = harness();
  b.api.syncClock(b.t.server, b.t.mono, b.t.mono);
  b.t.wall += 3_600_000;                         // device slept for an hour, mono paused
  assert.equal(b.api.clockStale(), true);
});

test("resync reads X-Pow-Now from /status without a proof", async () => {
  const { t, api } = harness({ deviceOffsetSec: 600 });
  api.syncClock(t.server - 1000, t.mono, t.mono);        // wrong anchor
  t.script.push({ status: 409, headers: { "X-Pow-Now": String(Math.floor(t.server)) } });
  await api.resyncClock();
  assert.equal(t.fetches.length, 1);
  assert.equal(t.fetches[0].url, "/.pow/status");
  assert.ok(Math.abs(api.nowSec() - t.server) < 1.5);
});

test("a proof rejected for skew is retried once with the corrected timestamp (GET)", async () => {
  const { t, api, sandbox } = harness({ deviceOffsetSec: 3 * 3600 });
  api.installProofFetch({});
  // No sync yet: first proof is stamped with the (wrong) device clock.
  t.script.push({ status: 403, headers: { "X-Pow-Reason": "proof_skew", "X-Pow-Now": String(Math.floor(t.server)) } });
  t.script.push({ status: 200 });
  const res = await sandbox.window.fetch("/api/data");
  assert.equal(res.status, 200);
  assert.equal(t.fetches.length, 2);
  const ts = (h) => Number(h.split(".").pop());
  assert.ok(Math.abs(ts(t.fetches[0].headerTs) - (t.wall / 1000)) < 2);
  assert.ok(Math.abs(ts(t.fetches[1].headerTs) - t.server) < 2);
});

test("no retry loop and no replay of non-idempotent requests", async () => {
  const get = harness();
  get.api.installProofFetch({});
  for (let i = 0; i < 3; i++) get.t.script.push({ status: 403, headers: { "X-Pow-Reason": "proof_skew", "X-Pow-Now": String(Math.floor(get.t.server)) } });
  await get.sandbox.window.fetch("/api/data");
  assert.equal(get.t.fetches.length, 2, "GET retried at most once");

  const post = harness();
  post.api.installProofFetch({});
  post.t.script.push({ status: 403, headers: { "X-Pow-Reason": "proof_skew", "X-Pow-Now": String(Math.floor(post.t.server)) } });
  const res = await post.sandbox.window.fetch("/api/data", { method: "POST", body: "x" });
  assert.equal(res.status, 403);
  assert.equal(post.t.fetches.length, 1, "POST not repeated");
});

test("other errors pass through untouched", async () => {
  const { t, api, sandbox } = harness();
  api.installProofFetch({});
  t.script.push({ status: 403 });
  const res = await sandbox.window.fetch("/api/data");
  assert.equal(res.status, 403);
  assert.equal(t.fetches.length, 1);
});
