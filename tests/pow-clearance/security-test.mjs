#!/usr/bin/env node
// Against an ISOLATED nginx fixture: /other-policy and /stronger serve the
// upstream marker but use a different policy name / higher difficulty.
// Optional POW_TEST_SECOND_IP tests genuine source-address changes on loopback.
// Optional NGINX_PID_FILE signals ONLY that isolated fixture's graceful reload.
import { request } from 'node:http';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const base = new URL(process.argv[2] || 'http://127.0.0.1:18080');
const ua = 'security-test';
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
const pk = b64(await crypto.subtle.exportKey('raw', pair.publicKey));
function send(method, path, body, headers = {}, source) {
  const data = body == null ? null : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const outgoingHeaders = { 'User-Agent': ua, ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}), ...headers };
    if (outgoingHeaders['Transfer-Encoding']) delete outgoingHeaders['Content-Length'];
    const req = request(new URL(path, base), {
      method, localAddress: source, agent: false, headers: outgoingHeaders,
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString() }));
    });
    req.setTimeout(10000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject); req.end(data);
  });
}
async function challenge() {
  const res = await send('GET', '/.pow/challenge', null, { 'X-Pow-Key': pk });
  assert.equal(res.status, 200); assert.equal(res.headers['cache-control'], 'no-store');
  return JSON.parse(res.text);
}
function solve(ch, start = 0) {
  const target = ((1n << 256n) / BigInt(ch.difficulty));
  for (let nonce = start; ; nonce++) {
    const value = BigInt('0x' + createHash('sha256').update(ch.salt + nonce).digest('hex'));
    if (value < target) return nonce;
  }
}
async function submission(ch) {
  return { ...ch, nonce: solve(ch), pubkey: pk, signature: b64(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey,
    new TextEncoder().encode('pow-gate-redeem-v2 ' + ch.token))) };
}
const verify = (body, headers, source) => send('POST', '/.pow/verify', body, headers, source);
const admitted = res => res.text.includes('upstream-content');
assert.equal((await send('GET', '/.pow/challenge')).status, 400);
assert.equal((await send('GET', '/.pow/challenge', null, { 'X-Pow-Key': 'A'.repeat(1024) })).status, 400);
assert.equal((await send('GET', '/.pow/verify')).status, 405);
const ch = await challenge(); const body = await submission(ch);
assert.equal((await verify({ ...body, pubkey: 'AA' })).status, 400);
assert.equal((await verify({ ...body, signature: b64(new Uint8Array(64)) })).status, 400);
assert.equal((await verify({ ...body, difficulty: 1 })).status, 400);
assert.equal((await verify(body, { 'User-Agent': 'another-client' })).status, 400);
if (process.env.POW_TEST_SECOND_IP) {
  assert.equal((await verify(body, {}, process.env.POW_TEST_SECOND_IP)).status, 400);
}
// Failed cryptographic/context checks must not consume the legitimate solution.
const results = await Promise.all(Array.from({ length: 16 }, () => verify(body)));
assert.equal(results.filter(r => r.status === 204).length, 1);
assert.equal(results.filter(r => r.status === 409).length, 15);
const winner = results.find(r => r.status === 204);
const cookie = winner.headers['set-cookie'][0].split(';')[0];
const cookieHeaders = { Cookie: cookie };
assert(admitted(await send('GET', '/', null, cookieHeaders)));
assert(!admitted(await send('GET', '/', null, { ...cookieHeaders, 'User-Agent': 'another-client' })));
assert(!admitted(await send('GET', '/other-policy', null, cookieHeaders)));
assert(!admitted(await send('GET', '/stronger', null, cookieHeaders)));
if (process.env.POW_TEST_OTHER_BASE) {
  const other = new URL(process.env.POW_TEST_OTHER_BASE);
  assert.equal((await send('POST', new URL('/.pow/verify', other).href, body)).status, 400,
    'independent issuer must reject another instance challenge');
  assert(!admitted(await send('GET', other.href, null, cookieHeaders)),
    'independent issuer must reject another instance cookie');
}

if (process.env.POW_TEST_SECOND_IP) {
  assert(!admitted(await send('GET', '/', null, cookieHeaders, process.env.POW_TEST_SECOND_IP)));
}
// A different valid nonce cannot redeem the same authenticated challenge again.
assert.equal((await verify({ ...body, nonce: solve(ch, body.nonce + 1) })).status, 409);
// Large JSON is rejected before allocating a large parsing buffer.
assert.equal((await verify({ padding: 'x'.repeat(9000) })).status, 413);
assert.equal((await verify({ padding: 'x'.repeat(20000) }, { 'Transfer-Encoding': 'chunked' })).status, 413);
if (process.env.NGINX_PID_FILE) {
  const pending = await submission(await challenge());
  process.kill(Number(readFileSync(process.env.NGINX_PID_FILE, 'utf8').trim()), 'SIGHUP');
  await new Promise(resolve => setTimeout(resolve, 500));
  assert(admitted(await send('GET', '/', null, cookieHeaders)), 'cookie survived reload');
  assert.equal((await verify(body)).status, 409, 'spent challenge stayed spent after reload');
  assert.equal((await verify(pending)).status, 204, 'pending challenge survived reload');
}
console.log('PASS: key possession, address/UA/policy binding, stronger-policy rejection, atomic replay protection, nonce reuse, bounded body, optional reload');
