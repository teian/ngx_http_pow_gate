#!/usr/bin/env node
// Cleartext HTTP/2 prior-knowledge tests; fixture must enable http2 on.
import http2 from 'node:http2';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
const base = process.argv[2] || 'http://127.0.0.1:18080';
const client = http2.connect(base);
client.on('error', error => { console.error(error); process.exitCode = 1; });
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
const pubkey = b64(await crypto.subtle.exportKey('raw', kp.publicKey));
function send(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const stream = client.request({ ':method': method, ':path': path, 'user-agent': 'h2-security-test', ...headers });
    let response; const chunks = [];
    stream.on('response', value => { response = value; });
    stream.on('data', value => chunks.push(value));
    stream.on('end', () => resolve({ status: response[':status'], headers: response, text: Buffer.concat(chunks).toString() }));
    stream.on('error', reject);
    stream.setTimeout(10000, () => stream.destroy(new Error('HTTP/2 request timed out')));
    stream.end(body == null ? undefined : JSON.stringify(body));
  });
}
async function submission() {
  const issued = await send('GET', '/.pow/challenge', null, { 'x-pow-key': pubkey });
  assert.equal(issued.status, 200);
  const ch = JSON.parse(issued.text);
  const target = (1n << 256n) / BigInt(ch.difficulty);
  let nonce = 0;
  while (BigInt('0x' + createHash('sha256').update(ch.salt + nonce).digest('hex')) >= target) nonce++;
  return { ...ch, nonce, pubkey, signature: b64(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey,
    new TextEncoder().encode('pow-gate-redeem-v2 ' + ch.token))) };
}
const verify = body => send('POST', '/.pow/verify', body, { 'content-type': 'application/json' });
try {
  // No Content-Length is sent: the streaming limit must handle HTTP/2 DATA.
  const body = await submission();
  const raced = await Promise.all(Array.from({ length: 16 }, () => verify(body)));
  assert.equal(raced.filter(r => r.status === 204).length, 1);
  assert.equal(raced.filter(r => r.status === 409).length, 15);
  const cookie = raced.find(r => r.status === 204).headers['set-cookie'][0].split(';')[0];
  assert((await send('GET', '/', null, { cookie })).text.includes('upstream-content'));
  const exact = await submission();
  const padded = { ...exact, padding: '' };
  padded.padding = 'x'.repeat(8192 - Buffer.byteLength(JSON.stringify(padded)));
  assert.equal(Buffer.byteLength(JSON.stringify(padded)), 8192);
  assert.equal((await verify(padded)).status, 204, 'exact 8 KiB boundary is accepted');
  const over = { ...await submission(), padding: '' };
  over.padding = 'x'.repeat(8193 - Buffer.byteLength(JSON.stringify(over)));
  assert.equal((await verify(over)).status, 413, '8 KiB + 1 is rejected while streaming');
  delete over.padding;
  assert.equal((await verify(over)).status, 204, 'oversize attempt did not consume the challenge');
  console.log('PASS: HTTP/2 multiplexed atomic redemption, navigation, unknown-length bodies and exact streaming size boundary');
} finally {
  client.close();
}
