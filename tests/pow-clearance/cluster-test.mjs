#!/usr/bin/env node
// Two real nginx masters + an isolated Redis primary. Never FLUSHDB/FLUSHALL.
// POW_REDIS defaults to 127.0.0.1:16379 (the test Docker service).
import { request } from 'node:http';
import { createConnection, createServer } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
const nginx = resolve(process.env.POW_NGINX || '.nginx/nginx-1.31.7/objs/nginx');
const sourceModule = resolve(process.env.POW_MODULE || 'target/debug/libngx_http_pow_gate.so');
const redisAddress = process.env.POW_REDIS || '127.0.0.1:16379';
const [redisHost, redisPort] = redisAddress.split(':');
const root = mkdtempSync(join(tmpdir(), 'pow-cluster-'));
const namespace = 'test_' + randomBytes(8).toString('hex');
const baseKey = `powgate:{${namespace}}`;
const ua = 'cluster-test';
const active = [];
const proxies = [];
function redis(...parts) {
 const buffers = parts.map(p => Buffer.from(String(p)));
 const command = Buffer.concat([Buffer.from(`*${parts.length}\r\n`), ...buffers.flatMap(p => [Buffer.from(`$${p.length}\r\n`), p, Buffer.from('\r\n')])]);
 function parse(buf, at = 0) {
  const end = buf.indexOf('\r\n', at); if (end < 0) return null;
  const kind = String.fromCharCode(buf[at]), line = buf.toString('utf8', at + 1, end); let next = end + 2;
  if (kind === '+' || kind === '-' || kind === ':') return [kind === ':' ? Number(line) : line, next, kind === '-'];
  if (kind === '$') { const len = Number(line); if (len === -1) return [null, next]; if (buf.length < next + len + 2) return null; return [buf.toString('utf8', next, next + len), next + len + 2]; }
  if (kind === '*') { const values = []; for (let i = 0; i < Number(line); i++) { const v = parse(buf, next); if (!v) return null; values.push(v[0]); next = v[1]; } return [values, next]; }
  throw new Error('invalid Redis reply');
 }
 return new Promise((resolve, reject) => {
  const socket = createConnection({ host: redisHost, port: Number(redisPort) }, () => socket.write(command));
  let input = Buffer.alloc(0);
  socket.setTimeout(3000, () => socket.destroy(new Error('Redis test timeout')));
  socket.on('error', reject);
  socket.on('data', chunk => { input = Buffer.concat([input, chunk]); const value = parse(input); if (value) { socket.end(); value[2] ? reject(new Error(value[0])) : resolve(value[0]); } });
 });
}
const delay = ms => new Promise(r => setTimeout(r, ms));
const freePort = () => new Promise(r => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const port = s.address().port; s.close(() => r(port)); }); });
async function start(name, ns = namespace, extra = '', password = '', address = redisAddress, module = sourceModule) {
 const prefix = join(root, name); mkdirSync(prefix); mkdirSync(join(prefix, 'logs'));
 copyFileSync(module, join(prefix, 'module.so'));
 const port = await freePort();
 const config = `load_module ${prefix}/module.so;
 pid ${prefix}/nginx.pid; error_log ${prefix}/error.log info;
 worker_processes 2; events { worker_connections 256; }
 http { log_format gate '$uri $status $pow_gate_result $pow_gate_reason'; access_log ${prefix}/access.log gate;
  http2 on;
  pow_gate_hmac_key_file ${root}/key; pow_gate_cookie_secure off; pow_gate_difficulty 500;
  pow_gate_redis { address ${address}; namespace ${ns}; epoch_file ${root}/epoch; ${extra} ${password} }
  map $http_user_agent $decision { default challenge; nojs-test challenge:nojs:1; }
  server { listen 127.0.0.1:${port};
   location / { pow_gate on; pow_gate_decision $decision; root ${root}; try_files /index.html =404; }
   location = /other-policy { pow_gate on; pow_gate_policy other; root ${root}; try_files /index.html =404; }
   location = /stronger { pow_gate on; pow_gate_difficulty 2000; root ${root}; try_files /index.html =404; }
  }
 }`;
 writeFileSync(join(prefix, 'nginx.conf'), config);
 execFileSync(nginx, ['-p', prefix + '/', '-c', join(prefix, 'nginx.conf')]);
 let pid = 0;
 for (let i = 0; i < 500 && !pid; i++) {
  try { pid = Number(readFileSync(join(prefix, 'nginx.pid'), 'utf8')); } catch {}
  if (!pid) await delay(10);
 }
 assert(pid > 0, 'nginx did not write its pid file');
 const node = { base: `http://127.0.0.1:${port}`, prefix, config, pid };
 active.push(node); return node;
}
function send(node, method, path, body, headers = {}) {
 const data = body == null ? null : JSON.stringify(body);
 return new Promise((resolve, reject) => {
  const req = request(new URL(path, node.base), { method, agent: false, headers: { 'User-Agent': ua, ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}), ...headers } }, res => {
   const chunks = []; res.on('data', x => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString() }));
  });
  req.on('error', reject); req.setTimeout(5000, () => req.destroy(new Error('nginx request stalled'))); req.end(data);
 });
}
const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
const b64 = b => Buffer.from(b).toString('base64url');
const pk = b64(await crypto.subtle.exportKey('raw', pair.publicKey));
async function challenge(node) {
 // Every worker establishes Redis readiness asynchronously. A successful poll
 // on one worker is not a promise that the next connection hits that worker.
 const until = Date.now() + 5000;
 let response;
 do {
  response = await send(node, 'GET', '/.pow/challenge', null, { 'X-Pow-Key': pk });
  if (response.status !== 503) break;
  await delay(25);
 } while (Date.now() < until);
 assert.equal(response.status, 200); return JSON.parse(response.text);
}
async function submission(node) {
 const ch = await challenge(node), target = (1n << 256n) / BigInt(ch.difficulty);
 let nonce = 0; while (BigInt('0x' + createHash('sha256').update(ch.salt + nonce).digest('hex')) >= target) nonce++;
 return { ...ch, nonce, pubkey: pk, signature: b64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode('pow-gate-redeem-v2 ' + ch.token))) };
}
const verify = (node, body) => send(node, 'POST', '/.pow/verify', body);
async function ready(node) {
 const until = Date.now() + 6000;
 while ((await send(node, 'GET', '/.pow/challenge', null, { 'X-Pow-Key': pk })).status !== 200) { assert(Date.now() < until, 'cluster did not become ready'); await delay(50); }
}
try {
 writeFileSync(join(root, 'key'), 'isolated-cluster-known-secret-key-32-bytes');
 writeFileSync(join(root, 'index.html'), 'upstream-content');
 execFileSync('python3', ['scripts/redis-epoch.py', '--address', redisAddress, '--namespace', namespace, '--output', join(root, 'epoch')]);
 const epoch = readFileSync(join(root, 'epoch'), 'utf8').trim();
 const a = await start('a'), b = await start('b'); await ready(a); await ready(b);
 execFileSync(process.execPath, ['tests/pow-clearance/security-test.mjs', a.base], {stdio: 'pipe', env: {...process.env, NGINX_PID_FILE: join(a.prefix, 'nginx.pid')}});
 execFileSync(process.execPath, ['tests/pow-clearance/http2-test.mjs', b.base], {stdio: 'pipe'});
 console.log('ok: full existing security suite and multiplexed HTTP/2 use Redis');
 const body = await submission(a);
 const races = await Promise.all(Array.from({ length: 32 }, (_, i) => verify(i % 2 ? a : b, body)));
 assert.equal(races.filter(r => r.status === 204).length, 1);
 assert.equal(races.filter(r => r.status === 409).length, 31);
 const cookie = races.find(r => r.status === 204).headers['set-cookie'][0].split(';')[0];
 assert.equal((await send(b, 'GET', '/', null, { Cookie: cookie })).text, 'upstream-content');
 console.log('ok: one redemption across two masters/four workers, portable cookie');
 // Optional local comparison against a retained, ABI-compatible old module.
 // Exercise both issuance directions and the same shared redemption authority.
 if (process.env.POW_COMPAT_MODULE) {
  const previous = await start('compat', namespace, '', '', redisAddress, resolve(process.env.POW_COMPAT_MODULE));
  await ready(previous);
  for (const [issuer, receiver] of [[a, previous], [previous, b]]) {
   const pending = await submission(issuer);
   const accepted = await verify(receiver, pending);
   assert.equal(accepted.status, 204);
   const portable = accepted.headers['set-cookie'][0].split(';')[0];
   for (const node of [a, b, previous]) {
    assert.equal((await send(node, 'GET', '/', null, {Cookie: portable})).text, 'upstream-content');
   }
   assert.equal((await verify(issuer, pending)).status, 409);
  }
  console.log('ok: previous/current modules interoperate in both issuance directions and reject cross-version replay');
 }

 const marker = `${baseKey}:${epoch}:spent:${createHash('sha256').update(body.token).digest('hex')}`;
 const keys = await redis('KEYS', `${baseKey}:${epoch}:spent:*`);
 assert(keys.length >= 1);
 assert((await redis('TTL', marker)) > 0);
 const issued = await submission(a);
 process.kill(a.pid, 'SIGHUP'); await delay(250); await ready(a);
 assert.equal((await verify(a, body)).status, 409);
 assert.equal((await verify(b, issued)).status, 204);
 console.log('ok: pending/spent tokens survive graceful reload');
 // Full process restart still uses the Redis epoch, including existing cookies.
 process.kill(a.pid, 'SIGQUIT'); await delay(300);
 execFileSync(nginx, ['-p', a.prefix + '/', '-c', join(a.prefix, 'nginx.conf')]);
 a.pid = Number(readFileSync(join(a.prefix, 'nginx.pid'), 'utf8')); await ready(a);
 assert.equal((await send(a, 'GET', '/', null, { Cookie: cookie })).text, 'upstream-content');
 assert.equal((await verify(a, body)).status, 409);
 console.log('ok: process restart preserves epoch and spent markers');
 const page = await send(a, 'GET', '/', null, { 'User-Agent': 'nojs-test' });
 const path = page.text.match(/(\/\.pow\/pass\?t=[^"\s<>]+)/)[1].replaceAll('&amp;', '&');
 await delay(1100);
 const nojs = await Promise.all([a, b].map(node => send(node, 'GET', path, null, { 'User-Agent': 'nojs-test' })));
 assert.equal(nojs.filter(r => r.status === 302 && r.headers['set-cookie']).length, 1);
 assert.equal(nojs.filter(r => r.status === 409).length, 1);
 console.log('ok: no-JS redemption shares the Redis backend');
 // Script clock high-water prevents a regressed clock from reopening a token.
 await redis('SET', baseKey + ':clock', Math.floor(Date.now() / 1000) + 200);
 assert.equal((await verify(a, await submission(b))).status, 400);
 await redis('SET', baseKey + ':clock', Math.floor(Date.now() / 1000));
 // Redis can commit before its TCP reply is lost. The gateway must refuse
 // clearance and preserve the spent marker rather than retrying locally.
 const sockets = new Set();
 const proxy = createServer(client => {
  const upstream = createConnection({host: redisHost, port: Number(redisPort)});
  sockets.add(client); sockets.add(upstream);
  let requestBytes = Buffer.alloc(0), consume = false;
  client.on('data', bytes => { requestBytes=Buffer.concat([requestBytes,bytes]); consume=requestBytes.includes(Buffer.from('local previous')); upstream.write(bytes); });
  upstream.on('data', bytes => {
   if (consume) { client.destroy(); upstream.destroy(); }
   else { client.write(bytes.subarray(0,1)); setTimeout(() => { if (!client.destroyed) client.write(bytes.subarray(1)); }, 3); }
  });
  client.on('error', () => upstream.destroy()); upstream.on('error', () => client.destroy());
  client.on('close', () => { sockets.delete(client); upstream.destroy(); });
  upstream.on('close', () => sockets.delete(upstream));
 });
 await new Promise(r => proxy.listen(0, '127.0.0.1', r));
 proxies.push({proxy,sockets});
 const ambiguous = await start('ambiguous', namespace, '', '', '127.0.0.1:' + proxy.address().port);
 await ready(ambiguous);
 const committed = await submission(a);
 assert.equal((await verify(ambiguous, committed)).status, 503);
 assert.equal((await verify(b, committed)).status, 409);
 console.log('ok: fragmented RESP and lost Redis acceptance replies fail closed without undoing markers');
 // Queue saturation, timeouts, and client cancellation under an unavailable
 // primary must neither block the nginx event loop nor leak request pointers.
 const tiny = await start('tiny', namespace, 'connections 1; queue 1; timeout 100;');
 await ready(tiny);
 const stalled = await submission(tiny);
 await redis('CLIENT', 'PAUSE', '1000', 'ALL');
 const t0 = Date.now();
 const rejected = await Promise.all(Array.from({length: 12}, () => verify(tiny, stalled)));
 assert(rejected.every(r => r.status === 503));
 assert(Date.now() - t0 < 900, 'Redis queue blocked the event loop');
 assert.equal((await send(tiny, 'GET', '/', null, {Cookie: cookie})).text, 'upstream-content');
 await delay(1100); await ready(tiny);
 const abortBody = await submission(tiny);
 await redis('CLIENT', 'PAUSE', '800', 'ALL');
 await Promise.all(Array.from({length: 8}, () => new Promise(resolve => {
  const data = JSON.stringify(abortBody);
  const req = request(new URL('/.pow/verify', tiny.base), {method:'POST', agent:false, headers:{'User-Agent':ua,'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}});
  req.on('error', () => resolve()); req.on('response', res => {res.resume(); resolve();}); req.end(data);
  setTimeout(() => req.destroy(), 20);
 })));
 await delay(1000); await ready(tiny);
 assert.equal((await verify(tiny, await submission(tiny))).status, 204);
 console.log('ok: bounded queue, Redis deadlines, disconnected clients, and local clearance during outage');
 // AUTH/ACL support works without exposing credentials in diagnostics.
 const username = namespace + '_user', password = randomBytes(24).toString('hex');
 writeFileSync(join(root, 'password'), password + '\n');
 await redis('ACL', 'SETUSER', username, 'on', '>' + password, '~' + baseKey + ':*', '+auth', '+eval', '+get', '+set', '+time');
 try {
  const authorized = await start('authorized', namespace, '', `username ${username}; password_file ${root}/password;`);
  await ready(authorized);
  assert.equal((await verify(authorized, await submission(authorized))).status, 204);
  assert(!readFileSync(join(authorized.prefix, 'error.log'), 'utf8').includes(password));
 } finally { await redis('ACL', 'DELUSER', username); }
 console.log('ok: Redis ACL credentials authenticate and stay out of logs');
 // Auth failures never downgrade to the local store.
 writeFileSync(join(root, 'bad-password'), 'not-the-password');
 const bad = await start('bad-auth', namespace, '', `password_file ${root}/bad-password;`);
 await delay(150);
 assert.equal((await send(bad, 'GET', '/.pow/challenge', null, { 'X-Pow-Key': pk })).status, 503);
 console.log('ok: Redis authentication failure refuses challenges');
 // Deliberate OOM affects fresh verification, never already-cleared requests.
 const pending = await submission(a);
 const maxmemory = await redis('CONFIG', 'GET', 'maxmemory');
 try {
  await redis('CONFIG', 'SET', 'maxmemory', '1');
  assert.equal((await verify(b, pending)).status, 503);
  assert.equal((await send(b, 'GET', '/', null, { Cookie: cookie })).text, 'upstream-content');
 } finally { await redis('CONFIG', 'SET', 'maxmemory', maxmemory[1]); }
 await ready(a); await ready(b);
 console.log('ok: Redis OOM fails verification closed; clearances stay local');
 // A different namespace stays isolated even with a copied epoch file.
 const isolated = await start('isolated', namespace + '_other');
 await delay(150);
 assert.notEqual((await send(isolated, 'GET', '/', null, {Cookie: cookie})).text, 'upstream-content');
 assert.equal((await send(isolated, 'GET', '/.pow/challenge', null, {'X-Pow-Key':pk})).status, 503);
 // Rotate the epoch, fence old nodes, and require the new issuer at restart.
 const beforeRotation = await submission(a);
 const nextEpoch = randomBytes(32).toString('hex');
 await redis('SET', baseKey + ':epoch', nextEpoch);
 assert.equal((await verify(a, beforeRotation)).status, 503);
 await delay(1200);
 writeFileSync(join(root, 'epoch'), nextEpoch + '\n');
 const fresh = await start('new-epoch'); await ready(fresh);
 assert.equal((await verify(fresh, beforeRotation)).status, 400);
 assert.notEqual((await send(fresh, 'GET', '/', null, {Cookie: cookie})).text, 'upstream-content');
 assert.equal((await verify(fresh, await submission(fresh))).status, 204);
 console.log('ok: namespace separation and epoch rotation invalidate old tokens');
 const clockToken = await submission(fresh);
 await redis('DEL', baseKey + ':clock');
 assert.equal((await verify(fresh, clockToken)).status, 503);
 await redis('SET', baseKey + ':clock', Math.floor(Date.now()/1000));
 const afterClockLoss = await start('after-clock-loss'); await ready(afterClockLoss);
 console.log('ok: missing shared clock fences verification');
 // Detect lost issuer state and fence permanently; never silently recreate it.
 const beforeLoss = await submission(afterClockLoss);
 await redis('DEL', baseKey + ':epoch');
 assert.equal((await verify(afterClockLoss, beforeLoss)).status, 503);
 await delay(1200);
 assert.equal((await send(b, 'GET', '/.pow/challenge', null, { 'X-Pow-Key': pk })).status, 503);
 await redis('SET', baseKey + ':epoch', nextEpoch);
 await delay(1100);
 assert.equal((await send(afterClockLoss, 'GET', '/.pow/challenge', null, { 'X-Pow-Key': pk })).status, 503);
 console.log('ok: missing epoch fences nodes and cannot resurrect old state');
} catch (error) {
 if (error.stderr) console.error(error.stderr.toString());
 for (const node of active) console.error(node.prefix, readFileSync(join(node.prefix, 'error.log'), 'utf8').slice(-5000));
 throw error;
} finally {
 for (const node of active) { try { process.kill(node.pid, 'SIGQUIT'); } catch {} }
 await delay(700);
 for (const {proxy,sockets} of proxies) { for (const socket of sockets) socket.destroy(); await new Promise(r => proxy.close(r)); }
 const keys = await redis('KEYS', baseKey + ':*').catch(() => []);
 if (keys.length) await redis('DEL', ...keys);
 rmSync(root, { recursive: true, force: true });
}
