// Real-browser gate regressions. Starts isolated nginx; never touches a running site.
import { chromium, firefox } from 'playwright';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const nginx = resolve(process.env.POW_NGINX || '.nginx/nginx-1.31.7/objs/nginx');
const sourceModule = resolve(process.env.POW_MODULE || 'target/debug/libngx_http_pow_gate.so');
const root = mkdtempSync(join(tmpdir(), 'pow-browser-'));
mkdirSync(join(root, 'logs'));
const module = join(root, 'module.so');
copyFileSync(sourceModule, module);
writeFileSync(join(root, 'key'), 'isolated-browser-test-secret-32-bytes');
writeFileSync(join(root, 'index.html'), '<h1 id="upstream">upstream</h1>');
const port = await new Promise(r => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const base = `http://127.0.0.1:${port}`;
writeFileSync(join(root, 'nginx.conf'), `load_module ${module};
pid ${root}/nginx.pid;
error_log ${root}/error.log info;
worker_processes 2;
events { worker_connections 128; }
http {
 gzip on; gzip_types text/javascript; gzip_vary on;
 log_format gate '$uri $status $pow_gate_result $pow_gate_reason $pow_gate_difficulty';
 access_log ${root}/access.log gate;
 pow_gate_hmac_key_file ${root}/key;
 pow_gate_difficulty 2000;
 pow_gate_cookie_secure off;
 server { listen 127.0.0.1:${port};
   location / { pow_gate on; root ${root}; try_files /index.html =404; }
   location /strict/ { pow_gate on; add_header Content-Security-Policy "worker-src 'none'" always; root ${root}; try_files /index.html =404; }
   location = /drop {
     pow_gate off;
     add_header Set-Cookie "$pow_gate_cookie_name=; Path=/; Max-Age=0" always;
     add_header X-Pow-Cookie $pow_gate_cookie_name always;
     return 204;
   }
   location /other/ { pow_gate on; pow_gate_policy other; root ${root}; try_files /index.html =404; }
 }
}`);
execFileSync(nginx, ['-p', root + '/', '-c', join(root, 'nginx.conf')]);
try {
 const pageResponse = await fetch(base);
 const html = await pageResponse.text();
 const version = html.match(/solver\.js\?v=([^"']+)/)[1];
 const asset = await fetch(`${base}/.pow/solver.js?v=${version}`);
 assert.equal(asset.headers.get('cache-control'), 'public, max-age=31536000, immutable');
 assert.equal(asset.headers.get('content-encoding'), 'gzip');
 assert.match(asset.headers.get('vary'), /Accept-Encoding/i);
 assert.equal(asset.headers.get('content-type'), 'text/javascript; charset=utf-8');
 const bytes = Buffer.from(await asset.arrayBuffer());
 const identity = await fetch(`${base}/.pow/solver.js?v=${version}`, {headers: {'Accept-Encoding': 'gzip;q=0, identity'}});
 assert.equal(identity.headers.get('content-encoding'), null);
 assert.equal(identity.headers.get('content-type'), 'text/javascript; charset=utf-8');
 assert.deepEqual(Buffer.from(await identity.arrayBuffer()), bytes);
 const head = await fetch(`${base}/.pow/solver.js?v=${version}`, {method: 'HEAD'});
 assert.equal(head.status, 200);
 assert.equal((await head.arrayBuffer()).byteLength, 0);
 assert(version.endsWith(createHash('sha256').update(bytes).digest('base64url')));
 for (const query of ['', '?v=obsolete', `?v=${version}&extra=1`]) {
   const response = await fetch(`${base}/.pow/solver.js${query}`);
   assert.equal(response.headers.get('cache-control'), 'no-store');
   assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
 }
 for (const name of (process.env.POW_BROWSERS || 'chromium,firefox').split(',')) {
  const kind = name === 'firefox' ? firefox : chromium;
  const browser = await kind.launch({ headless: true, ...(name === 'firefox' && process.env.POW_FIREFOX ? { executablePath: process.env.POW_FIREFOX } : {}), ...(name === 'chromium' && process.env.POW_CHROMIUM ? { executablePath: process.env.POW_CHROMIUM } : {}) });
  try {
   async function scenario(title, setup = async () => {}, path = '/') {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
     await setup(page, context);
     await page.goto(base + path);
     await page.locator('#upstream').waitFor({ timeout: 25000 });
     const cookies = await context.cookies();
     assert(cookies.some(c => /^pow_clearance_[0-9a-f]{24}$/.test(c.name)));
     console.log(`ok ${name}: ${title}`);
    } finally { await context.close(); }
   }
   const offset = readFileSync(join(root, 'access.log'), 'utf8').length;
   await scenario('normal clearance and outcome logging');
   const assets = readFileSync(join(root, 'access.log'), 'utf8').slice(offset).split('\n')
     .filter(line => line.startsWith('/.pow/solver.js ')).length;
   assert(assets >= 1 && assets <= 2, `solver/worker cache requests: ${assets}`);
   console.log(`ok ${name}: solver and workers used ${assets} network asset request(s)`);
   await scenario('strict worker CSP falls back', async () => {}, '/strict/');
   await scenario('transient challenge reset recovers', async page => {
    let calls = 0;
    await page.route('**/.pow/challenge', route => ++calls === 1 ? route.abort('connectionreset') : route.continue());
   });
   await scenario('429 challenge honors retry', async page => {
    let calls = 0;
    await page.route('**/.pow/challenge', route => ++calls === 1 ? route.fulfill({ status: 429, headers: { 'Retry-After': '0' }, body: 'slow down' }) : route.continue());
   });
   await scenario('lost verify response gets fresh challenge', async page => {
    let calls = 0;
    await page.route('**/.pow/verify', async route => {
     if (++calls === 1) { await route.fetch(); await route.abort('connectionreset'); }
     else await route.continue();
    });
   });
   await scenario('initial solver asset failure recovers', async page => {
    let calls = 0;
    await page.route('**/solver.js?*', route => ++calls === 1 ? route.abort('failed') : route.continue());
   });
   await scenario('IndexedDB failure still permits navigation', async page => {
    await page.addInitScript(() => { Object.defineProperty(window, 'indexedDB', { get() { throw new Error('storage blocked'); } }); });
   });
   await scenario('silent workers fall back after watchdog', async page => {
    await page.addInitScript(() => { window.Worker = class { postMessage() {} terminate() {} }; });
   });
   await scenario('old fixed-name cookie cannot shadow clearance', async (_page, context) => {
    await context.addCookies([{ name: 'pow_clearance', value: 'old-invalid-token', url: base }]);
   });
   const context = await browser.newContext();
   try {
    const page = await context.newPage();
    let verifications = 0, navigation = 0;
    await page.route('**/.pow/verify', async route => {
     verifications++;
     const response = await route.fetch();
     const headers = { ...response.headers() }; delete headers['set-cookie'];
     await route.fulfill({ response, headers });
    });
    // Simulate the browser refusing cookies, including ones set by route.fetch.
    await page.route('**/.pow/status', route => route.fulfill({ status: 409, body: 'cookie blocked' }));
    page.on('framenavigated', frame => { if (frame === page.mainFrame()) navigation++; });
    await page.goto(base);
    await page.locator('#pow-error:visible').waitFor({ timeout: 25000 });
    assert.equal(verifications, 3); assert.equal(navigation, 1);
    console.log(`ok ${name}: missing cookies stop after three attempts without reload`);
   } finally { await context.close(); }
   const wrongPolicy = await browser.newContext();
   try {
    const page = await wrongPolicy.newPage(); let navigation = 0;
    page.on('framenavigated', frame => { if (frame === page.mainFrame()) navigation++; });
    await page.goto(base + '/other/');
    await page.locator('#pow-error:visible').waitFor({timeout: 25000});
    assert(navigation <= 4);
    console.log(`ok ${name}: mismatched content/endpoint policy stops automatic reloads`);
   } finally { await wrongPolicy.close(); }
   const reset = await browser.newContext();
   try {
    const page = await reset.newPage(); await page.goto(base);
    await page.locator('#upstream').waitFor({timeout:25000});
    const response = await reset.request.get(base + '/drop');
    assert.match(response.headers()['x-pow-cookie'], /^pow_clearance_[0-9a-f]{24}$/);
    assert(!(await reset.cookies()).some(c => c.name === response.headers()['x-pow-cookie']));
    await page.goto(base); await page.locator('#upstream').waitFor({timeout:25000});
    console.log(`ok ${name}: effective cookie variable supports dev reset helper`);
   } finally { await reset.close(); }
   const multi = await browser.newContext();
   try {
    const pages = await Promise.all([multi.newPage(), multi.newPage()]);
    await Promise.all(pages.map(async p => { await p.goto(base); await p.locator('#upstream').waitFor({ timeout: 25000 }); }));
    console.log(`ok ${name}: concurrent tabs recover`);
   } finally { await multi.close(); }
  } finally { await browser.close(); }
 }
 const log = readFileSync(join(root, 'access.log'), 'utf8');
 assert.match(log, /accepted pow 2000/);
 assert.match(log, /bypass clearance 2000/);
 const challenge = await fetch(base);
 assert.match(challenge.headers.get('cache-control'), /no-store/);
 const rejected = await fetch(base + '/.pow/challenge');
 assert.equal(rejected.status, 400); assert.match(rejected.headers.get('cache-control'), /no-store/);
 console.log('ok: cache headers and nginx outcome variables');
} catch (error) {
 console.error(readFileSync(join(root, 'error.log'), 'utf8').slice(-5000));
 throw error;
} finally {
 execFileSync(nginx, ['-p', root + '/', '-c', join(root, 'nginx.conf'), '-s', 'quit']);
 // Let workers finish before removing their prefix.
 await new Promise(r => setTimeout(r, 200));
 rmSync(root, { recursive: true, force: true });
}
