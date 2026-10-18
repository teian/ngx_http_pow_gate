#!/usr/bin/env python3
"""Live per-feed refresh, expiry and strict configuration tests (isolated nginx)."""
import http.server, json, os, signal, socket, subprocess, sys, tempfile, threading, time, urllib.request
from pathlib import Path
nginx, module = map(lambda s: str(Path(s).resolve()), sys.argv[1:3])
state = {'first': True, 'second': True, 'ip': '192.0.2.3'}
class Feed(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        healthy = state['first' if self.path == '/first' else 'second']
        self.send_response(200 if healthy else 503); self.end_headers()
        if healthy:
            ip = '192.0.2.0/24' if self.path == '/first' else '198.51.100.0/24'
            self.wfile.write(json.dumps({'prefixes': [{'ipv4Prefix': ip}]}).encode())
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Feed)
threading.Thread(target=server.serve_forever, daemon=True).start()
with tempfile.TemporaryDirectory(prefix='pow-feeds-') as tmp:
    root = Path(tmp); (root/'logs').mkdir(); (root/'key').write_text('isolated-feed-key-32-bytes-not-secret'); (root/'index.html').write_text('upstream')
    with socket.socket() as sock: sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
    config = f'''load_module {module};
pid {root}/nginx.pid; error_log {root}/error.log info;
worker_processes 2; events {{ worker_connections 64; }}
http {{
 log_format gate '$pow_gate_result $pow_gate_reason'; access_log {root}/access.log gate;
 pow_gate_hmac_key_file {root}/key; pow_gate_cookie_secure off;
 set_real_ip_from 127.0.0.1; real_ip_header X-Test-IP;
 pow_gate_verifier feeds {{
   ip_ranges_url http://127.0.0.1:{server.server_port}/first;
   ip_ranges_url http://127.0.0.1:{server.server_port}/second;
   ip_ranges_refresh 1s; ip_ranges_max_stale 3s;
 }}
 server {{ listen 127.0.0.1:{port}; location / {{ pow_gate on; pow_gate_decision verify:feeds; root {root}; try_files /index.html =404; }} }}
}}'''
    path = root/'nginx.conf'; path.write_text(config)
    for bad in ['0s', 'invalid', '18446744073709551615d']:
        path.write_text(config.replace('ip_ranges_refresh 1s;', f'ip_ranges_refresh {bad};'))
        assert subprocess.run([nginx,'-p',tmp+'/', '-c',str(path),'-t'], capture_output=True).returncode != 0
    path.write_text(config)
    subprocess.run([nginx,'-p',tmp+'/', '-c',str(path)], check=True)
    def body(ip):
        req=urllib.request.Request(f'http://127.0.0.1:{port}/', headers={'X-Test-IP':ip})
        with urllib.request.urlopen(req,timeout=2) as r: return r.read().decode()
    try:
        until=time.monotonic()+5
        while body('192.0.2.3') != 'upstream' or body('198.51.100.3') != 'upstream':
            assert time.monotonic()<until; time.sleep(.05)
        state['first']=False
        time.sleep(1.5)
        assert body('192.0.2.3')=='upstream', 'one failed refresh prematurely discarded a good feed'
        time.sleep(2)
        assert body('192.0.2.3')!='upstream', 'stale feed still trusted'
        assert body('198.51.100.3')=='upstream', 'failed source discarded healthy provider'
        assert 'feed_stale' in (root/'access.log').read_text()
        print('ok: strict times, independent provider snapshots, bounded stale age, outcome logging')
    finally:
        os.kill(int((root/'nginx.pid').read_text()),signal.SIGQUIT)
        time.sleep(.1)
server.shutdown()
