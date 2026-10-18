#!/usr/bin/env python3
"""Isolated native-nginx regression: failed reload must not change respawn policy.
Run unprivileged: python3 reload-test.py /path/to/nginx /path/to/module.so
"""
import argparse
import html
import os
from pathlib import Path
import signal
import re
import socket
import subprocess
import tempfile
import time
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('nginx', type=Path)
parser.add_argument('module', type=Path)
args = parser.parse_args()
if os.geteuid() == 0:
    parser.error('run this isolated regression as an unprivileged user')
nginx, module = args.nginx.resolve(), args.module.resolve()

def poll(check, message, timeout=5):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if check(): return
        time.sleep(.05)
    raise AssertionError(message)

with tempfile.TemporaryDirectory(prefix='pow-cycle-review-') as temporary:
    root = Path(temporary)
    (root / 'logs').mkdir()
    (root / 'hmac.key').write_text('isolated-known-test-key-not-production')
    (root / 'index.html').write_text('upstream-content')
    (root / 'deny.json').write_text('{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}')
    (root / 'allow.json').write_text('{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"}]}')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    def configuration(allow=False, invalid=False, late_failure=False):
        return f'''load_module {module};
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/{'missing/' if late_failure else ''}error.log notice;
events {{ worker_connections 64; }}
http {{
  access_log {root}/access.log;
  pow_gate_hmac_key_file {root}/hmac.key;
  pow_gate_cookie_secure off;
  map $http_user_agent $decision {{ default verify:policy; nojs-review challenge:nojs:1; }}
  pow_gate_verifier policy {{
    ip_ranges_url http://127.0.0.1:{port}/{'allow' if allow else 'deny'}.json;
    ip_ranges_refresh 1h;
  }}
  server {{
    listen 127.0.0.1:{port};
    location = /deny.json {{ root {root}; }}
    location = /allow.json {{ root {root}; }}
    location / {{
      pow_gate on;
      pow_gate_decision $decision;
      root {root}; try_files /index.html =404;
    }}
  }}
  {'invalid_review_directive on;' if invalid else ''}
}}
'''
    config = root / 'nginx.conf'; config.write_text(configuration())
    subprocess.run([str(nginx), '-p', str(root) + '/', '-c', str(config)], check=True)
    poll(lambda: (root / 'nginx.pid').exists() and (root / 'nginx.pid').read_text().strip().isdigit(), 'nginx did not write its pid file')
    pid = int((root / 'nginx.pid').read_text())
    def body():
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=2) as response:
            return response.read().decode()
    def worker():
        try:
            return max(map(int, subprocess.check_output(['pgrep', '-P', str(pid)], text=True).split()))
        except subprocess.CalledProcessError:
            return 0
    try:
        poll(lambda: (root / 'access.log').exists() and '/deny.json' in (root / 'access.log').read_text(), 'initial feed was not fetched')
        assert 'upstream-content' not in body(), 'original policy must deny verification'
        original_worker = worker()
        config.write_text(configuration(allow=True, invalid=True))
        os.kill(pid, signal.SIGHUP)
        poll(lambda: 'invalid_review_directive' in (root / 'error.log').read_text(), 'invalid reload was not rejected')
        os.kill(original_worker, signal.SIGKILL)
        poll(lambda: worker() > original_worker, 'worker was not respawned')
        # Wait until the respawned worker fetches its policy feed.
        time.sleep(.3)
        assert 'upstream-content' not in body(), 'FAILED reload changed the respawned worker verification policy'
        # Fail after HTTP postconfiguration and then respawn: the replay-zone
        # pointer must also come from the still-active configuration cycle.
        request = urllib.request.Request(f'http://127.0.0.1:{port}/', headers={'User-Agent': 'nojs-review'})
        with urllib.request.urlopen(request, timeout=2) as response:
            page = response.read().decode()
        grant = html.unescape(re.search(r'(/\.pow/pass\?t=[^"\s<>]+)', page).group(1))
        config.write_text(configuration(allow=True, late_failure=True))
        previous = worker(); os.kill(pid, signal.SIGHUP)
        poll(lambda: 'missing/error.log' in (root / 'error.log').read_text(), 'late reload failure was not rejected')
        os.kill(previous, signal.SIGKILL)
        poll(lambda: worker() > previous, 'worker was not respawned after late failure')
        time.sleep(1.1)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args): return None
        opener = urllib.request.build_opener(NoRedirect)
        request = urllib.request.Request(f'http://127.0.0.1:{port}' + grant, headers={'User-Agent': 'nojs-review'})
        try:
            opener.open(request, timeout=2)
            raise AssertionError('redemption should redirect')
        except urllib.error.HTTPError as response:
            assert response.code == 302 and response.headers.get('Set-Cookie'), 'late failed reload lost replay-zone context'
        try:
            opener.open(request, timeout=2)
            raise AssertionError('repeated redemption should fail')
        except urllib.error.HTTPError as response:
            assert response.code == 409, 'late failed reload lost one-use state'
        assert 'upstream-content' not in body(), 'late FAILED reload changed the verification policy'
        config.write_text(configuration(allow=True))
        previous = worker(); os.kill(pid, signal.SIGHUP)
        poll(lambda: worker() > previous, 'successful reload did not replace worker')
        poll(lambda: 'upstream-content' in body(), 'successful reload did not activate the new policy')
        print('PASS: early/late failed reloads preserve respawn policy and replay state; valid reload activates new policy')
    finally:
        os.kill(pid, signal.SIGQUIT)
        poll(lambda: not (root / 'nginx.pid').exists(), 'isolated nginx failed to stop')
