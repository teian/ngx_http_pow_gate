#!/usr/bin/env python3
"""Isolated native-nginx regression: pow_gate_state_file keeps clearances
across a full restart without reopening the one-use ledger.
Run unprivileged: python3 restart-test.py /path/to/nginx /path/to/module.so
"""
import argparse
import html
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('nginx', type=Path)
parser.add_argument('module', type=Path)
args = parser.parse_args()
if os.geteuid() == 0:
    parser.error('run this isolated regression as an unprivileged user')
nginx, module = args.nginx.resolve(), args.module.resolve()
AGENT = {'User-Agent': 'restart-review'}


def poll(check, message, timeout=5):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if check():
            return
        time.sleep(.05)
    raise AssertionError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


opener = urllib.request.build_opener(NoRedirect)


def scenario(persist):
    with tempfile.TemporaryDirectory(prefix='pow-restart-') as temporary:
        root = Path(temporary)
        (root / 'logs').mkdir()
        (root / 'hmac.key').write_text('isolated-known-test-key-not-production')
        (root / 'index.html').write_text('upstream-content')
        state = root / 'state' / 'issuer'
        state.parent.mkdir()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        config = root / 'nginx.conf'
        config.write_text(f'''load_module {module};
worker_processes 2;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 64; }}
http {{
  access_log off;
  pow_gate_hmac_key_file {root}/hmac.key;
  pow_gate_cookie_secure off;
  {f'pow_gate_state_file {state};' if persist else ''}
  server {{
    listen 127.0.0.1:{port};
    location / {{
      pow_gate on;
      pow_gate_decision challenge:nojs:1;
      root {root}; try_files /index.html =404;
    }}
  }}
}}
''')
        pid_file = root / 'nginx.pid'

        def start():
            subprocess.run([str(nginx), '-p', f'{root}/', '-c', str(config)], check=True)
            poll(lambda: pid_file.exists() and pid_file.read_text().strip().isdigit(),
                 'nginx did not write its pid file')

        def stop():
            os.kill(int(pid_file.read_text()), signal.SIGQUIT)
            poll(lambda: not pid_file.exists(), 'isolated nginx failed to stop')

        def page(cookie=None):
            headers = dict(AGENT, **({'Cookie': cookie} if cookie else {}))
            with urllib.request.urlopen(urllib.request.Request(base + '/', headers=headers), timeout=2) as response:
                return response.read().decode()

        def grant():
            return html.unescape(re.search(r'(/\.pow/pass\?t=[^"\s<>]+)', page()).group(1))

        def redeem(path):
            try:
                opener.open(urllib.request.Request(base + path, headers=AGENT), timeout=2)
            except urllib.error.HTTPError as response:
                return response.code, (response.headers.get('Set-Cookie') or '').split(';')[0]
            raise AssertionError('redemption must not answer 2xx')

        start()
        try:
            if persist:
                mode = stat.S_IMODE(state.stat().st_mode)
                assert mode == 0o600, f'state file mode {oct(mode)}'
                assert re.fullmatch(r'[0-9a-f]{64}\n', state.read_text()), 'state file format'
                before = state.read_text()
            spent, unspent = grant(), grant()
            time.sleep(1.1)
            code, cookie = redeem(spent)
            assert code == 302 and cookie, f'initial redemption failed ({code})'
            assert 'upstream-content' in page(cookie), 'fresh clearance rejected'

            stop()
            start()
            # Grants issued in the restored store's first second are refused.
            time.sleep(1.1)
            admitted = 'upstream-content' in page(cookie)
            if not persist:
                assert not admitted, 'without a state file a restart must invalidate clearances'
                return
            assert state.read_text() == before, 'restart rewrote the state file'
            assert admitted, 'clearance did not survive the restart'
            # The ledger is gone: neither the spent grant nor one that was
            # still outstanding may mint a clearance now.
            for name, path in (('spent', spent), ('outstanding', unspent)):
                code, minted = redeem(path)
                assert code == 400 and not minted, f'{name} pre-restart grant redeemed after restart ({code})'
            fresh = grant()
            time.sleep(1.1)
            code, minted = redeem(fresh)
            assert code == 302 and minted, f'post-restart grant rejected ({code})'
            assert redeem(fresh)[0] == 409, 'post-restart grant redeemed twice'
        finally:
            if pid_file.exists():
                stop()


scenario(persist=True)
scenario(persist=False)
print('PASS: state file keeps clearances across a restart, refuses pre-restart grants, and is not required')
