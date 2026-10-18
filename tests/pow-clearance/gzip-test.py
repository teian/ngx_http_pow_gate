#!/usr/bin/env python3
"""Generated MIME metadata must work with nginx's optional gzip body filter."""
import gzip
import http.client
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

nginx, module = (str(Path(value).resolve()) for value in sys.argv[1:3])
with tempfile.TemporaryDirectory(prefix='pow-gzip-') as temporary:
    root = Path(temporary)
    (root / 'logs').mkdir()
    (root / 'key').write_text('isolated-gzip-regression-secret-32-bytes')
    shutil.copyfile(module, root / 'module.so')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    custom = ('custom-☃ {{difficulty}} {{endpoint}}\n' * 32768).encode()
    (root / 'custom.html').write_bytes(custom)
    config = root / 'nginx.conf'
    config.write_text(f'''load_module {root}/module.so;
worker_processes 2;
pid {root}/nginx.pid; error_log {root}/error.log warn;
events {{ worker_connections 64; }}
http {{ access_log off;
 pow_gate_hmac_key_file {root}/key; pow_gate_cookie_secure off; pow_gate_difficulty 2000;
 server {{ listen 127.0.0.1:{port};
  location / {{ pow_gate on; }}
  location = /gzip-page {{ pow_gate on; gzip on; gzip_vary on; }}
  location = /custom {{ pow_gate on; pow_gate_page {root}/custom.html; gzip on; }}
  location = /.pow/solver.js {{ pow_gate on; gzip on; gzip_types text/javascript; gzip_vary on; }}
 }}
}}''')
    subprocess.run([nginx, '-p', temporary + '/', '-c', str(config)], check=True)
    try:
        def request(path, encoding='identity', method='GET', slow=False):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                connection.request(method, path, headers={'Accept-Encoding': encoding})
                response = connection.getresponse()
                if slow:
                    parts = []
                    while True:
                        part = response.read(4096)
                        if not part:
                            break
                        parts.append(part)
                        time.sleep(.0001)
                    body = b''.join(parts)
                else:
                    body = response.read()
                headers = response.headers
                assert response.status == 200, response.status
                assert len(headers.get_all('Content-Type')) == 1
                return headers, body
            finally:
                connection.close()

        headers, page = request('/')
        assert headers['Content-Type'] == 'text/html; charset=utf-8'
        assert headers['Cache-Control'] == 'no-store'
        page_headers, page_compressed = request('/gzip-page', 'gzip')
        assert page_headers['Content-Encoding'] == 'gzip'
        assert page_headers['Cache-Control'] == 'no-store'
        assert gzip.decompress(page_compressed) == page
        assert request('/')[1] == page
        version = re.search(rb'solver\.js\?v=([^"\']+)', page).group(1).decode()
        path = '/.pow/solver.js?v=' + version
        plain_headers, plain = request(path)
        compressed_headers, compressed = request(path, 'gzip')
        assert plain_headers['Content-Encoding'] is None
        assert compressed_headers['Content-Encoding'] == 'gzip'
        assert 'accept-encoding' in compressed_headers['Vary'].lower()
        assert compressed_headers['Content-Type'] == 'text/javascript; charset=utf-8'
        assert gzip.decompress(compressed) == plain
        assert len(compressed) < len(plain) / 2
        assert plain_headers['Cache-Control'] == compressed_headers['Cache-Control'] == 'public, max-age=31536000, immutable'
        denied_headers, denied = request(path, 'gzip;q=0, identity')
        assert denied_headers['Content-Encoding'] is None and denied == plain
        head_headers, head = request(path, 'gzip', 'HEAD')
        assert head_headers['Content-Type'] == 'text/javascript; charset=utf-8' and head == b''
        expected = custom.replace(b'{{difficulty}}', b'2000').replace(b'{{endpoint}}', b'/.pow/')
        _, large = request('/custom', slow=True)
        assert large == expected
        _, large_gzip = request('/custom', 'gzip')
        assert gzip.decompress(large_gzip) == expected
        assert request('/custom')[1] == expected
        assert request('/custom', method='HEAD')[1] == b''
        print(f'PASS: native MIME/charset, one Content-Type, gzip negotiation, Vary and HEAD; solver {len(plain)} -> {len(compressed)} bytes')
    finally:
        # Startup has completed by the time the responses above arrive.
        os.kill(int((root / 'nginx.pid').read_text()), signal.SIGQUIT)
        for _ in range(500):
            if not (root / 'nginx.pid').exists():
                break
            time.sleep(.01)
        else:
            raise AssertionError('isolated nginx did not stop')
