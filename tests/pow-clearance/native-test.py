#!/usr/bin/env python3
"""Run the existing wire suites against an isolated local shared-memory backend."""
import os, signal, socket, subprocess, sys, tempfile, time, shutil
from pathlib import Path
nginx, module = map(lambda s: str(Path(s).resolve()),sys.argv[1:3])
with tempfile.TemporaryDirectory(prefix='pow-native-') as tmp:
    root=Path(tmp); (root/'logs').mkdir(); (root/'key').write_text('isolated-native-suite-secret-key-32-bytes'); (root/'index.html').write_text('upstream-content')
    shutil.copyfile(module,root/'module.so')
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    path=root/'nginx.conf'
    path.write_text(f'''load_module {root}/module.so;
pid {root}/nginx.pid; error_log {root}/error.log info;
worker_processes 4; events {{ worker_connections 256; }}
http {{ http2 on; access_log off;
 pow_gate_hmac_key_file {root}/key; pow_gate_cookie_secure off; pow_gate_difficulty 2000;
 map $http_user_agent $decision {{ default challenge; ~*nojs challenge:nojs:1; }}
 server {{ listen 127.0.0.1:{port};
  location / {{ pow_gate on; pow_gate_decision $decision; root {root}; try_files /index.html =404; }}
  location = /other-policy {{ pow_gate on; pow_gate_policy other; root {root}; try_files /index.html =404; }}
  location = /stronger {{ pow_gate on; pow_gate_difficulty 4000; root {root}; try_files /index.html =404; }}
 }}
}}''')
    subprocess.run([nginx,'-p',tmp+'/', '-c',str(path)],check=True)
    try:
        base=f'http://127.0.0.1:{port}'
        env={**os.environ,'NGINX_PID_FILE':str(root/'nginx.pid'),'POW_TEST_SECOND_IP':'127.0.0.2'}
        for test in ['security-test.mjs','http2-test.mjs','solve-test.mjs']:
            subprocess.run(['node','tests/pow-clearance/'+test,base],check=True,env=env)
    finally:
        os.kill(int((root/'nginx.pid').read_text()),signal.SIGQUIT);time.sleep(.2)
