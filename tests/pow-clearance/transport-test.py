#!/usr/bin/env python3
"""Run the HTTP/3 suite against isolated local and optional Redis fixtures.
Invoke from a venv with http3-requirements.txt installed; pass HTTP/3 nginx.
"""
import os, signal, socket, subprocess, sys, tempfile, time, shutil, secrets
from pathlib import Path
nginx,module=map(lambda s:str(Path(s).resolve()),sys.argv[1:3])
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
for backend in (['local','redis'] if os.environ.get('POW_REDIS') else ['local']):
    with tempfile.TemporaryDirectory(prefix='pow-h3-'+backend+'-') as tmp:
        root=Path(tmp);(root/'logs').mkdir();(root/'key').write_text('isolated-http3-test-secret-key-32-bytes')
        (root/'healthz.txt').write_text('ok');(root/'index.html').write_text('upstream-content');(root/'ranges.json').write_text('{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"}]}')
        shutil.copyfile(module,root/'module.so')
        subprocess.run(['bash','scripts/test-tls.sh',str(root/'tls')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        http,tls=port(),port()
        config=Path('docker/nginx.test.conf').read_text().replace('modules/ngx_http_pow_gate_module.so',str(root/'module.so')).replace('/etc/pow/hmac.key',str(root/'key')).replace('/etc/pow/test-tls/',str(root/'tls')+'/').replace('/var/www',str(root))
        config=config.replace('listen 8080;',f'listen 127.0.0.1:{http};').replace('listen 8443 ',f'listen 127.0.0.1:{tls} ').replace('127.0.0.1:8080',f'127.0.0.1:{http}')
        config=f'pid {root}/nginx.pid; error_log {root}/error.log info;\n'+config
        if backend=='redis':
            namespace='h3_'+secrets.token_hex(8)
            subprocess.run(['python3','scripts/redis-epoch.py','--address',os.environ['POW_REDIS'],'--namespace',namespace,'--output',str(root/'epoch')],check=True,stdout=subprocess.DEVNULL)
            config=config.replace('http {',f'http {{\n pow_gate_redis {{ address {os.environ["POW_REDIS"]}; namespace {namespace}; epoch_file {root}/epoch; }}',1)
        path=root/'nginx.conf';path.write_text(config)
        subprocess.run([nginx,'-p',tmp+'/', '-c',str(path)],check=True)
        try:
            time.sleep(1.2) # initial Redis/feed health in every worker
            subprocess.run([sys.executable,'tests/pow-clearance/http3-test.py',f'https://127.0.0.1:{tls}','--ca-file',str(root/'tls/cert.pem')],check=True)
            print(f'ok: HTTP/3 {backend} backend',flush=True)
        except Exception:
            print((root/'error.log').read_text()[-6000:],file=sys.stderr);raise
        finally:
            os.kill(int((root/'nginx.pid').read_text()),signal.SIGQUIT);time.sleep(.2)
