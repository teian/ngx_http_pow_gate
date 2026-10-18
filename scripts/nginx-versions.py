#!/usr/bin/env python3
"""Emit one pinned nginx channel's build arguments or its version."""
import argparse
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('channel', choices=['mainline', 'stable'])
parser.add_argument('--version', action='store_true')
args = parser.parse_args()
pins = json.loads((Path(__file__).resolve().parent.parent / 'docker/nginx-versions.json').read_text())[args.channel]
for key, pattern in {
    'NGINX_VERSION': r'1\.\d+\.\d+',
    'NGINX_SHA256': r'[a-f0-9]{64}',
    'NGINX_DEBIAN_DIGEST': r'sha256:[a-f0-9]{64}',
    'NGINX_ALPINE_DIGEST': r'sha256:[a-f0-9]{64}',
}.items():
    if not re.fullmatch(pattern, pins[key]):
        parser.error(f'invalid {key} pin')
if args.version:
    print(pins['NGINX_VERSION'])
else:
    for key, value in pins.items():
        print(f'{key}={value}')
