#!/usr/bin/env python3
"""Refresh pinned mainline AND stable releases once their runtime images exist."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('version', nargs='?')
args = parser.parse_args()
manifest = ROOT / 'docker/nginx-versions.json'
pins = json.loads(manifest.read_text())
previous = json.loads(manifest.read_text())
def version_tuple(value):
    if not re.fullmatch(r'1\.\d+\.\d+', value):
        raise ValueError(f'invalid nginx release: {value!r}')
    return tuple(map(int, value.split('.')))
def channel(value):
    return 'mainline' if version_tuple(value)[1] % 2 else 'stable'
def label(data):
    return '_'.join(f'{name}-{data[name]["NGINX_VERSION"]}' for name in ['mainline', 'stable'])

if args.version:
    wanted = {channel(args.version): args.version}
else:
    tags = subprocess.check_output(['git', 'ls-remote', '--tags', 'https://github.com/nginx/nginx.git', 'release-*'], text=True, timeout=60)
    releases = re.findall(r'refs/tags/release-(1\.\d+\.\d+)$', tags, re.M)
    wanted = {name: max((v for v in releases if channel(v) == name), key=version_tuple) for name in ['mainline', 'stable']}
registry = os.environ.get('REGISTRY', 'mirror.gcr.io/library')
for name, version in wanted.items():
    old = pins[name]['NGINX_VERSION']
    if version_tuple(version) <= version_tuple(old):
        print(f'{name}: {old} is already current (candidate {version})')
        continue
    digests = []
    for tag in [version, version + '-alpine']:
        result = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', '--format', '{{.Manifest.Digest}}', f'{registry}/nginx:{tag}'], capture_output=True, text=True, timeout=60)
        digest = result.stdout.strip()
        if result.returncode or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            print(f'{name}: image {tag} unavailable; retain {old} and retry next run')
            break
        digests.append(digest)
    if len(digests) != 2:
        continue
    with urllib.request.urlopen(f'https://nginx.org/download/nginx-{version}.tar.gz', timeout=30) as response:
        tarball_hash = hashlib.file_digest(response, 'sha256').hexdigest()
    pins[name] = dict(NGINX_VERSION=version, NGINX_SHA256=tarball_hash,
                      NGINX_DEBIAN_DIGEST=digests[0], NGINX_ALPINE_DIGEST=digests[1])
    print(f'{name}: {old} -> {version}')

changed = pins != previous
if changed:
    manifest.write_text(json.dumps(pins, indent=2) + '\n')
    mainline = pins['mainline']
    dockerfile = ROOT / 'docker/Dockerfile'
    text = dockerfile.read_text()
    for key, value in mainline.items():
        text = re.sub(r'^ARG ' + key + r'=.*$', f'ARG {key}={value}', text, flags=re.M)
    dockerfile.write_text(text)
    for filename in ['docker-compose.test.yml', 'docker-compose.dev.yml', 'docker-compose.perf.yml']:
        path = ROOT / filename
        text = path.read_text()
        for key, value in mainline.items():
            text = re.sub(r'\$\{' + key + r':-[^}]*\}', '${' + key + ':-' + value + '}', text)
        path.write_text(text)
    path = ROOT / '.cargo/config.toml'
    path.write_text(re.sub(r'^NGX_VERSION = .*$', f'NGX_VERSION = "{mainline["NGINX_VERSION"]}"', path.read_text(), flags=re.M))
    for path in [ROOT / 'README.md', *(ROOT / 'docs').glob('*.md')]:
        # Preserve versions in dated review evidence. Only instructional docs
        # and the README's introductory/build sections track the current pins.
        if path.name in {'security.md', 'performance.md', 'testing.md'}:
            continue
        text = path.read_text()
        current, marker, review = text.partition('\n## Performance\n') if path.name == 'README.md' else (text, '', '')
        for name in ['mainline', 'stable']:
            current = current.replace(previous[name]['NGINX_VERSION'], pins[name]['NGINX_VERSION'])
        path.write_text(current + marker + review)
if os.environ.get('GITHUB_OUTPUT'):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write(f'updated={str(changed).lower()}\nold={label(previous)}\nnew={label(pins)}\n')
