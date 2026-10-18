"""Regression: a new stable release must update alongside a new mainline release."""
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]

class ChannelUpdates(unittest.TestCase):
    def run_update(self, unavailable=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ['scripts', 'docker', '.cargo', 'docs']:
                (root / directory).mkdir()
            files = ['scripts/update-nginx.py', 'docker/nginx-versions.json', 'docker/Dockerfile',
                     '.cargo/config.toml', 'README.md', 'docker-compose.test.yml',
                     'docker-compose.dev.yml', 'docker-compose.perf.yml']
            for filename in files:
                shutil.copyfile(ROOT / filename, root / filename)
            old = json.loads((root / 'docker/nginx-versions.json').read_text())
            mainline = old['mainline']['NGINX_VERSION']
            stable = old['stable']['NGINX_VERSION']
            def following(version):
                parts = version.split('.'); parts[-1] = str(int(parts[-1]) + 1)
                return '.'.join(parts)
            next_mainline, next_stable = following(mainline), following(stable)
            snapshot = 'Reviewed nginx ' + mainline + ' and ' + stable + '\n'
            (root / 'docs/performance.md').write_text(snapshot)
            (root / 'docs/security.md').write_text(snapshot)
            (root / 'docs/testing.md').write_text(snapshot)
            tags = '\n'.join(f'hash\trefs/tags/release-{v}' for v in [mainline, stable, next_mainline, next_stable, '1.28.99'])
            def image(command, **kwargs):
                missing = unavailable and command[-1].endswith(next_stable + '-alpine')
                return subprocess.CompletedProcess(command, 1 if missing else 0, stdout='' if missing else 'sha256:' + 'a' * 64, stderr='')
            with patch.object(sys, 'argv', ['update-nginx.py']), \
                 patch('subprocess.check_output', return_value=tags), \
                 patch('subprocess.run', side_effect=image), \
                 patch('urllib.request.urlopen', side_effect=lambda *a, **k: io.BytesIO(b'test nginx source')), \
                 patch.dict(os.environ, {'GITHUB_OUTPUT': str(root / 'outputs')}):
                runpy.run_path(str(root / 'scripts/update-nginx.py'), run_name='__main__')
            result = json.loads((root / 'docker/nginx-versions.json').read_text())
            self.assertEqual(result['mainline']['NGINX_VERSION'], next_mainline)
            self.assertEqual(result['stable']['NGINX_VERSION'], stable if unavailable else next_stable)
            for filename in ['docker-compose.test.yml', 'docker-compose.dev.yml', 'docker-compose.perf.yml']:
                self.assertIn('${NGINX_VERSION:-' + next_mainline + '}', (root / filename).read_text())
            self.assertIn('updated=true', (root / 'outputs').read_text())
            for filename in ['performance.md', 'security.md', 'testing.md']:
                self.assertEqual((root / 'docs' / filename).read_text(), snapshot)
            self.assertIn('latest pinned **mainline ' + next_mainline, (root / 'README.md').read_text())
            if unavailable:
                self.assertEqual(result['stable'], old['stable'], 'never mix a new version with old image/source pins')

    def test_updates_both_release_channels(self):
        self.run_update()

    def test_unpublished_stable_image_preserves_entire_stable_pin(self):
        self.run_update(unavailable=True)

if __name__ == '__main__':
    unittest.main()
