#!/usr/bin/env bash
# Refresh both latest mainline and latest stable pins. An explicit version
# updates its corresponding channel only: ./scripts/update-nginx.sh 1.31.7
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/update-nginx.py "$@"
