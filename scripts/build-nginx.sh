#!/usr/bin/env bash
# Build one fully pinned nginx channel. Examples:
# ./scripts/build-nginx.sh stable --target nginx-smoke-alpine
# ./scripts/build-nginx.sh mainline --target module-export-debian --output type=local,dest=dist
set -euo pipefail
cd "$(dirname "$0")/.."
channel="${1:?usage: build-nginx.sh mainline|stable [docker build options]}"
shift
pins=$(python3 scripts/nginx-versions.py "$channel")
args=()
while IFS= read -r pin; do args+=(--build-arg "$pin"); done <<<"$pins"
exec docker build -f docker/Dockerfile "${args[@]}" "$@" .
