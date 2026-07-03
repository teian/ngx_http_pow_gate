#!/usr/bin/env bash
# Manual test sandbox: bring up nginx + the module on http://localhost:12222 and
# poke it by hand (browser or curl). See docs/testing.md → "Manual testing".
#
#   ./scripts/dev.sh up       # build + start, prints what to try
#   ./scripts/dev.sh reload   # apply an edited docker/nginx.dev.conf (no rebuild)
#   ./scripts/dev.sh logs     # follow nginx logs
#   ./scripts/dev.sh down     # stop + remove
#
#   DEV_PORT=9090 ./scripts/dev.sh up          # different host port
#   DEV_TARGET=nginx-smoke-alpine ./scripts/dev.sh up   # musl build
set -euo pipefail
cd "$(dirname "$0")/.."

compose() { docker compose -f docker-compose.dev.yml "$@"; }
port="${DEV_PORT:-12222}"

case "${1:-up}" in
  up)
    compose up --build -d
    cat <<EOF

Sandbox up: http://localhost:${port}

Try:
  browser  http://localhost:${port}/      challenge page → solver → reload shows 'upstream-content'
  curl -i  http://localhost:${port}/      challenge HTML (no clearance cookie yet)
  curl     http://localhost:${port}/healthz            'ok' — gate off, never challenged
  curl -A verifierbot http://localhost:${port}/        verified good bot → upstream directly
  curl -iA denybot    http://localhost:${port}/        denied

Config: docker/nginx.dev.conf (mounted) — edit, then: ./scripts/dev.sh reload
Module code changed? ./scripts/dev.sh up rebuilds the image.
EOF
    ;;
  reload)
    compose exec nginx nginx -t
    compose exec nginx nginx -s reload
    echo "reloaded"
    ;;
  logs)  compose logs -f nginx ;;
  down)  compose down -v ;;
  *) echo "usage: $0 [up|reload|logs|down]" >&2; exit 2 ;;
esac
