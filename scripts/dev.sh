#!/usr/bin/env bash
# Manual test sandbox: bring up nginx + the module on http://localhost:12222 and
# poke it by hand (browser or curl). See docs/testing.md → "Manual testing".
#
#   ./scripts/dev.sh up       # build + start, prints what to try
#   ./scripts/dev.sh check    # smoke checks + full node handshake against it
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
Automated: ./scripts/dev.sh check
EOF
    ;;
  check)
    base="http://localhost:${port}"
    fail=0
    check() { # <name> <expected> <actual>
      if [ "$2" = "$3" ]; then echo "  PASS  $1"; else echo "  FAIL  $1 (expected $2, got $3)"; fail=1; fi
    }
    echo "== smoke checks ($base)"
    check "no upstream without solve"  "no" "$(curl -s "$base/" | grep -q 'upstream-content' && echo yes || echo no)"
    check "solver endpoint"            "200" "$(curl -s -o /dev/null -w '%{http_code}' "$base/.pow/solver.js")"
    check "challenge endpoint"         "200" "$(curl -s -o /dev/null -w '%{http_code}' "$base/.pow/challenge")"
    check "excluded path (healthz)"    "ok" "$(curl -s "$base/healthz")"
    check "verified good bot"          "yes" "$(curl -s -A verifierbot "$base/" | grep -q 'upstream-content' && echo yes || echo no)"
    check "denied bot"                 "403" "$(curl -s -o /dev/null -w '%{http_code}' -A denybot "$base/")"
    if [ "$fail" != 0 ]; then
      echo "== FAILURES — logs: ./scripts/dev.sh logs"
      exit 1
    fi
    echo "== all smoke checks passed"
    if command -v node >/dev/null; then
      echo "== full handshake (node tests/pow-clearance/solve-test.mjs)"
      node tests/pow-clearance/solve-test.mjs "$base"
    else
      echo "== node not found — skipping the automated solve; test in a browser: $base"
    fi
    ;;
  reload)
    compose exec nginx nginx -t
    compose exec nginx nginx -s reload
    echo "reloaded"
    ;;
  logs)  compose logs -f nginx ;;
  down)  compose down -v ;;
  *) echo "usage: $0 [up|check|reload|logs|down]" >&2; exit 2 ;;
esac
