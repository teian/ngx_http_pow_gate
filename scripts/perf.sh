#!/usr/bin/env bash
# Performance load test: build the module + nginx, then hammer it with the load
# generator and print req/s + latency per request class. See docs/performance.md.
#
#   ./scripts/perf.sh
#   PERF_DURATION=10 PERF_CONCURRENCY=16 PERF_MODES=cleared,proof ./scripts/perf.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8080}"
NAME="pow-gate-perf-nginx"

echo "==> build module + nginx image"
docker build -f docker/Dockerfile --target nginx-smoke -t pow-gate-nginx . >/dev/null

echo "==> start nginx on :${PORT}"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "${PORT}:8080" pow-gate-nginx >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
sleep 2

echo "==> microbenchmarks (engine crypto — the per-op bottleneck)"
cargo bench -p pow-gate-core --bench engine -- --warm-up-time 1 --measurement-time 2 2>/dev/null \
  | grep -E 'time:' || true

echo "==> HTTP load test"
( cd perf && \
  BASE_URL="http://localhost:${PORT}" \
  PERF_DURATION="${PERF_DURATION:-5}" \
  PERF_CONCURRENCY="${PERF_CONCURRENCY:-8}" \
  PERF_MODES="${PERF_MODES:-baseline,challenge,cleared,proof}" \
  cargo run --release -q )
