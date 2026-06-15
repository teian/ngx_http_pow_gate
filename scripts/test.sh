#!/usr/bin/env bash
# One command to run the whole verification pipeline locally — the same steps CI
# runs. Each stage is independent; a failure stops the run with a non-zero exit.
#
#   ./scripts/test.sh          # everything
#   ./scripts/test.sh core     # just the engine unit tests (fast, no Docker)
#   ./scripts/test.sh docker   # build module + nginx -t + e2e (needs Docker)
set -euo pipefail
cd "$(dirname "$0")/.."

stage="${1:-all}"

core_tests() {
  echo "==> core unit tests"
  ( cd src/pow-gate-core && cargo test )
}

docker_pipeline() {
  echo "==> core unit tests (in Docker)"
  docker build -f docker/Dockerfile --target core-test .

  echo "==> build module against nginx"
  docker build -f docker/Dockerfile --target module-build -t pow-gate-module .

  echo "==> nginx -t smoke (module loads + directives parse)"
  docker build -f docker/Dockerfile --target nginx-smoke -t pow-gate-nginx .

  echo "==> live end-to-end handshake"
  docker compose -f docker-compose.test.yml up --build \
    --abort-on-container-exit --exit-code-from e2e
  docker compose -f docker-compose.test.yml down -v
}

case "$stage" in
  core)   core_tests ;;
  docker) docker_pipeline ;;
  all)    core_tests; docker_pipeline ;;
  *) echo "usage: $0 [core|docker|all]" >&2; exit 2 ;;
esac

echo "All requested stages passed."
