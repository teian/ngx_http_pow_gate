#!/usr/bin/env bash
# Check for a newer nginx release and update every pin in the repo: the
# Dockerfile ARGs (version, tarball SHA256, image digests), .cargo/config.toml,
# the compose files, README and docs. Used by .github/workflows/nginx-update.yml
# (daily cron → auto-PR), but safe to run locally:
#
#   ./scripts/update-nginx.sh          # update to the latest release, if any
#   ./scripts/update-nginx.sh 1.31.3   # pin an explicit version
#
# Exits 0 without touching anything when already up to date, or when the Docker
# Hub images for the new version aren't published yet (they lag the tarball —
# the next run retries). In Actions, writes updated/old/new to $GITHUB_OUTPUT.
set -euo pipefail
cd "$(dirname "$0")/.."

out() { if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "$1" >>"$GITHUB_OUTPUT"; fi; }

current=$(sed -n 's/^ARG NGINX_VERSION=//p' docker/Dockerfile)

if [ $# -ge 1 ]; then
  latest="$1"
else
  echo "==> latest nginx release tag"
  latest=$(git ls-remote --tags https://github.com/nginx/nginx.git 'release-*' |
    sed -n 's|.*refs/tags/release-\([0-9][0-9.]*\)$|\1|p' | sort -V | tail -1)
fi
[ -n "$latest" ] || { echo "could not determine the latest nginx version" >&2; exit 1; }

echo "==> current ${current}, latest ${latest}"
if [ "$latest" = "$current" ]; then
  echo "up to date"
  out "updated=false"
  exit 0
fi
# Never downgrade — guards against tag-parsing hiccups and typo'd arguments.
if [ "$(printf '%s\n%s\n' "$latest" "$current" | sort -V | tail -1)" != "$latest" ]; then
  echo "latest (${latest}) is older than current (${current}) — refusing to downgrade"
  out "updated=false"
  exit 0
fi

# The runtime images must exist before we can pin their digests. They usually
# appear on Docker Hub hours-to-days after the tarball; until then, do nothing.
registry="${REGISTRY:-mirror.gcr.io/library}"
echo "==> resolve image digests"
for tag in "${latest}" "${latest}-alpine"; do
  if ! docker buildx imagetools inspect "${registry}/nginx:${tag}" >/dev/null 2>&1; then
    echo "nginx:${tag} not on the registry yet — retrying on the next run"
    out "updated=false"
    exit 0
  fi
done
debian_digest=$(docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "${registry}/nginx:${latest}")
alpine_digest=$(docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "${registry}/nginx:${latest}-alpine")

echo "==> fetch tarball, compute SHA256"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL "https://nginx.org/download/nginx-${latest}.tar.gz" -o "$tmp"
sha256=$(sha256sum "$tmp" | cut -d' ' -f1)

echo "==> update pins: ${current} → ${latest}"
sed -i \
  -e "s|^ARG NGINX_VERSION=.*|ARG NGINX_VERSION=${latest}|" \
  -e "s|^ARG NGINX_DEBIAN_DIGEST=.*|ARG NGINX_DEBIAN_DIGEST=${debian_digest}|" \
  -e "s|^ARG NGINX_ALPINE_DIGEST=.*|ARG NGINX_ALPINE_DIGEST=${alpine_digest}|" \
  -e "s|^ARG NGINX_SHA256=.*|ARG NGINX_SHA256=${sha256}|" \
  docker/Dockerfile
sed -i "s/${current//./\\.}/${latest}/g" \
  .cargo/config.toml docker-compose.test.yml docker-compose.perf.yml README.md docs/*.md

out "updated=true"
out "old=${current}"
out "new=${latest}"
echo "==> done"
