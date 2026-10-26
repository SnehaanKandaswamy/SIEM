#!/usr/bin/env bash
# Deploys (or rolls back to) a published image version on a Linux Docker host, verifies health, and
# automatically rolls back to the previously running version if the new one does not become healthy.
#
#   ./deploy.sh <version>            e.g. sha-abc1234 or v1.2.0   (never "latest")
#   GHCR credentials (optional, for private packages) are read from stdin: line 1 = user, line 2 = token.
#
# Expected layout in $PWD: docker-compose.yml, docker-compose.prod.yml, deploy/, and a .env with production secrets
# (created once by the operator; this script never writes secrets).
set -euo pipefail

VERSION="${1:?usage: deploy.sh <version>}"
[[ "$VERSION" == "latest" ]] && { echo "refusing to deploy :latest" >&2; exit 2; }
[[ "$VERSION" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid version string" >&2; exit 2; }
: "${IMAGE_NS:?IMAGE_NS (owner/repo) must be set}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/readyz}"
TIMEOUT="${HEALTH_TIMEOUT:-300}"
STATE_FILE=".deployed_version"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.prod.yml)

[[ -f .env ]] || { echo ".env missing in $(pwd)" >&2; exit 2; }
grep -q '^SIEM_ENV=production' .env || echo "WARNING: SIEM_ENV is not 'production' in .env" >&2

if ! read -r -t 1 GHCR_USER 2>/dev/null; then GHCR_USER=""; fi
if [[ -n "${GHCR_USER}" ]]; then
  read -r GHCR_TOKEN
  echo "${GHCR_TOKEN}" | docker login ghcr.io -u "${GHCR_USER}" --password-stdin >/dev/null
fi

PREVIOUS=""
[[ -f "$STATE_FILE" ]] && PREVIOUS="$(cat "$STATE_FILE")"

export SIEM_IMAGE_NAMESPACE="$IMAGE_NS"

wait_healthy() {
  local deadline=$((SECONDS + TIMEOUT))
  while ((SECONDS < deadline)); do
    if curl -fsS --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then return 0; fi
    sleep 5
  done
  return 1
}

deploy() {
  local v="$1"
  export SIEM_VERSION="$v"
  echo "==> pulling images for $v"
  "${COMPOSE[@]}" pull backend frontend migrate
  echo "==> applying (migrations run first via the 'migrate' service)"
  "${COMPOSE[@]}" up -d --no-build --remove-orphans
  echo "==> waiting for $HEALTH_URL"
  wait_healthy
}

if deploy "$VERSION"; then
  echo "$VERSION" >"$STATE_FILE"
  [[ -n "$PREVIOUS" ]] && echo "$PREVIOUS" >.previous_version
  echo "==> deployment of $VERSION healthy"
  exit 0
fi

echo "!! $VERSION did not become healthy within ${TIMEOUT}s" >&2
"${COMPOSE[@]}" logs --no-color --tail 80 backend migrate >&2 || true
if [[ -n "$PREVIOUS" && "$PREVIOUS" != "$VERSION" ]]; then
  echo "==> rolling back to $PREVIOUS" >&2
  if deploy "$PREVIOUS"; then
    echo "$PREVIOUS" >"$STATE_FILE"
    echo "rolled back to $PREVIOUS; deployment of $VERSION FAILED" >&2
  else
    echo "rollback to $PREVIOUS ALSO failed - manual intervention required" >&2
  fi
else
  echo "no previous version recorded; nothing to roll back to" >&2
fi
exit 1
