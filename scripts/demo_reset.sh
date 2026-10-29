#!/usr/bin/env bash
# Clear a Sybil demo key prefix so a repeated demo starts from zero.
set -euo pipefail

PREFIX="${1:-sybil:demo}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"

if command -v redis-cli >/dev/null 2>&1; then
  redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" --scan --pattern "${PREFIX}:*" \
    | xargs -r redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" DEL >/dev/null
elif docker compose ps redis >/dev/null 2>&1; then
  docker compose exec -T redis sh -c \
    'redis-cli --scan --pattern "$1:*" | xargs -r redis-cli DEL >/dev/null' sh "${PREFIX}"
else
  echo "error: redis-cli not found and the compose redis service is not running" >&2
  exit 2
fi

echo "cleared keys under ${PREFIX}:*"
