#!/usr/bin/env bash
# Start Redis (if needed), the Sybil frontend, and the pcap backend.
# The backend runs in the foreground so its ClientHello output stays visible.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE="${IFACE:-lo}"
PORT="${PORT:-9443}"
REDIS_ADDR="${REDIS_ADDR:-127.0.0.1:6379}"
API_ADDR="${API_ADDR:-:9090}"
FE_PORT="${FE_PORT:-3001}"
PREFIX="${RISK_PREFIX:-sybil:demo}"
DEMO_DIR="${DEMO_DIR:-${ROOT}/.demo}"

if [[ "${REDIS_ADDR}" == *:* ]]; then
  REDIS_HOST="${REDIS_ADDR%:*}"
  REDIS_PORT="${REDIS_ADDR##*:}"
else
  REDIS_HOST="${REDIS_ADDR}"
  REDIS_PORT="6379"
fi

STARTED_REDIS=0
FE_PID=""

mkdir -p "${DEMO_DIR}"

if [ ! -d "${ROOT}/sybil_fe" ]; then
  echo "error: frontend submodule is missing; run: git submodule update --init sybil_fe" >&2
  exit 2
fi

redis_ping() {
  redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" ping 2>/dev/null | grep -q PONG
}

cleanup() {
  trap - EXIT INT TERM
  if [ -n "${FE_PID}" ] && kill -0 "${FE_PID}" 2>/dev/null; then
    kill -- -"${FE_PID}" 2>/dev/null || kill "${FE_PID}" 2>/dev/null || true
  fi
  if [ "${STARTED_REDIS}" -eq 1 ]; then
    redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" shutdown nosave >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

if ! command -v redis-cli >/dev/null 2>&1; then
  echo "error: redis-cli is required." >&2
  echo "install Redis natively, for example: sudo pacman -S redis" >&2
  exit 2
fi

if ! redis_ping; then
  if ! command -v redis-server >/dev/null 2>&1; then
    echo "error: Redis is not running and redis-server is not installed." >&2
    echo "install Redis natively, for example: sudo pacman -S redis" >&2
    exit 2
  fi
  mkdir -p "${DEMO_DIR}/redis"
  redis-server \
    --bind "${REDIS_HOST}" \
    --port "${REDIS_PORT}" \
    --save "" \
    --appendonly no \
    --daemonize yes \
    --dir "${DEMO_DIR}/redis" \
    --pidfile "${DEMO_DIR}/redis.pid" \
    --logfile "${DEMO_DIR}/redis.log"
  STARTED_REDIS=1
  for _ in $(seq 1 50); do
    redis_ping && break
    sleep 0.1
  done
  if ! redis_ping; then
    echo "error: Redis did not start; see ${DEMO_DIR}/redis.log" >&2
    exit 2
  fi
  echo "redis: started on ${REDIS_HOST}:${REDIS_PORT}"
else
  echo "redis: using ${REDIS_HOST}:${REDIS_PORT}"
fi

bash "${ROOT}/scripts/demo_reset.sh" "${PREFIX}" >/dev/null 2>&1 || true

DEMO_DB_URL="${DEMO_DB_URL:-}"
DEMO_DB_TOKEN="${DEMO_DB_TOKEN:-}"
DEFAULT_DB_URL="file:${ROOT}/datasets/ja4.db"
if [ -z "${DEMO_DB_URL}" ]; then
  DEMO_DB_URL="${DEFAULT_DB_URL}"
fi

if [[ "${DEMO_DB_URL}" == file:* ]]; then
  db_path="${DEMO_DB_URL#file:}"
  if [[ "${db_path}" != /* ]]; then
    db_path="${ROOT}/${db_path}"
    DEMO_DB_URL="file:${db_path}"
  fi
  if [ "${DEMO_DB_URL}" = "${DEFAULT_DB_URL}" ] || [ ! -s "${db_path}" ]; then
    (cd "${ROOT}" && go build -o bin/ja4import ./cmd/ja4import)
    "${ROOT}/bin/ja4import" \
      -dataset "${ROOT}/datasets/ja4plus-mapping.csv" \
      -db "${DEMO_DB_URL}" -replace
  fi
fi

LOOKUP_ARGS=(-ja4-db-url "${DEMO_DB_URL}")
DATASET_LABEL="libSQL ${DEMO_DB_URL}"
if [ -n "${DEMO_DB_TOKEN}" ]; then
  LOOKUP_ARGS+=(-ja4-db-auth-token "${DEMO_DB_TOKEN}")
fi

(cd "${ROOT}" && go build -o bin/sybil .)

if ! command -v node >/dev/null 2>&1; then
  echo "error: Node.js is required for the frontend." >&2
  exit 2
fi
if ! command -v npx >/dev/null 2>&1; then
  echo "error: npx is required for the frontend." >&2
  exit 2
fi

if curl -fsS "http://127.0.0.1:${FE_PORT}" >/dev/null 2>&1; then
  echo "frontend: already running on http://127.0.0.1:${FE_PORT}"
else
  if [ ! -d "${ROOT}/sybil_fe/node_modules" ]; then
    echo "frontend: installing dependencies"
    (cd "${ROOT}/sybil_fe" && npx --yes pnpm@12.16.1 install)
  fi
  (
    cd "${ROOT}/sybil_fe"
    exec setsid env \
      NEXT_PUBLIC_API_URL="http://127.0.0.1:${API_ADDR##*:}" \
      NEXT_PUBLIC_REFRESH_MS="${FE_REFRESH_MS:-1000}" \
      npx --yes pnpm@12.16.1 dev \
      >"${DEMO_DIR}/frontend.log" 2>&1
  ) &
  FE_PID=$!

  ready=0
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:${FE_PORT}" >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "${FE_PID}" 2>/dev/null; then
      break
    fi
    sleep 0.5
  done
  if [ "${ready}" -ne 1 ]; then
    echo "error: frontend did not start; see ${DEMO_DIR}/frontend.log" >&2
    exit 2
  fi
  echo "frontend: http://127.0.0.1:${FE_PORT}"
fi

SUDO_CMD=()
if [ -n "${SUDO:-}" ]; then
  # Allow tests or a custom privilege wrapper.
  read -r -a SUDO_CMD <<<"${SUDO}"
elif [ "$(id -u)" -ne 0 ]; then
  SUDO_CMD=(sudo)
fi

cat <<EOF

Sybil demo is ready.

  API:      http://127.0.0.1:${API_ADDR##*:}
  Frontend: http://127.0.0.1:${FE_PORT}
  Redis:    ${REDIS_HOST}:${REDIS_PORT}
  Dataset:  ${DATASET_LABEL}
  Capture:  ${IFACE}:${PORT} (pcap output below)

In another terminal:
  bash scripts/demo_reset.sh ${PREFIX}
  bash scripts/demo-benign.sh
  bash scripts/demo-suspicious.sh

Press Ctrl+C here to stop the backend and any services started by this script.

EOF

"${SUDO_CMD[@]}" "${ROOT}/bin/sybil" \
  -backend pcap \
  -iface "${IFACE}" \
  -port "${PORT}" \
  -redis-addr "${REDIS_ADDR}" \
  "${LOOKUP_ARGS[@]}" \
  -risk-demo \
  -risk-key-prefix "${PREFIX}" \
  -http-addr "${API_ADDR}"
