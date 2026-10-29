#!/usr/bin/env bash
# Real-HTTPS browse profile: several public hosts and browser fingerprints.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY=python3
if [ -x "${ROOT}/.demo/venv/bin/python" ]; then
  PY="${ROOT}/.demo/venv/bin/python"
fi
exec "${PY}" "${ROOT}/scripts/demo_traffic.py" --profile browse "$@"
