#!/usr/bin/env bash
# Real-HTTPS burst profile: one target, one browser fingerprint, capped rate.
# Point it at a lab-owned HTTPS target with: --targets https://host:port/
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY=python3
if [ -x "${ROOT}/.demo/venv/bin/python" ]; then
  PY="${ROOT}/.demo/venv/bin/python"
fi
exec "${PY}" "${ROOT}/scripts/demo_traffic.py" --profile burst "$@"
