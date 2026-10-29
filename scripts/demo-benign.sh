#!/usr/bin/env bash
# Fast local benign profile: many SNIs, low rate.
set -euo pipefail
exec python3 scripts/demo_local_target_and_load.py --profile benign "$@"
