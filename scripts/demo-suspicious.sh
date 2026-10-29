#!/usr/bin/env bash
# Fast local burst profile: one SNI, high rate.
set -euo pipefail
exec python3 scripts/demo_local_target_and_load.py --profile burst "$@"
