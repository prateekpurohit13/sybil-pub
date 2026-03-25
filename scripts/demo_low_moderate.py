#!/usr/bin/env python3
"""Low/moderate traffic profile for Sybil demo.

This is a thin wrapper around demo_local_target_and_load.py with gentle settings.
Expected outcome with default thresholds: mostly clean, maybe mild suspicious spikes.
"""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    cmd = [
        sys.executable,
        "scripts/demo_local_target_and_load.py",
        "--port",
        "9443",
        "--warmup-seconds",
        "90",
        "--warmup-rate",
        "1",
        "--warmup-concurrency",
        "2",
        "--mid-seconds",
        "90",
        "--mid-rate",
        "1",
        "--mid-concurrency",
        "2",
        "--spike-seconds",
        "30",
        "--spike-rate",
        "4",
        "--spike-concurrency",
        "4",
    ]
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
