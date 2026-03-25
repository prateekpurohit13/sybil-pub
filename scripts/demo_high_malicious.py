#!/usr/bin/env python3
"""High-risk traffic profile for Sybil demo.

This wrapper runs the local target/load generator with an aggressive burst pattern.
For clear malicious tagging in API cards, run Sybil with demo threshold overrides.
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
        "60",
        "--warmup-rate",
        "2",
        "--warmup-concurrency",
        "4",
        "--mid-seconds",
        "60",
        "--mid-rate",
        "2",
        "--mid-concurrency",
        "4",
        "--spike-seconds",
        "90",
        "--spike-rate",
        "60",
        "--spike-concurrency",
        "32",
    ]
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
