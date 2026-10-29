#!/usr/bin/env python3
"""High-pressure local profile: one SNI, fast burst."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    return subprocess.call(
        [sys.executable, "scripts/demo_local_target_and_load.py", "--profile", "burst"]
    )


if __name__ == "__main__":
    raise SystemExit(main())
