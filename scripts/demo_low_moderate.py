#!/usr/bin/env python3
"""Low/moderate local profile: many SNIs, medium rate."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    return subprocess.call(
        [sys.executable, "scripts/demo_local_target_and_load.py", "--profile", "moderate"]
    )


if __name__ == "__main__":
    raise SystemExit(main())
