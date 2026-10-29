#!/usr/bin/env python3
"""Capped burst against a real HTTPS target."""

from __future__ import annotations

import os
import subprocess
import sys


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    python = os.path.join(root, ".demo", "venv", "bin", "python")
    if not os.access(python, os.X_OK):
        python = sys.executable
    return subprocess.call([python, os.path.join(root, "scripts", "demo_traffic.py"), "--profile", "burst"])


if __name__ == "__main__":
    raise SystemExit(main())
