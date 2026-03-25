#!/usr/bin/env python3
"""Lab-only traffic generator to drive Sybil risk scoring upward.

This script intentionally produces low-diversity, bursty TLS handshakes against
ONE host so the following components trend high:
- resource_diversity (single host)
- velocity (high requests/minute)
- burstiness (quiet -> spike pattern)

Use only against systems you own or have permission to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import random
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


@dataclass
class Phase:
    duration_seconds: int
    handshakes_per_second: int
    concurrency: int


def parse_target(target: str, default_port: int) -> tuple[str, int, str]:
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname
        if not host:
            raise ValueError(f"invalid target: {target}")
        port = parsed.port or (443 if parsed.scheme == "https" else default_port)
        sni = host
        return host, port, sni

    if ":" in target:
        host, port_text = target.rsplit(":", 1)
        if not host:
            raise ValueError(f"invalid target: {target}")
        return host, int(port_text), host

    return target, default_port, target


def tls_handshake(host: str, port: int, sni: str, timeout: float) -> bool:
    context = ssl.create_default_context()
    # For scoring demos we only need ClientHello generation, not cert validation.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni):
                return True
    except Exception:
        return False


def run_phase(phase: Phase, host: str, port: int, sni: str, timeout: float) -> tuple[int, int]:
    stop_at = time.time() + phase.duration_seconds
    ok = 0
    fail = 0

    lock = threading.Lock()

    def worker() -> None:
        nonlocal ok, fail
        while time.time() < stop_at:
            start = time.time()
            success = tls_handshake(host, port, sni, timeout)
            with lock:
                if success:
                    ok += 1
                else:
                    fail += 1

            pace = 1.0 / max(phase.handshakes_per_second, 1)
            # Add jitter to avoid perfectly uniform traffic.
            sleep_for = max(0.0, pace + random.uniform(-0.003, 0.003) - (time.time() - start))
            time.sleep(sleep_for)

    with concurrent.futures.ThreadPoolExecutor(max_workers=phase.concurrency) as pool:
        futures = [pool.submit(worker) for _ in range(phase.concurrency)]
        for future in futures:
            future.result()

    return ok, fail


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate bursty TLS handshakes to raise Sybil threat score (lab use only)."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="https://example.com:443",
        help="Target URL/host, e.g. https://example.com or example.com:443",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Socket timeout in seconds (default: 2.0)",
    )

    # Minute-bucket friendly pattern: 2 calm minutes + 1 spike minute.
    parser.add_argument("--warmup-seconds", type=int, default=60)
    parser.add_argument("--warmup-rate", type=int, default=2)
    parser.add_argument("--warmup-concurrency", type=int, default=4)

    parser.add_argument("--mid-seconds", type=int, default=60)
    parser.add_argument("--mid-rate", type=int, default=2)
    parser.add_argument("--mid-concurrency", type=int, default=4)

    parser.add_argument("--spike-seconds", type=int, default=60)
    parser.add_argument("--spike-rate", type=int, default=40)
    parser.add_argument("--spike-concurrency", type=int, default=24)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    host, port, sni = parse_target(args.target, 443)

    phases = [
        Phase(args.warmup_seconds, args.warmup_rate, args.warmup_concurrency),
        Phase(args.mid_seconds, args.mid_rate, args.mid_concurrency),
        Phase(args.spike_seconds, args.spike_rate, args.spike_concurrency),
    ]

    print("Lab-only high-threat demo")
    print(f"target={host}:{port} sni={sni} timeout={args.timeout}s")
    print("pattern=warmup -> mid -> spike (single host for low diversity)")

    total_ok = 0
    total_fail = 0
    for i, phase in enumerate(phases, start=1):
        print(
            f"phase {i}: duration={phase.duration_seconds}s "
            f"rate={phase.handshakes_per_second}/worker/s concurrency={phase.concurrency}"
        )
        ok, fail = run_phase(phase, host, port, sni, args.timeout)
        total_ok += ok
        total_fail += fail
        print(f"  phase {i} results: ok={ok} fail={fail}")

    print(f"done: total_ok={total_ok} total_fail={total_fail}")
    print("check Grafana: Sybil Threat Lens + Sybil Overview")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
