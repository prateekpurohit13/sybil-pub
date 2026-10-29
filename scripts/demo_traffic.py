#!/usr/bin/env python3
"""Drive real HTTPS traffic for Sybil demos.

The script sends TLS handshakes to real public HTTPS endpoints, not to a local
server. It can use curl_cffi impersonation profiles to produce several browser
fingerprints, or plain Python TLS as a dependency-free fallback.

Profiles are deliberately rate-capped. Use only with permission for any target
you supply explicitly. The built-in targets are low-rate public examples.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import random
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse

PUBLIC_TARGETS = [
    "https://example.com/",
    "https://www.google.com/",
    "https://www.cloudflare.com/",
    "https://github.com/",
    "https://www.wikipedia.org/",
    "https://mozilla.org/",
    "https://www.apple.com/",
    "https://www.microsoft.com/",
]

BROWSER_PROFILES = ["chrome131", "chrome136", "firefox133", "safari260", "edge101"]


@dataclass
class Config:
    name: str
    rate: int
    duration: int
    max_requests: int
    concurrency: int
    profiles: list[str]
    targets: list[str]


PROFILES = {
    "browse": Config(
        name="browse",
        rate=4,
        duration=12,
        max_requests=48,
        concurrency=4,
        profiles=BROWSER_PROFILES,
        targets=PUBLIC_TARGETS,
    ),
    "moderate": Config(
        name="moderate",
        rate=10,
        duration=8,
        max_requests=80,
        concurrency=8,
        profiles=["chrome131"],
        targets=PUBLIC_TARGETS,
    ),
    "burst": Config(
        name="burst",
        rate=20,
        duration=10,
        max_requests=200,
        concurrency=16,
        profiles=["chrome131"],
        targets=["https://example.com/"],
    ),
    "flood": Config(
        name="flood",
        rate=40,
        duration=8,
        max_requests=300,
        concurrency=24,
        profiles=["chrome131"],
        targets=["https://example.com/"],
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Drive real HTTPS traffic for a Sybil demo")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="browse")
    parser.add_argument("--engine", choices=["auto", "curl", "ssl"], default="auto")
    parser.add_argument("--targets", help="Comma-separated HTTPS URLs (defaults to the public list)")
    parser.add_argument("--profiles", help="Comma-separated curl_cffi impersonation profiles")
    parser.add_argument("--rate", type=int, help="Total attempts per second")
    parser.add_argument("--duration", type=int, help="Run duration in seconds")
    parser.add_argument("--max-requests", type=int, help="Hard attempt cap")
    parser.add_argument("--concurrency", type=int, help="Worker count")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def resolve_config(args: argparse.Namespace) -> Config:
    base = PROFILES[args.profile]
    return Config(
        name=base.name,
        rate=args.rate if args.rate is not None else base.rate,
        duration=args.duration if args.duration is not None else base.duration,
        max_requests=args.max_requests if args.max_requests is not None else base.max_requests,
        concurrency=args.concurrency if args.concurrency is not None else base.concurrency,
        profiles=split_list(args.profiles) or base.profiles,
        targets=split_list(args.targets) or base.targets,
    )


def split_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def load_curl():
    try:
        from curl_cffi import requests as curl_requests

        return curl_requests
    except Exception:
        return None


def ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def ssl_handshake(context: ssl.SSLContext, target: str, timeout: float) -> bool:
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        return False
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def curl_request(curl_requests, target: str, profile: str, timeout: float) -> bool:
    try:
        response = curl_requests.get(
            target,
            impersonate=profile,
            verify=False,
            timeout=timeout,
            stream=True,
        )
        response.close()
        return True
    except Exception:
        return False


def run(config: Config, engine: str, timeout: float, quiet: bool) -> tuple[int, int]:
    curl_requests = load_curl() if engine in ("auto", "curl") else None
    if engine == "curl" and curl_requests is None:
        print("error: curl_cffi is not installed; run `make demo-deps` or use --engine ssl", file=sys.stderr)
        return 0, 0
    use_curl = curl_requests is not None and engine != "ssl"

    if not use_curl and len(config.profiles) > 1:
        print("warning: the ssl engine ignores impersonation profiles", file=sys.stderr)

    deadline = time.time() + config.duration
    stop = threading.Event()
    lock = threading.Lock()
    attempts = 0
    ok = 0
    fail = 0
    next_index = 0
    pace = config.concurrency / max(config.rate, 1)

    def worker() -> None:
        nonlocal attempts, ok, fail, next_index
        context = ssl_context() if not use_curl else None
        while not stop.is_set() and time.time() < deadline:
            with lock:
                if attempts >= config.max_requests:
                    return
                index = next_index
                next_index += 1
                attempts += 1
            target = config.targets[index % len(config.targets)]
            profile = config.profiles[index % len(config.profiles)]

            started = time.time()
            if use_curl:
                success = curl_request(curl_requests, target, profile, timeout)
            else:
                success = ssl_handshake(context, target, timeout)

            with lock:
                if success:
                    ok += 1
                else:
                    fail += 1

            sleep_for = max(0.0, pace + random.uniform(-0.02, 0.02) - (time.time() - started))
            time.sleep(sleep_for)

    def monitor() -> None:
        last = 0
        while not stop.wait(1.0):
            with lock:
                current_ok, current_fail, current_attempts = ok, fail, attempts
            if not quiet:
                print(
                    f"  {config.name}: {current_attempts}/{config.max_requests} attempts "
                    f"({current_ok} ok, {current_fail} fail, +{current_attempts - last}/s)",
                    flush=True,
                )
            last = current_attempts

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.concurrency) as pool:
            futures = [pool.submit(worker) for _ in range(config.concurrency)]
            for future in futures:
                future.result()
    finally:
        stop.set()
        monitor_thread.join(timeout=2)

    return ok, fail


def main() -> int:
    args = parse_args()
    config = resolve_config(args)

    engine = args.engine
    if engine == "auto":
        engine = "curl" if load_curl() is not None else "ssl"

    print(f"profile={config.name} engine={engine}")
    print(f"targets={','.join(config.targets)}")
    print(f"clients={','.join(config.profiles)}")
    print(
        f"rate={config.rate}/s duration={config.duration}s "
        f"max_requests={config.max_requests} concurrency={config.concurrency}"
    )
    if engine == "ssl":
        print("warning: Python TLS produces one fingerprint; install curl_cffi for browser profiles")

    ok, fail = run(config, engine, args.timeout, args.quiet)
    print(f"done: ok={ok} fail={fail} attempts={ok + fail}")
    return 0 if ok > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
