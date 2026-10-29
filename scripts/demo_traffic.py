#!/usr/bin/env python3
"""Drive real HTTPS traffic for Sybil demos.

The script sends TLS handshakes to real public HTTPS endpoints, not to a local
server. It can use curl_cffi browser profiles plus Python, Go, curl, and
OpenSSL TLS stacks to produce several client fingerprints.

Profiles are deliberately rate-capped. Use only with permission for any target
you supply explicitly. The built-in targets are low-rate public examples.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import random
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
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
LIB_CLIENTS = ["python", "go", "curl", "openssl"]
C2_CLIENT = "c2"
ALL_CLIENTS = BROWSER_PROFILES + LIB_CLIENTS + [C2_CLIENT]
ROOT = Path(__file__).resolve().parents[1]
GO_CLIENT = ROOT / ".demo" / "bin" / "go-client"
C2_HELLO = ROOT / "datasets" / "demo-c2-hello.bin"


@dataclass
class Config:
    name: str
    rate: int
    duration: int
    max_requests: int
    concurrency: int
    profiles: list[str]
    targets: list[str]
    warmup_seconds: int = 0
    warmup_rate: int = 1
    warmup_concurrency: int = 1


PROFILES = {
    "browse": Config(
        name="browse",
        rate=4,
        duration=12,
        max_requests=48,
        concurrency=4,
        profiles=BROWSER_PROFILES + LIB_CLIENTS,
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
        duration=5,
        max_requests=100,
        concurrency=16,
        profiles=["chrome131"],
        targets=["https://example.com/"],
        warmup_seconds=10,
        warmup_rate=1,
        warmup_concurrency=1,
    ),
    "c2": Config(
        name="c2",
        rate=40,
        duration=5,
        max_requests=200,
        concurrency=24,
        profiles=[C2_CLIENT],
        targets=["https://example.com/"],
        warmup_seconds=20,
        warmup_rate=1,
        warmup_concurrency=1,
    ),
    "flood": Config(
        name="flood",
        rate=40,
        duration=5,
        max_requests=200,
        concurrency=24,
        profiles=["chrome131"],
        targets=["https://example.com/"],
        warmup_seconds=10,
        warmup_rate=1,
        warmup_concurrency=1,
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Drive real HTTPS traffic for a Sybil demo")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="browse")
    parser.add_argument("--engine", choices=["auto", "curl", "ssl"], default="auto")
    parser.add_argument("--targets", help="Comma-separated HTTPS URLs (defaults to the public list)")
    parser.add_argument(
        "--clients",
        help="Comma-separated clients: chrome131, chrome136, firefox133, safari260, edge101, python, go, curl, openssl",
    )
    parser.add_argument("--profiles", help=argparse.SUPPRESS)
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
        profiles=split_list(args.clients) or split_list(args.profiles) or base.profiles,
        targets=split_list(args.targets) or base.targets,
        warmup_seconds=base.warmup_seconds,
        warmup_rate=base.warmup_rate,
        warmup_concurrency=base.warmup_concurrency,
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


def parse_target(target: str) -> tuple[str, int]:
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def python_request(context: ssl.SSLContext, target: str, timeout: float) -> bool:
    return ssl_handshake(context, target, timeout)


def curl_cli_request(target: str, timeout: float) -> bool:
    if shutil.which("curl") is None:
        return False
    try:
        result = subprocess.run(
            ["curl", "-k", "-sS", "-o", os.devnull, "--max-time", str(timeout), target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def openssl_request(target: str, timeout: float) -> bool:
    if shutil.which("openssl") is None:
        return False
    host, port = parse_target(target)
    if not host:
        return False
    try:
        result = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"{host}:{port}",
                "-servername", host,
                "-alpn", "http/1.1",
                "-tls1_3",
                "-quiet",
                "-no_ign_eof",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        return result.returncode == 0
    except Exception:
        return False


def go_request(target: str, timeout: float) -> bool:
    if not GO_CLIENT.exists():
        return False
    try:
        result = subprocess.run(
            [str(GO_CLIENT), target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        return result.returncode == 0
    except Exception:
        return False


def c2_request(target: str, timeout: float) -> bool:
    if not C2_HELLO.exists():
        return False
    host, port = parse_target(target)
    if not host:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(C2_HELLO.read_bytes())
        return True
    except Exception:
        return False


def send_request(
    client: str,
    context: ssl.SSLContext,
    curl_requests,
    target: str,
    timeout: float,
) -> bool:
    if client in BROWSER_PROFILES:
        if curl_requests is not None:
            return curl_request(curl_requests, target, client, timeout)
        return python_request(context, target, timeout)
    if client == "python":
        return python_request(context, target, timeout)
    if client == "go":
        return go_request(target, timeout)
    if client == "curl":
        return curl_cli_request(target, timeout)
    if client == "openssl":
        return openssl_request(target, timeout)
    if client == "c2":
        return c2_request(target, timeout)
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
        context = ssl_context()
        while not stop.is_set() and time.time() < deadline:
            with lock:
                if attempts >= config.max_requests:
                    return
                index = next_index
                next_index += 1
                attempts += 1
            target = config.targets[index % len(config.targets)]
            client = config.profiles[index % len(config.profiles)]

            started = time.time()
            success = send_request(client, context, curl_requests if use_curl else None, target, timeout)

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

    if "go" in config.profiles and not GO_CLIENT.exists():
        print(f"warning: {GO_CLIENT} is missing; run `make demo-deps` or drop `go`", file=sys.stderr)
        config.profiles = [client for client in config.profiles if client != "go"]
    if C2_CLIENT in config.profiles and not C2_HELLO.exists():
        print(f"warning: {C2_HELLO} is missing; dropping `c2`", file=sys.stderr)
        config.profiles = [client for client in config.profiles if client != C2_CLIENT]
    if not config.profiles:
        config.profiles = ["python"]

    unknown = [client for client in config.profiles if client not in ALL_CLIENTS]
    if unknown:
        print(f"error: unknown clients: {', '.join(unknown)}", file=sys.stderr)
        return 2

    print(f"profile={config.name} engine={engine}")
    print(f"targets={','.join(config.targets)}")
    print(f"clients={','.join(config.profiles)}")
    print(
        f"rate={config.rate}/s duration={config.duration}s "
        f"max_requests={config.max_requests} concurrency={config.concurrency}"
    )
    if config.warmup_seconds > 0:
        print(
            f"warmup={config.warmup_seconds}s rate={config.warmup_rate}/s "
            f"concurrency={config.warmup_concurrency}"
        )
    if engine == "ssl":
        print("warning: Python TLS produces one fingerprint; install curl_cffi for browser profiles")

    warmup_ok = 0
    warmup_fail = 0
    if config.warmup_seconds > 0:
        warmup = replace(
            config,
            name=f"{config.name}-warmup",
            rate=config.warmup_rate,
            duration=config.warmup_seconds,
            max_requests=config.warmup_rate * config.warmup_seconds,
            concurrency=config.warmup_concurrency,
        )
        warmup_ok, warmup_fail = run(warmup, engine, args.timeout, args.quiet)

    ok, fail = run(config, engine, args.timeout, args.quiet)
    print(
        f"done: ok={ok + warmup_ok} fail={fail + warmup_fail} "
        f"attempts={ok + fail + warmup_ok + warmup_fail}"
    )
    return 0 if ok + warmup_ok > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
