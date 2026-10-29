#!/usr/bin/env python3
"""Start a local TLS target and drive a fast, labelled Sybil demo profile.

The script is self-contained: it creates a temporary self-signed certificate,
starts a local HTTPS server, and sends real TLS handshakes at a controlled rate.
Profiles:

  benign    many SNIs, low rate          -> low diversity pressure
  moderate  many SNIs, medium rate       -> delay / rate-limit transition
  burst     one SNI, high rate           -> quick escalation
  flood     one SNI, very high rate      -> sustained pressure

It is intended for a lab-owned interface only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import random
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Phase:
    name: str
    duration_seconds: int
    requests_per_worker_per_second: int
    concurrency: int


PROFILES = {
    "benign": {
        "spike_seconds": 20,
        "spike_rate": 1,
        "spike_concurrency": 1,
        "snis": [f"cdn-{letter}.local" for letter in "abcdefgh"],
    },
    "moderate": {
        "spike_seconds": 15,
        "spike_rate": 3,
        "spike_concurrency": 8,
        "snis": [f"cdn-{letter}.local" for letter in "abcdefgh"],
    },
    "burst": {
        "warmup_seconds": 2,
        "warmup_rate": 2,
        "warmup_concurrency": 4,
        "mid_seconds": 2,
        "mid_rate": 2,
        "mid_concurrency": 4,
        "spike_seconds": 20,
        "spike_rate": 25,
        "spike_concurrency": 16,
        "sni": "c2.lab.local",
    },
    "flood": {
        "warmup_seconds": 2,
        "warmup_rate": 2,
        "warmup_concurrency": 4,
        "mid_seconds": 2,
        "mid_rate": 2,
        "mid_concurrency": 4,
        "spike_seconds": 30,
        "spike_rate": 40,
        "spike_concurrency": 24,
        "sni": "c2.lab.local",
    },
}


class QuietHandler(BaseHTTPRequestHandler):
    server_version = "SybilDemoTLS/1.0"

    def do_GET(self) -> None:  # noqa: N802
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


def generate_self_signed_cert(cert_path: str, key_path: str, common_name: str) -> None:
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        key_path,
        "-out",
        cert_path,
        "-days",
        "1",
        "-subj",
        f"/CN={common_name}",
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_https_server(bind: str, port: int, cert_path: str, key_path: str) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((bind, port), QuietHandler)
    httpd.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def make_client_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def build_http_request(path: str, sni: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {sni}\r\n"
        "User-Agent: sybil-demo-client/1.0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def request_once(context: ssl.SSLContext, request: bytes, host: str, port: int, sni: str, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as tls_sock:
                tls_sock.sendall(request)
                _ = tls_sock.recv(256)
        return True
    except Exception:
        return False


def run_phase(phase: Phase, host: str, port: int, snis: list[str], timeout: float, path: str, quiet: bool) -> tuple[int, int]:
    stop_at = time.time() + phase.duration_seconds
    ok = 0
    fail = 0
    counter = 0
    lock = threading.Lock()

    def worker() -> None:
        nonlocal ok, fail, counter
        context = make_client_context()
        pace = 1.0 / max(phase.requests_per_worker_per_second, 1)
        while time.time() < stop_at:
            with lock:
                sni = snis[counter % len(snis)]
                counter += 1

            started = time.time()
            success = request_once(context, build_http_request(path, sni), host, port, sni, timeout)
            with lock:
                if success:
                    ok += 1
                else:
                    fail += 1

            sleep_for = max(0.0, pace + random.uniform(-0.002, 0.002) - (time.time() - started))
            time.sleep(sleep_for)

    stop_monitor = threading.Event()

    def monitor() -> None:
        last_total = 0
        while not stop_monitor.wait(1.0):
            with lock:
                current_ok, current_fail = ok, fail
            total = current_ok + current_fail
            if not quiet:
                print(
                    f"  {phase.name}: {total} attempts "
                    f"({current_ok} ok, {current_fail} fail, +{total - last_total}/s)",
                    flush=True,
                )
            last_total = total

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=phase.concurrency) as pool:
            futures = [pool.submit(worker) for _ in range(phase.concurrency)]
            for future in futures:
                future.result()
    finally:
        stop_monitor.set()
        monitor_thread.join(timeout=2)

    return ok, fail


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Start a local TLS target and drive a fast Sybil demo profile")
    p.add_argument("--profile", choices=sorted(PROFILES), default="burst", help="Traffic profile (default: burst)")
    p.add_argument("--bind", default="127.0.0.1", help="Server bind address (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=9443, help="Server port (default: 9443)")
    p.add_argument("--sni", default=None, help="Single TLS SNI and Host header")
    p.add_argument("--snis", default=None, help="Comma-separated SNIs for benign diversity")
    p.add_argument("--path", default="/", help="HTTP path to request (default: /)")
    p.add_argument("--timeout", type=float, default=2.0, help="Socket timeout seconds")
    p.add_argument("--quiet", action="store_true", help="Suppress per-second progress lines")

    p.add_argument("--warmup-seconds", type=int, default=None)
    p.add_argument("--warmup-rate", type=int, default=None)
    p.add_argument("--warmup-concurrency", type=int, default=None)

    p.add_argument("--mid-seconds", type=int, default=None)
    p.add_argument("--mid-rate", type=int, default=None)
    p.add_argument("--mid-concurrency", type=int, default=None)

    p.add_argument("--spike-seconds", type=int, default=None)
    p.add_argument("--spike-rate", type=int, default=None)
    p.add_argument("--spike-concurrency", type=int, default=None)
    return p.parse_args()


def value(args: argparse.Namespace, name: str, profile: dict, default: int) -> int:
    explicit = getattr(args, name)
    if explicit is not None:
        return explicit
    return profile.get(name, default)


def main() -> int:
    args = parse_args()
    profile = PROFILES[args.profile]

    if not shutil_which("openssl"):
        print("error: openssl is required but was not found in PATH")
        return 2

    if args.snis:
        snis = [item.strip() for item in args.snis.split(",") if item.strip()]
    elif args.sni:
        snis = [args.sni]
    else:
        snis = profile.get("snis", [profile.get("sni", "localhost")])

    phases = [
        Phase("warmup", value(args, "warmup_seconds", profile, 0), value(args, "warmup_rate", profile, 1), value(args, "warmup_concurrency", profile, 1)),
        Phase("mid", value(args, "mid_seconds", profile, 0), value(args, "mid_rate", profile, 1), value(args, "mid_concurrency", profile, 1)),
        Phase("spike", value(args, "spike_seconds", profile, 20), value(args, "spike_rate", profile, 25), value(args, "spike_concurrency", profile, 16)),
    ]
    phases = [phase for phase in phases if phase.duration_seconds > 0]

    with tempfile.TemporaryDirectory(prefix="sybil-demo-") as tmp:
        cert_path = os.path.join(tmp, "cert.pem")
        key_path = os.path.join(tmp, "key.pem")
        generate_self_signed_cert(cert_path, key_path, snis[0])

        server = start_https_server(args.bind, args.port, cert_path, key_path)
        print(f"profile={args.profile} target=https://{args.bind}:{args.port}{args.path}")
        print(f"snis={','.join(snis)}")
        if args.profile in ("burst", "flood"):
            print("interval scoring: run Sybil with -risk-demo and a fresh -risk-key-prefix")
        print("watch Sybil frontend: Common Fingerprints, Recent Requests, Top Threats")

        total_ok = 0
        total_fail = 0
        try:
            for phase in phases:
                print(
                    f"phase={phase.name} duration={phase.duration_seconds}s "
                    f"rate={phase.requests_per_worker_per_second}/worker/s "
                    f"concurrency={phase.concurrency}"
                )
                ok, fail = run_phase(
                    phase=phase,
                    host=args.bind,
                    port=args.port,
                    snis=snis,
                    timeout=args.timeout,
                    path=args.path,
                    quiet=args.quiet,
                )
                total_ok += ok
                total_fail += fail
                print(f"  {phase.name} results: ok={ok} fail={fail}")
        finally:
            server.shutdown()
            server.server_close()

    print(f"done: total_ok={total_ok} total_fail={total_fail}")
    return 0


def shutil_which(binary: str) -> bool:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return True
    return False


if __name__ == "__main__":
    raise SystemExit(main())
