#!/usr/bin/env python3
"""Start a local TLS target server and drive bursty requests to it.

This script is intended for local/lab testing of Sybil scoring behavior.
It does two things in one process:
1. Starts a local HTTPS server (self-signed cert generated at runtime via openssl).
2. Sends phased request traffic to that server to emulate calm->spike behavior.
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
        # Keep output clean during high-rate tests.
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
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def request_once(host: str, port: int, sni: str, timeout: float, path: str) -> bool:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {sni}\r\n"
        "User-Agent: sybil-demo-client/1.0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as tls_sock:
                tls_sock.sendall(request)
                _ = tls_sock.recv(256)
        return True
    except Exception:
        return False


def run_phase(phase: Phase, host: str, port: int, sni: str, timeout: float, path: str) -> tuple[int, int]:
    stop_at = time.time() + phase.duration_seconds
    ok = 0
    fail = 0
    lock = threading.Lock()

    def worker() -> None:
        nonlocal ok, fail
        pace = 1.0 / max(phase.requests_per_worker_per_second, 1)
        while time.time() < stop_at:
            started = time.time()
            success = request_once(host, port, sni, timeout, path)
            with lock:
                if success:
                    ok += 1
                else:
                    fail += 1

            jitter = random.uniform(-0.004, 0.004)
            sleep_for = max(0.0, pace + jitter - (time.time() - started))
            time.sleep(sleep_for)

    with concurrent.futures.ThreadPoolExecutor(max_workers=phase.concurrency) as pool:
        futures = [pool.submit(worker) for _ in range(phase.concurrency)]
        for future in futures:
            future.result()

    return ok, fail


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Start local TLS server and send bursty traffic to it")
    p.add_argument("--bind", default="127.0.0.1", help="Server bind address (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=9443, help="Server port (default: 9443)")
    p.add_argument("--sni", default="localhost", help="TLS SNI and Host header (default: localhost)")
    p.add_argument("--path", default="/", help="HTTP path to request (default: /)")
    p.add_argument("--timeout", type=float, default=2.0, help="Socket timeout seconds")

    p.add_argument("--warmup-seconds", type=int, default=60)
    p.add_argument("--warmup-rate", type=int, default=2)
    p.add_argument("--warmup-concurrency", type=int, default=4)

    p.add_argument("--mid-seconds", type=int, default=60)
    p.add_argument("--mid-rate", type=int, default=2)
    p.add_argument("--mid-concurrency", type=int, default=4)

    p.add_argument("--spike-seconds", type=int, default=60)
    p.add_argument("--spike-rate", type=int, default=40)
    p.add_argument("--spike-concurrency", type=int, default=24)
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not shutil_which("openssl"):
        print("error: openssl is required but was not found in PATH")
        return 2

    phases = [
        Phase("warmup", args.warmup_seconds, args.warmup_rate, args.warmup_concurrency),
        Phase("mid", args.mid_seconds, args.mid_rate, args.mid_concurrency),
        Phase("spike", args.spike_seconds, args.spike_rate, args.spike_concurrency),
    ]

    with tempfile.TemporaryDirectory(prefix="sybil-demo-") as tmp:
        cert_path = os.path.join(tmp, "cert.pem")
        key_path = os.path.join(tmp, "key.pem")
        generate_self_signed_cert(cert_path, key_path, args.sni)

        server = start_https_server(args.bind, args.port, cert_path, key_path)
        print(f"local TLS target started on https://{args.bind}:{args.port}{args.path}")
        print("traffic pattern: warmup -> mid -> spike")

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
                    sni=args.sni,
                    timeout=args.timeout,
                    path=args.path,
                )
                total_ok += ok
                total_fail += fail
                print(f"  {phase.name} results: ok={ok} fail={fail}")
        finally:
            server.shutdown()
            server.server_close()

    print(f"done: total_ok={total_ok} total_fail={total_fail}")
    print("watch Sybil Threat Lens and Sybil Overview during the run")
    return 0


def shutil_which(binary: str) -> bool:
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return True
    return False


if __name__ == "__main__":
    raise SystemExit(main())
