#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Benchmark: eBPF vs pcap capture backend
#
# Runs sybil with each backend under an identical traffic load and compares
# packet throughput, TLS hello detection, processing latency, and resource
# usage (CPU / RSS).
#
# Requires: sudo, curl, jq (optional, for pretty JSON), /proc filesystem.
# ---------------------------------------------------------------------------

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "$SCRIPT_DIR")

IFACE="${IFACE:-lo}"
PORT="${PORT:-4433}"
HTTP_ADDR="${HTTP_ADDR:-:9099}"
DURATION="${DURATION:-15}"
TRAFFIC_CONCURRENCY="${TRAFFIC_CONCURRENCY:-6}"
TRAFFIC_REQUESTS="${TRAFFIC_REQUESTS:-120}"
BINARY="${BINARY:-$REPO_ROOT/bin/sybil}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

log()  { printf "${CYAN}[bench]${RESET} %s\n" "$*"; }
logb() { printf "${BOLD}%s${RESET}\n" "$*"; }
die()  { printf "${RED}error:${RESET} %s\n" "$*" >&2; exit 1; }

# http_listen_addr turns -http-addr into an address curl can reach locally.
# ":9099" binds all interfaces; curl needs a concrete loopback host, so
# prepend 127.0.0.1. An explicit "host:port" is used as-is.
http_listen_addr() {
    local addr="$1"
    if [[ "$addr" == :* ]]; then
        printf '127.0.0.1%s' "$addr"
    else
        printf '%s' "$addr"
    fi
}

cleanup() {
    if [[ -n "${SYBIL_PID:-}" ]] && kill -0 "$SYBIL_PID" 2>/dev/null; then
        sudo kill "$SYBIL_PID" 2>/dev/null || true
        wait "$SYBIL_PID" 2>/dev/null || true
    fi
    if [[ -n "${TLS_SERVER_PID:-}" ]] && kill -0 "$TLS_SERVER_PID" 2>/dev/null; then
        kill "$TLS_SERVER_PID" 2>/dev/null || true
        wait "$TLS_SERVER_PID" 2>/dev/null || true
    fi
    rm -f "${METRICS_FILE:-}" "${TLS_SERVER_SCRIPT:-}"
}
trap cleanup EXIT

METRICS_FILE=$(mktemp)
TLS_SERVER_SCRIPT=$(mktemp --suffix=.py)

# ---- preflight checks ----------------------------------------------------

command -v curl  >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required"
[[ -f "$BINARY" ]] || { log "Building sybil..."; make -C "$REPO_ROOT" build; }
[[ -f "$BINARY" ]] || die "binary not found at $BINARY"

# ---- tiny TLS server on loopback -----------------------------------------
# We spin up a minimal python TLS server so we can generate deterministic
# TLS traffic without relying on external hosts.

generate_tls_server() {
    cat > "$TLS_SERVER_SCRIPT" <<'PYEOF'
import http.server, ssl, sys, os

port = int(sys.argv[1]) if len(sys.argv) > 1 else 4433
certfile = os.environ.get("BENCH_CERT", "cert.pem")
keyfile  = os.environ.get("BENCH_KEY",  "key.pem")

if not (os.path.isfile(certfile) and os.path.isfile(keyfile)):
    import subprocess
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", keyfile, "-out", certfile,
        "-days", "1", "-nodes",
        "-subj", "/CN=localhost",
    ], check=True, capture_output=True)

handler = http.server.BaseHTTPRequestHandler
handler.do_GET = lambda self: (
    self.send_response(200),
    self.end_headers(),
    self.wfile.write(b"ok"),
)
handler.log_message = lambda *_: None

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile, keyfile)

srv = http.server.HTTPServer(("127.0.0.1", port), handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print(f"TLS server listening on 127.0.0.1:{port}", flush=True)
srv.serve_forever()
PYEOF
    python3 "$TLS_SERVER_SCRIPT" "$PORT" &
    TLS_SERVER_PID=$!
    sleep 1
    if ! kill -0 "$TLS_SERVER_PID" 2>/dev/null; then
        die "TLS server failed to start"
    fi
}

# ---- traffic generator ----------------------------------------------------

generate_traffic() {
    local reqs="$1" concurrency="$2"
    log "Sending $reqs TLS requests (concurrency=$concurrency) to 127.0.0.1:$PORT"
    seq "$reqs" | xargs -n1 -P "$concurrency" -I{} \
        curl -ksS -o /dev/null "https://127.0.0.1:${PORT}/" 2>/dev/null || true
}

# ---- metrics scraping -----------------------------------------------------

wait_for_health() {
    local addr="$1" tries=30
    while (( tries-- > 0 )); do
        if curl -fsS "http://${addr}/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.3
    done
    die "sybil health endpoint did not become ready"
}

scrape_metric() {
    local file="$1" name="$2" labels="${3:-}"
    if [[ -n "$labels" ]]; then
        grep "^${name}{.*${labels}" "$file" | head -1 | awk '{print $NF}'
    else
        grep "^${name}" "$file" | grep -v '{' | head -1 | awk '{print $NF}'
    fi
}

scrape_histogram_avg() {
    local file="$1" name="$2" labels="${3:-}"
    local sum count
    if [[ -n "$labels" ]]; then
        sum=$(grep "^${name}_sum{.*${labels}" "$file" | head -1 | awk '{print $NF}')
        count=$(grep "^${name}_count{.*${labels}" "$file" | head -1 | awk '{print $NF}')
    else
        sum=$(grep "^${name}_sum" "$file" | head -1 | awk '{print $NF}')
        count=$(grep "^${name}_count" "$file" | head -1 | awk '{print $NF}')
    fi
    if [[ -n "$count" && "$count" != "0" ]]; then
        awk "BEGIN {printf \"%.6f\", ${sum:-0}/${count}}"
    else
        echo "N/A"
    fi
}

# ---- resource usage via /proc --------------------------------------------

sample_proc_stats() {
    local pid="$1"
    if [[ -d "/proc/$pid" ]]; then
        local rss_pages
        rss_pages=$(awk '{print $24}' "/proc/$pid/stat" 2>/dev/null || echo 0)
        local rss_kb=$(( rss_pages * 4 ))

        local utime stime
        utime=$(awk '{print $14}' "/proc/$pid/stat" 2>/dev/null || echo 0)
        stime=$(awk '{print $15}' "/proc/$pid/stat" 2>/dev/null || echo 0)
        local cpu_ticks=$(( utime + stime ))

        echo "${rss_kb} ${cpu_ticks}"
    else
        echo "0 0"
    fi
}

# ---- run one backend ------------------------------------------------------

run_backend() {
    local backend="$1"
    local listen
    listen=$(http_listen_addr "$HTTP_ADDR")

    logb "=== Backend: $backend ==="

    sudo "$BINARY" \
        -backend "$backend" \
        -iface "$IFACE" \
        -port "$PORT" \
        -http-addr "$HTTP_ADDR" &
    SYBIL_PID=$!
    sleep 1

    if ! kill -0 "$SYBIL_PID" 2>/dev/null; then
        die "sybil ($backend) failed to start"
    fi

    wait_for_health "$listen"
    log "sybil ($backend) is ready (pid=$SYBIL_PID)"

    read -r rss_before cpu_before <<< "$(sample_proc_stats "$SYBIL_PID")"

    local t_start
    t_start=$(date +%s%N)

    generate_traffic "$TRAFFIC_REQUESTS" "$TRAFFIC_CONCURRENCY"

    log "Waiting ${DURATION}s for pipeline to settle..."
    sleep "$DURATION"

    local t_end
    t_end=$(date +%s%N)
    local wall_ms=$(( (t_end - t_start) / 1000000 ))

    read -r rss_after cpu_after <<< "$(sample_proc_stats "$SYBIL_PID")"

    curl -fsS "http://${listen}/metrics" > "$METRICS_FILE" 2>/dev/null

    local packets hellos errors uptime
    packets=$(scrape_metric "$METRICS_FILE" "sybil_capture_packets_total")
    hellos=$(scrape_metric "$METRICS_FILE" "sybil_tls_hellos_total" 'type="client"')
    errors=$(scrape_metric "$METRICS_FILE" "sybil_capture_errors_total")
    uptime=$(scrape_metric "$METRICS_FILE" "sybil_uptime_seconds")

    local avg_event_sec avg_event_us
    avg_event_sec=$(scrape_histogram_avg "$METRICS_FILE" "sybil_processing_duration_seconds" 'stage="event"')
    if [[ "$avg_event_sec" != "N/A" ]]; then
        avg_event_us=$(awk "BEGIN {printf \"%.1f\", ${avg_event_sec} * 1000000}")
    else
        avg_event_us="N/A"
    fi

    local pps="N/A"
    if [[ -n "$uptime" && "$uptime" != "0" ]]; then
        pps=$(awk "BEGIN {printf \"%.0f\", ${packets:-0}/${uptime}}")
    fi

    local cpu_delta=$(( cpu_after - cpu_before ))
    local peak_rss_kb="$rss_after"

    sudo kill "$SYBIL_PID" 2>/dev/null || true
    wait "$SYBIL_PID" 2>/dev/null || true
    SYBIL_PID=""

    sleep 1

    printf -v "R_${backend}_packets" '%s' "${packets:-0}"
    printf -v "R_${backend}_hellos" '%s' "${hellos:-0}"
    printf -v "R_${backend}_errors" '%s' "${errors:-0}"
    printf -v "R_${backend}_pps" '%s' "${pps}"
    printf -v "R_${backend}_avg_event_us" '%s' "${avg_event_us}"
    printf -v "R_${backend}_wall_ms" '%s' "${wall_ms}"
    printf -v "R_${backend}_rss_kb" '%s' "${peak_rss_kb}"
    printf -v "R_${backend}_cpu_ticks" '%s' "${cpu_delta}"
}

# ---- main -----------------------------------------------------------------

log "Interface=$IFACE  Port=$PORT  Duration=${DURATION}s  Requests=$TRAFFIC_REQUESTS  Concurrency=$TRAFFIC_CONCURRENCY"
echo

generate_tls_server

run_backend ebpf
run_backend pcap

# ---- report ---------------------------------------------------------------

echo
logb "============================== Results =============================="
printf "${BOLD}%-28s %15s %15s${RESET}\n" "Metric" "eBPF" "pcap"
printf "%-28s %15s %15s\n"   "---" "---" "---"
printf "%-28s %15s %15s\n"   "Packets captured"       "$R_ebpf_packets"      "$R_pcap_packets"
printf "%-28s %15s %15s\n"   "TLS ClientHellos"        "$R_ebpf_hellos"       "$R_pcap_hellos"
printf "%-28s %15s %15s\n"   "Capture errors"          "$R_ebpf_errors"       "$R_pcap_errors"
printf "%-28s %15s %15s\n"   "Packets/sec"             "$R_ebpf_pps"          "$R_pcap_pps"
printf "%-28s %12s µs %12s µs\n" "Avg event latency"   "$R_ebpf_avg_event_us" "$R_pcap_avg_event_us"
printf "%-28s %12s ms %12s ms\n" "Wall clock"           "$R_ebpf_wall_ms"      "$R_pcap_wall_ms"
printf "%-28s %12s KB %12s KB\n" "Peak RSS"             "$R_ebpf_rss_kb"       "$R_pcap_rss_kb"
printf "%-28s %15s %15s\n"   "CPU ticks (usr+sys)"     "$R_ebpf_cpu_ticks"    "$R_pcap_cpu_ticks"
logb "====================================================================="
