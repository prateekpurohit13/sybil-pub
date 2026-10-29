## Usage

### Build

Generate eBPF bindings (required for `-backend ebpf`):

```bash
make generate
```

Build the binary:

```bash
make build
```

Note: the project uses CGO-enabled dependencies (`libpcap` and `go-libsql`), so builds must keep `CGO_ENABLED=1`.

Binary paths:

```text
./bin/sybil       live capture, scoring, metrics, API
./bin/ja4check    offline pcap/dataset comparison
./bin/ja4import   CSV to libSQL/SQLite importer
```

### Capture Backends

The binary supports two capture backends:

- `pcap` (default): easier for development and captures local/browser traffic reliably.
- `ebpf`: existing XDP path is preserved.

Run with `pcap` backend:

```bash
sudo ./bin/sybil -backend pcap -iface wlan0
```

Or with Makefile helper:

```bash
make run-pcap IFACE=wlan0
```

Run with `ebpf` backend:

```bash
sudo ./bin/sybil -backend ebpf -iface wlan0
```

### Useful Flags

```text
-v                              Full hello output (hex dump, parsed fields, component scores)
-iface <name>                   Capture interface: pcap device or XDP attach point (default: lo)
-backend <pcap|ebpf>            Capture backend (default: pcap)
-port <n>                       Filter to TCP flows where src or dst port matches (0 = all, max 65535)
-hello-out <path>               Save first detected TLS hello record bytes to file
-exit-after-hello               Exit after first detected TLS hello
-redis-addr <addr>              Enable Redis-backed live threat scoring
-redis-password <pwd>           Redis password (prefer $SYBIL_REDIS_PASSWORD)
-redis-db <n>                   Redis database number, >= 0 (default: 0)
-risk-key-prefix <key>          Redis prefix for scoring state
-redis-dial-timeout <dur>       Dial timeout for Redis (default: 5s)
-redis-read-timeout <dur>       Redis read timeout (default: 3s)
-redis-write-timeout <dur>      Redis write timeout (default: 3s)
-redis-pool-timeout <dur>       Wait for a pooled Redis connection (default: 4s)
-redis-pool-size <n>            Maximum Redis connection pool size (default: 32)
-redis-min-idle-conns <n>       Minimum idle Redis connections (default: 2)
-redis-connect-attempts <n>     Startup connect attempts before capture-only mode (default: 3)
-risk-delay-threshold <n>       Override delay threshold (default: 70; negative = scorer default)
-risk-rate-limit-threshold <n>  Override rate-limit threshold (default: 80; negative = scorer default)
-risk-challenge-threshold <n>   Override challenge threshold (default: 90; negative = scorer default)
-risk-block-threshold <n>       Override block threshold (default: 95; negative = scorer default)
-risk-use-host-fallback <bool>  Use SNI host as a weaker diversity signal (default: true)
-ja4-csv <path>                JA4+ mapping CSV for enrichment (takes precedence)
-risk-demo                     Fast demo scoring: 5s buckets, 2m window, lower thresholds
-risk-bucket-seconds <n>        Scoring bucket width override (0 = preset/default)
-risk-burst-min-buckets <n>     Minimum active buckets before burstiness (0 = preset/default)
-risk-burst-min-requests <n>    Minimum requests before burstiness (0 = preset/default)
-ja4-lookup-url <url>           Optional JA4 enrichment URL or template with %s
-ja4-lookup-timeout <dur>       Timeout for external JA4 lookups (default: 2s)
-ja4-db-url <url>               Optional libSQL/Turso JA4 database URL (prefer $DB_URL)
-ja4-db-auth-token <t>          Optional auth token for the JA4 database (prefer $AUTH_TOKEN)
-ja4-cache-ttl <dur>            Redis TTL for cached JA4 lookups (default: 30m)
-http-addr <addr>               Listen address for /metrics, /healthz and /api (default: 127.0.0.1:9090; empty disables)
-http-token <token>             Bearer token for /api endpoints (prefer $SYBIL_HTTP_TOKEN)
-http-cors-origins <list>       Comma-separated exact origins allowed to read /api cross-origin (default: none)
-http-read-header-timeout <d>   Max time to read request headers (default: 5s)
-http-read-timeout <dur>        Max time to read the whole request (default: 10s)
-http-write-timeout <dur>       Max time to write a response (default: 10s)
-http-idle-timeout <dur>        Max keep-alive idle time between requests (default: 60s)
```

Configuration is validated at startup. Bad values fail fast instead of surfacing at runtime: unknown `-backend`, empty `-iface`, `-port` above 65535, non-monotonic `-risk-*-threshold` overrides, negative `-redis-db`, non-positive Redis/JA4/HTTP timeouts, an unparseable `-http-addr`, a `-ja4-lookup-url` that is not http(s), and malformed `-http-cors-origins` entries (for example an origin containing a path or missing the scheme; a trailing slash is normalized away).

### Live Threat Scoring

When `-redis-addr` is set, Sybil keeps rolling JA4+IP state in Redis and emits a threat score with progressive actions:

- `resource_diversity` (30): strongest signal; low unique destination diversity pushes risk up. A real HTTP endpoint path earns full weight, an SNI host fallback earns 75%, and a per-source-IP bucket (no SNI, or `-risk-use-host-fallback=false`) earns 50%.
- `velocity` (30): higher requests per active minute push risk up. This is an active-minute rate: idle minutes are not zero-filled, so a slow drip and a burst compressed into the same active minutes read the same here. `burstiness` separates the two.
- `burstiness` (25): the newest minute is compared against the median of the preceding active minutes, so a single-minute spike is scored even before three buckets exist.
- `fingerprint_reputation` (15): JA4 DB metadata only nudges the score; it does not override behavior.

Default actions (each overridable with `-risk-delay-threshold`, `-risk-rate-limit-threshold`, `-risk-challenge-threshold` and `-risk-block-threshold`; the effective delay < rate-limit < challenge < block ordering is enforced at startup):

- `70+`: add delay
- `80+`: rate limit
- `90+`: challenge
- `95+`: block

Important: a raw TLS ClientHello does not expose encrypted HTTP paths. In the current sniffer flow, Sybil can only see SNI at handshake time, so the diversity model falls back to host-level diversity when no real endpoint is available, and to a per-source-IP bucket when there is no SNI either. Fallbacks are never silently zero-valued.

The reported score is normalized against the maximum weight the sensor can actually earn from the signals it has. `100` therefore means "as risky as the observable evidence allows", and the `70/80/90/95` thresholds stay reachable in host-only and SNI-less capture. When JA4 enrichment is disabled the denominator is behavior-only; when enrichment is enabled the reputation weight stays in the denominator even if a lookup errors, so an outage cannot inflate the score.

> **Threat model / enforcement:** actions are advisory only. Sybil is a passive sniffer: it prints the action and persists it with each assessment, but it does not delay, rate-limit, challenge, or block anything. The capture path (including the eBPF/XDP backend) always passes traffic; wiring these labels into an enforcement plane (proxy, firewall, upstream XDP verdict) is left to the operator.

### JA4 Enrichment

For demo mode, Sybil can enrich JA4 fingerprints from a read-only libSQL/Turso database.
The binary reads `DB_URL` and `AUTH_TOKEN` from the environment by default, or you can pass `-ja4-db-url` and `-ja4-db-auth-token`.
Prefer the environment variables on shared machines: CLI flags are visible to every local user via `ps` and `/proc/<pid>/cmdline`.

When enrichment is enabled, Sybil classifies traffic into demo-friendly categories such as `verified_browser`, `automation`, `vpn`, `mobile_app`, `known_unverified`, and `unknown`.
These labels feed the Grafana dashboards and also influence the reputation component of the threat score.

The bundled FoxIO mapping table can be used without a database:

```bash
sudo ./bin/sybil -backend pcap -iface wlan0 -redis-addr 127.0.0.1:6379 \
  -ja4-csv datasets/ja4plus-mapping.csv
```

`-ja4-csv` takes precedence over `-ja4-db-url` and `-ja4-lookup-url`.

### Dataset Comparison

`bin/ja4check` compares computed JA4 fingerprints with `datasets/ja4plus-mapping.csv`.
It reports `exact`, `ambiguous`, `prefix` (same `JA4_a` only), `unknown`, and
parse errors. Exact matches are required by `-strict`.

Compare explicit fingerprints:

```bash
./bin/ja4check -ja4 t13d1516h2_8daaf6152771_02713d6af862
```

Compare every ClientHello in an offline pcap/pcapng file:

```bash
./bin/ja4check -pcap capture.pcap -strict
./bin/ja4check -pcap capture.pcap -port 443 -json
```

Or through Make:

```bash
make verify-ja4 PCAP=capture.pcap
```

Additional options:

```text
-db <dsn>             Read a libSQL/SQLite fingerprints table instead of CSV
-db-auth-token <t>    Auth token for a remote libSQL database
-lenient              Skip invalid JA4 rows in community CSV exports
-max-matches <n>      Cap reported matches per fingerprint (default 20)
```

Sybil uses the libSQL driver, which reads local SQLite files and remote Turso
databases. Import the committed CSV into a local database:

```bash
./bin/ja4import -dataset datasets/ja4plus-mapping.csv \
  -db file:datasets/ja4.db -replace
./bin/ja4check -db file:datasets/ja4.db -ja4 t13d1516h2_8daaf6152771_02713d6af862
make ja4-db DB=file:datasets/ja4.db
```

The loader also accepts JA4DB-style headers (`ja4_fingerprint`, ...) and the
frozen JA4DB export, which needs `-lenient`. Free pcap and mapping sources are
listed in `datasets/README.md`; `scripts/fetch-ja4-samples.sh` downloads a
small FoxIO pcap set.

The CSV contains fingerprint labels, not packet payloads. Wire-level validation
therefore requires a pcap; the CSV alone cannot prove that a ClientHello was
parsed correctly.

### Metrics And Grafana

Sybil now serves:

- `GET /metrics`
- `GET /healthz`
- `GET /api/...` (read-only dashboard data: totals, timeseries, recent requests, top threats, fingerprint rankings)

The default observability address is `127.0.0.1:9090` (loopback only, because `/api` exposes source/destination IPs, JA4 fingerprints and threat history). Pass `-http-addr :9090` to listen on all interfaces, or an empty `-http-addr` to disable the server. Protect a non-loopback listener with `-http-token` and list any browser origins that may read `/api` with `-http-cors-origins` (a wildcard is rejected).

Bring up Redis, Prometheus, and Grafana:

```bash
docker compose up -d
```

Grafana:

- URL: `http://127.0.0.1:3000`
- Username: `admin`
- Password: `admin`

Prometheus scrapes the Sybil process from `host.docker.internal:9090`, so run the Sybil binary on the host.

### Frontend Dashboard

The Redis-backed dashboard is the `sybil_fe` submodule. It reads the API at
`http://localhost:9090` by default and runs on port 3001 so it does not collide
with Grafana.

```bash
git submodule update --init sybil_fe
cd sybil_fe
npm exec --yes pnpm@12.16.1 install
npm exec --yes pnpm@12.16.1 dev
```

Open `http://localhost:3001`. The API endpoints require Sybil to be started with
`-redis-addr`; otherwise the frontend receives `503` responses.

### Demo Flow

Install the optional browser-profile client once (for multiple JA4s):

```bash
make demo-deps
```

One command starts Redis, the frontend and the pcap backend:

```bash
make demo
```

The backend runs in the foreground so its ClientHello output stays visible.
Redis must be installed natively (`redis-server` and `redis-cli`); Docker is not
required. On Arch:

```bash
sudo pacman -S redis
```

`make demo` uses a local libSQL database at `datasets/ja4.db`. On first run it
imports `datasets/ja4plus-mapping.csv` plus `datasets/demo-profiles.csv` (named
curl_cffi browser profiles) into that database; later runs use the same
database. Refresh it explicitly with:

```bash
make ja4-db DB=file:datasets/ja4.db
```

Use a remote libSQL/Turso dataset instead:

```bash
DEMO_DB_URL=libsql://your-db.turso.io \
DEMO_DB_TOKEN="$AUTH_TOKEN" \
make demo
```

`make demo` auto-detects the default network interface and captures TCP port
443. To run the backend manually instead:

```bash
sudo ./bin/sybil -backend pcap -iface wlan0 -port 443 \
  -redis-addr 127.0.0.1:6379 \
  -ja4-db-url file:datasets/ja4.db \
  -risk-demo -risk-key-prefix sybil:demo
```

`-risk-demo` uses 5-second buckets, a 2-minute window and demo thresholds
(`30/45/55/70`) so the dashboard reacts within seconds. Production defaults are
unchanged; do not use demo thresholds for real triage.

In a second terminal, generate a benign profile. It sends low-rate handshakes
to several real public HTTPS hosts with several browser impersonation profiles:

```bash
bash scripts/demo-benign.sh
```

Generate the malicious/C2-shaped profile:

```bash
bash scripts/demo-suspicious.sh
```

This runs a **lab C2 fixture** ClientHello with a 20-second quiet baseline at
1 handshake/s, then 40 handshakes/s for 5 seconds (200 spike attempts). The
fixture is labelled `C2 Lab Client (OpenSSL fixture)` with a `malware_like`
reputation in the demo database, so the score reaches roughly 84 and the action
is `block`. The label is synthetic and explicitly a lab fixture.

The separate browser-behaviour profile is still available:

```bash
python3 scripts/demo_traffic.py --profile burst
```

`make demo` captures all TCP/443 traffic on the interface, so background browser
or telemetry traffic can also appear. Use a loopback lab target or close other
browsers for a clean run. Known background Chrome/Firefox/LinkupBot variants observed in
this lab are mapped in `datasets/demo-profiles.csv`.

Point it at a lab-owned HTTPS target instead:

```bash
bash scripts/demo-suspicious.sh --targets https://localhost:8443/
```

For a vulnerable demo app such as OWASP Juice Shop, put a TLS terminator
(Caddy/nginx) in front of the app and use that HTTPS URL, then start the demo
capture on the matching interface/port:

```bash
DEMO_IFACE=lo DEMO_PORT=8443 make demo
bash scripts/demo-suspicious.sh --targets https://localhost:8443/
```

The `browse` profile uses these clients:

```text
chrome131, chrome136, firefox133, safari260, edge101,
python, go, curl, openssl
```

Each client's JA4 is mapped in `datasets/demo-profiles.csv`, so the frontend
shows `Chromium Browser`, `Firefox 133`, `Python 3.14 (OpenSSL)`,
`Go 1.27 (crypto/tls)`, `curl 8.x (OpenSSL)`, etc. instead of
`Unknown JA4 Client`.

Select specific clients:

```bash
bash scripts/demo-benign.sh --clients chrome131,python,go,openssl
python3 scripts/demo_traffic.py --profile moderate
python3 scripts/demo_traffic.py --profile flood
```

`make demo-deps` also builds the tiny Go ClientHello helper used by the `go`
client. Use `--engine ssl` if `curl_cffi` is unavailable; browser profiles then
fall back to Python TLS, while explicit `python`, `go`, `curl`, and `openssl`
clients still run their own stacks.

Reset demo state between presentations:

```bash
bash scripts/demo_reset.sh sybil:demo
```

The frontend refreshes every second during `make demo`
(`NEXT_PUBLIC_REFRESH_MS=1000`); the Grafana dashboards use a 2-second refresh
when that stack is running separately.

### Example Test Commands

Trigger browser-like TLS over TCP:

```bash
curl --http1.1 -I https://google.com
curl --http1.1 -I https://www.cloudflare.com
```

Local OpenSSL test (the generated pair is a throwaway localhost cert in the gitignored `scripts/testdata/` scratch dir; never commit it):

```bash
mkdir -p scripts/testdata
openssl req -x509 -newkey rsa:2048 -nodes -keyout scripts/testdata/key.pem -out scripts/testdata/cert.pem -days 1 -subj "/CN=localhost"
openssl s_server -accept 8443 -cert scripts/testdata/cert.pem -key scripts/testdata/key.pem
```

In another terminal:

```bash
sudo ./bin/sybil -backend pcap -iface lo
openssl s_client -connect 127.0.0.1:8443 -servername localhost
```

When a ClientHello is detected, Sybil prints parsed fields such as protocol, TLS version, SNI, ALPN, cipher count, and extension count.

## Secrets Hygiene

- Pass secrets through the environment, not CLI flags: flags are visible in `ps` and `/proc/<pid>/cmdline` to every local user.
  - `DB_URL` / `AUTH_TOKEN`: JA4 libSQL/Turso URL and read-only token. `-ja4-db-url` / `-ja4-db-auth-token` are optional overrides.
  - `SYBIL_REDIS_PASSWORD`: Redis password. `-redis-password` still works but is ps-visible.
  - `SYBIL_HTTP_TOKEN`: bearer token required on `/api` endpoints. `-http-token` still works but is ps-visible.
- `.env` is gitignored; `.env.example` lists the supported variables. The binary does not parse `.env` itself, so load it in the shell: `set -a; . ./.env; set +a`.
- `*.pem` files (including `scripts/testdata/cert.pem` and `key.pem`) are gitignored and excluded from the Docker build context by `.dockerignore`. They are throwaway local TLS test artifacts generated at runtime by the demo commands and `scripts/benchmark.sh`; never commit certificates or keys.
- No `*_FILE` indirection is supported yet; inject these variables with your secret manager (Docker/Kubernetes secret env, systemd `EnvironmentFile`, etc.).
- The Grafana `admin`/`admin` login, the passwordless Redis service, and the published `6379:6379` port in `docker-compose.yml` are local-dev defaults. Change the credentials and restrict the published ports before exposing the stack beyond localhost.

### Known Limitations

- TLS-over-TCP only: the sniffer reassembles TCP streams and parses TLS records, so QUIC/HTTP3 (UDP 443) and DTLS are not inspected. UDP traffic is ignored by both backends.
- A TLS ClientHello exposes the SNI host but never the encrypted HTTP path. Endpoint-level diversity therefore falls back to host-level diversity (`-risk-use-host-fallback=false` disables it), and to a per-source-IP bucket when there is no SNI.
- Actions are advisory. Sybil prints and persists the verdict; it never delays, rate-limits, challenges or blocks traffic. See the threat model note above.
- Capture needs elevated privileges: run the binary with `sudo`, or with `CAP_NET_RAW` (and `CAP_NET_ADMIN`/`CAP_BPF` for XDP). The Docker image ships a non-root user and expects `--cap-add=NET_RAW --cap-add=NET_ADMIN --network=host`.
- Risk scoring, the JA4 cache and the `/api` store require Redis. Without `-redis-addr` the sensor still captures and prints hellos; startup with an unreachable Redis degrades to capture-only mode instead of failing.

## License

MIT. The eBPF program in `ebpf/xdp_tcp.c` is dual MIT/GPL (the kernel requires a GPL-compatible license for the helpers it uses); see [LICENSE](LICENSE).

## References

- https://blog.cloudflare.com/ja4-signals/
- https://blog.foxio.io/ja4%2B-network-fingerprinting
- https://www.tigera.io/learn/guides/ebpf/
- https://ebpf.io/what-is-ebpf/

<!-- tokei-start -->
## Stats

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Language              Files        Lines         Code     Comments       Blanks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 C                         1          116           69           29           18
 CSS                       1          126          121            0            5
 Dockerfile                1           44           23           18            3
 Go                       41        10816         8735          927         1154
 JavaScript                2           25           20            2            3
 JSON                      7        13554        13554            0            0
 Makefile                  1           32           22            0           10
 Python                    5          677          536           15          126
 Shell                     3          318          236           25           57
 SVG                       5            5            5            0            0
 TSX                      17         1448         1326            6          116
 TypeScript                5          128           98           13           17
 Typst                     1          301          200           12           89
 YAML                      5         8052         7466            0          586
─────────────────────────────────────────────────────────────────────────────────
 Markdown                  2          264            0          186           78
 |- BASH                   2           25           22            3            0
 (Total)                              289           22          189           78
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Total                    97        35931        32433         1236         2262
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
<!-- tokei-end -->
