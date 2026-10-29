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
-iface <name>           Network interface (default: lo)
-backend <pcap|ebpf>    Capture backend (default: pcap)
-port <n>               Filter to TCP flows where src or dst port matches
-hello-out <path>       Save first detected TLS hello record bytes to file
-exit-after-hello       Exit after first detected TLS hello
-redis-addr <addr>      Enable Redis-backed live threat scoring
-redis-password <pwd>   Redis password
-redis-db <n>           Redis database number (default: 0)
-risk-key-prefix <key>  Redis prefix for scoring state
-ja4-csv <path>         JA4+ mapping CSV for enrichment (takes precedence)
-risk-demo              Fast demo scoring: 5s buckets, 2m window, lower thresholds
-risk-bucket-seconds <n> Scoring bucket width override (demo preset: 5)
-ja4-lookup-url <url>   Optional JA4 enrichment URL or template
-ja4-db-url <url>       Optional libSQL/Turso JA4 database URL
-ja4-db-auth-token <t>  Optional auth token for the JA4 database
-http-addr <addr>       HTTP listen address for /metrics and /healthz
```

### Live Threat Scoring

When `-redis-addr` is set, Sybil keeps rolling JA4+IP state in Redis and emits a threat score with progressive actions:

- `resource_diversity` (30): strongest signal; low unique endpoint diversity pushes risk up.
- `velocity` (30): higher requests per active minute push risk up.
- `burstiness` (25): sudden minute-level spikes push risk up.
- `fingerprint_reputation` (15): JA4 DB metadata only nudges the score; it does not override behavior.

Default actions:

- `70+`: add delay
- `80+`: rate limit
- `90+`: challenge
- `95+`: block

Important: a raw TLS ClientHello does not expose encrypted HTTP paths. In the current sniffer flow, Sybil can only see SNI at handshake time, so the diversity model falls back to host-level diversity when no real endpoint path is available. That fallback is intentionally weighted lower than true endpoint diversity.

### JA4 Enrichment

For demo mode, Sybil can enrich JA4 fingerprints from a read-only libSQL/Turso database.
The binary reads `DB_URL` and `AUTH_TOKEN` from the environment by default, or you can pass `-ja4-db-url` and `-ja4-db-auth-token`.

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

The default observability address is `:9090`.

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

Generate a capped burst against one real HTTPS target:

```bash
bash scripts/demo-suspicious.sh
```

The burst uses a 10-second quiet baseline at 1 handshake/s, then 20 handshakes/s
for 5 seconds (100 burst attempts). The baseline gives the burstiness signal
something to compare against.

`make demo` captures all TCP/443 traffic on the interface, so background browser
or telemetry traffic can also appear. Use a loopback lab target or close other
browsers for a clean run. Known background Chrome/Firefox variants observed in
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

Local OpenSSL test:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj "/CN=localhost"
openssl s_server -accept 8443 -cert cert.pem -key key.pem
```

In another terminal:

```bash
sudo ./bin/sybil -backend pcap -iface lo
openssl s_client -connect 127.0.0.1:8443 -servername localhost
```

When a ClientHello is detected, Sybil prints parsed fields such as protocol, TLS version, SNI, ALPN, cipher count, and extension count.

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
 C                         1           41           27            5            9
 CSS                       1          126          121            0            5
 Dockerfile                1           27           19            5            3
 Go                       34         7209         6195          151          863
 JavaScript                2           25           20            2            3
 JSON                      6         1378         1378            0            0
 Makefile                  1           48           37            0           11
 Python                    5          711          566           14          131
 Shell                     4           77           52           14           11
 SVG                       5            5            5            0            0
 TSX                      15         1331         1221            2          108
 TypeScript                4           69           60            0            9
 YAML                      6         8315         7688            0          627
─────────────────────────────────────────────────────────────────────────────────
 Markdown                  3          384            0          263          121
 |- BASH                   3           49           49            0            0
 (Total)                              433           49          263          121
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Total                    88        19795        17438          456         1901
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
<!-- tokei-end -->
