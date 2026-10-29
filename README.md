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

### Demo Flow

Start Sybil with Redis and DB enrichment:

```bash
export DB_URL="https://thia.shrimp-fujita.ts.net"
export AUTH_TOKEN="..."
sudo ./bin/sybil -backend pcap -iface wlan0 -redis-addr 127.0.0.1:6379
```

Generate baseline traffic:

```bash
bash scripts/demo-benign.sh
```

Generate bursty suspicious traffic:

```bash
bash scripts/demo-suspicious.sh https://example.com 60 12
```

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
 Dockerfile                1           27           19            5            3
 Go                       33         6579         5628          141          810
 JSON                      3         1284         1284            0            0
 Makefile                  1           33           24            0            9
 Python                    5          671          532           15          124
 Shell                     2           31           25            2            4
 YAML                      4           66           60            0            6
─────────────────────────────────────────────────────────────────────────────────
 Markdown                  2          231            0          157           74
 |- BASH                   2           28           25            2            1
 (Total)                              259           25          159           75
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Total                    52         8991         7624          327         1040
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
<!-- tokei-end -->
