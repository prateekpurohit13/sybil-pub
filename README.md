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

Binary path:

```text
./bin/sybil
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
-ja4-lookup-url <url>   Optional JA4 enrichment URL or template
-ja4-db-url <url>       Optional libSQL/Turso JA4 database URL
-ja4-db-auth-token <t>  Optional auth token for the JA4 database
-http-addr <addr>       HTTP listen address for /metrics and /healthz
```

### Live Threat Scoring

When `-redis-addr` is set, Sybil keeps rolling JA4+IP state in Redis and emits a threat score with progressive actions:

- `resource_diversity` (30): strongest signal; low unique destination diversity pushes risk up. A real HTTP endpoint path earns full weight, an SNI host fallback earns 75%, and a per-source-IP bucket (no SNI, or `-risk-use-host-fallback=false`) earns 50%.
- `velocity` (30): higher requests per active minute push risk up. This is an active-minute rate: idle minutes are not zero-filled, so a slow drip and a burst compressed into the same active minutes read the same here. `burstiness` separates the two.
- `burstiness` (25): the newest minute is compared against the median of the preceding active minutes, so a single-minute spike is scored even before three buckets exist.
- `fingerprint_reputation` (15): JA4 DB metadata only nudges the score; it does not override behavior.

Default actions:

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

When enrichment is enabled, Sybil classifies traffic into demo-friendly categories such as `verified_browser`, `automation`, `vpn`, `mobile_app`, `known_unverified`, and `unknown`.
These labels feed the Grafana dashboards and also influence the reputation component of the threat score.

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
 C                         1          116           69           29           18
 CSS                       1          126          121            0            5
 Dockerfile                1           44           23           18            3
 Go                       33         8140         6673          561          906
 JavaScript                2           25           20            2            3
 JSON                      7        13553        13553            0            0
 Makefile                  1           29           20            0            9
 Python                    5          671          532           15          124
 Shell                     3          303          226           22           55
 SVG                       5            5            5            0            0
 TSX                      16         1349         1235            2          112
 TypeScript                5          257          214            4           39
 YAML                      5         8052         7466            0          586
─────────────────────────────────────────────────────────────────────────────────
 Markdown                  2          215            0          144           71
 |- BASH                   2           24           21            3            0
 (Total)                              239           21          147           71
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Total                    87        32909        30178          800         1931
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
<!-- tokei-end -->
