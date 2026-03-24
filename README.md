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
 Dockerfile                1           26           18            5            3
 Go                        6         1050          810           85          155
 Makefile                  1           23           16            0            7
 Markdown                  1           44            0           34           10
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Total                    11         1184          871          129          184
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
<!-- tokei-end -->
