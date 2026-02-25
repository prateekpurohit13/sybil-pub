## Usage

Generate eBPF code:

```
make generate
```

Build the analyzer binary:

```
make build
```

Run the analyzer (requires root privileges):

```
sudo ./bin/analyzer -iface lo
```

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
 C                         1          114           78           13           23
 Dockerfile                1           26           18            5            3
 Go                        9          615          438           89           88
 Makefile                  1           13            9            0            4
 Markdown                  1           46            0           34           12
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Total                    14          814          543          141          130
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
<!-- tokei-end -->
