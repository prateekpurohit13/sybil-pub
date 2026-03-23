package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go XdpTcp xdp_tcp.c -- -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I.
