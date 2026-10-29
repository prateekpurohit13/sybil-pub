package ebpf

// -no-strip keeps generation dependent only on clang; the embedded objects are
// a few KB larger but llvm-strip is not required on every build host.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip XdpTcp xdp_tcp.c -- -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I.
