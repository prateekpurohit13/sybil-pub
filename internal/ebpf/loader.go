package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf ../../bpf/probe.c
