package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// TestGeneratedSpec guards the embedded BPF object without loading it into the
// kernel (no root or NIC needed): the generated bindings, the XDP program and
// the perf/config maps must all survive ELF parsing.
func TestGeneratedSpec(t *testing.T) {
	spec, err := LoadXdpTcp()
	if err != nil {
		t.Fatalf("LoadXdpTcp() error = %v", err)
	}

	if spec.Programs["xdp_tcp_parser"] == nil {
		t.Fatal("missing xdp_tcp_parser program")
	}

	events, ok := spec.Maps["events"]
	if !ok {
		t.Fatal("missing events map")
	}
	if events.Type != ebpf.PerfEventArray {
		t.Fatalf("events map type = %v, want %v", events.Type, ebpf.PerfEventArray)
	}

	portConfig, ok := spec.Maps["port_config"]
	if !ok {
		t.Fatal("missing port_config map")
	}
	if portConfig.Type != ebpf.Array {
		t.Fatalf("port_config map type = %v, want %v", portConfig.Type, ebpf.Array)
	}
	if portConfig.MaxEntries != 1 {
		t.Fatalf("port_config max entries = %d, want 1", portConfig.MaxEntries)
	}
	if portConfig.KeySize != 4 || portConfig.ValueSize != 4 {
		t.Fatalf("port_config sizes = key %d / value %d, want 4 / 4", portConfig.KeySize, portConfig.ValueSize)
	}
}
