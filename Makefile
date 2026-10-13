.PHONY: build test vet setup generate run run-pcap benchmark clean

IFACE ?= wlan0

generate:
	go generate ./ebpf

build: generate
	mkdir -p bin
	go build -o bin/sybil .

vet:
	go vet ./...

run: build
	sudo ./bin/sybil -iface $(IFACE)

run-pcap: build
	sudo ./bin/sybil -backend pcap -iface $(IFACE)

test:
	go test ./...

setup:
	git config core.hooksPath .githooks

benchmark: build
	sudo IFACE=lo ./scripts/benchmark.sh

clean:
	rm -rf bin
	rm -f ebpf/xdptcp_bpfel.go ebpf/xdptcp_bpfel.o ebpf/xdptcp_bpfeb.go ebpf/xdptcp_bpfeb.o
