.PHONY: build test setup generate run run-pcap verify-ja4 clean

IFACE ?= wlan0
PCAP ?=

generate:
	go generate ./ebpf

build: generate
	mkdir -p bin
	go build -o bin/sybil .
	go build -o bin/ja4check ./cmd/ja4check

run: build
	sudo ./bin/sybil -iface $(IFACE)

run-pcap: build
	sudo ./bin/sybil -backend pcap -iface $(IFACE)

test:
	go test ./...

verify-ja4:
	mkdir -p bin
	go build -o bin/ja4check ./cmd/ja4check
	./bin/ja4check -dataset datasets/ja4plus-mapping.csv $(if $(PCAP),-pcap $(PCAP),) -strict

setup:
	git config core.hooksPath .githooks

clean:
	rm -rf bin
	rm -f ebpf/xdptcp_bpfel.go ebpf/xdptcp_bpfel.o ebpf/xdptcp_bpfeb.go ebpf/xdptcp_bpfeb.o
