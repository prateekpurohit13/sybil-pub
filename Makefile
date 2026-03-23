.PHONY: build test setup generate run clean

IFACE ?= wlan0

generate:
	go generate ./ebpf

build: generate
	mkdir -p bin
	go build -o bin/sybil main.go

run: build
	sudo ./bin/sybil -iface $(IFACE)

test:
	go test ./...

setup:
	git config core.hooksPath .githooks

clean:
	rm -rf bin
	rm -f ebpf/xdptcp_bpfel.go ebpf/xdptcp_bpfel.o ebpf/xdptcp_bpfeb.go ebpf/xdptcp_bpfeb.o
	rm -f traffic.log
