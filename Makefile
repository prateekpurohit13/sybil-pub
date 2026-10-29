.PHONY: build test setup generate run run-pcap demo verify-ja4 ja4-db clean

IFACE ?= wlan0
DEMO_IFACE ?= lo
REDIS_ADDR ?= 127.0.0.1:6379
DEMO_DB_URL ?=
DEMO_DB_TOKEN ?=
PCAP ?=
DB ?=

generate:
	go generate ./ebpf

build: generate
	mkdir -p bin
	go build -o bin/sybil .
	go build -o bin/ja4check ./cmd/ja4check
	go build -o bin/ja4import ./cmd/ja4import

run: build
	sudo ./bin/sybil -iface $(IFACE)

run-pcap: build
	sudo ./bin/sybil -backend pcap -iface $(IFACE)

demo:
	IFACE="$(DEMO_IFACE)" REDIS_ADDR="$(REDIS_ADDR)" \
	DEMO_DB_URL="$(DEMO_DB_URL)" DEMO_DB_TOKEN="$(DEMO_DB_TOKEN)" \
	./scripts/demo_up.sh

test:
	go test ./...

verify-ja4:
	mkdir -p bin
	go build -o bin/ja4check ./cmd/ja4check
	./bin/ja4check $(if $(DB),-db $(DB),-dataset datasets/ja4plus-mapping.csv) $(if $(PCAP),-pcap $(PCAP),) -strict

ja4-db:
	mkdir -p bin
	go build -o bin/ja4import ./cmd/ja4import
	./bin/ja4import -dataset datasets/ja4plus-mapping.csv -db $(if $(DB),$(DB),file:datasets/ja4.db) -replace

setup:
	git config core.hooksPath .githooks

clean:
	rm -rf bin
	rm -f ebpf/xdptcp_bpfel.go ebpf/xdptcp_bpfel.o ebpf/xdptcp_bpfeb.go ebpf/xdptcp_bpfeb.o
