.PHONY: build test vet setup generate run run-pcap demo demo-deps benchmark verify-ja4 ja4-db clean

IFACE ?= wlan0
DEMO_IFACE ?=
DEMO_PORT ?= 443
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

vet:
	go vet ./...

run: build
	sudo ./bin/sybil -iface $(IFACE)

run-pcap: build
	sudo ./bin/sybil -backend pcap -iface $(IFACE)

.demo/bin/go-client: cmd/demo-client/main.go
	mkdir -p .demo/bin
	go build -o .demo/bin/go-client ./cmd/demo-client

demo-deps: .demo/bin/go-client
	python3 -m venv .demo/venv
	.demo/venv/bin/pip install -q -r scripts/requirements-demo.txt

demo:
	IFACE="$(DEMO_IFACE)" PORT="$(DEMO_PORT)" REDIS_ADDR="$(REDIS_ADDR)" \
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

benchmark: build
	sudo IFACE=lo ./scripts/benchmark.sh

clean:
	rm -rf bin
	rm -f ebpf/xdptcp_bpfel.go ebpf/xdptcp_bpfel.o ebpf/xdptcp_bpfeb.go ebpf/xdptcp_bpfeb.o
