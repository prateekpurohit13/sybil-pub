.PHONY: generate build test setup run

generate:
	go generate ./internal/ebpf/...

build: generate
	go build -o bin/analyzer ./cmd/analyzer

run: build
	sudo ./bin/analyzer -iface $(IFACE)

test:
	go test ./...

setup:
	git config core.hooksPath .githooks
