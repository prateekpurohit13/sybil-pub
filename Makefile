.PHONY: generate build test setup run

generate:
	go generate ./internal/ebpf/...

build: generate
	go build -o bin/analyzer ./cmd/analyzer

test:
	go test ./...

setup:
	git config core.hooksPath .githooks
