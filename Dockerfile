# Multi-stage build:
#  - builder: compile the Go binary (glibc toolchain + libpcap headers for cgo)
#  - runtime: slim Debian image with only runtime deps (libpcap + certs)
#
# Note: glibc images are required, not Alpine/musl. github.com/tursodatabase/go-libsql
# ships glibc-linked static libraries (lib/linux_amd64/libsql_experimental.a) and has
# no musl build, so linking fails on Alpine with undefined references to stat64,
# readdir64, gnu_get_libc_version, etc.

# Pinned to the toolchain required by go.mod (go 1.25.5); do not float.
ARG GO_VERSION=1.25.5
ARG DEBIAN_VERSION=bookworm
ARG BIN_NAME=sybil

# Stage 1: Build the Go binary
FROM golang:${GO_VERSION}-${DEBIAN_VERSION} AS builder
# gopacket/pcap and go-libsql both require cgo.
ENV CGO_ENABLED=1
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -o /out/${BIN_NAME} .

# Stage 2: The final runtime image (Tiny)
FROM debian:${DEBIAN_VERSION}-slim AS runtime
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --user-group app
COPY --from=builder /out/${BIN_NAME} ./${BIN_NAME}
COPY --from=builder /src/datasets ./datasets
# The container intentionally runs as non-root (USER app:app) and libpcap live
# capture needs privileges, so start it with capabilities instead of root:
#   docker run --cap-add=NET_RAW --cap-add=NET_ADMIN --network=host sybil ...
# docker-compose equivalent:
#   cap_add: [NET_RAW, NET_ADMIN]
#   network_mode: host
USER app:app) and libpcap live
# capture needs privileges, so start it with capabilities instead of root:
#   docker run --cap-add=NET_RAW --cap-add=NET_ADMIN --network=host sybil ...
# docker-compose equivalent:
#   cap_add: [NET_RAW, NET_ADMIN]
#   network_mode: host
>>>>>>> origin/main
USER app:app
ENTRYPOINT ["./sybil"]
