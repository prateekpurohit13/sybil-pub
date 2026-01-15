# Multi-stage build:
#  - builder: compile the Go binary (with libpcap headers available for cgo builds)
#  - runtime: minimal Alpine image with only runtime deps (libpcap + certs)

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.20
ARG BIN_NAME=sybil

# Stage 1: Build the Go binary
FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
RUN apk add --no-cache gcc musl-dev libpcap-dev
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -o /out/${BIN_NAME} ./cmd

# Stage 2: The final runtime image (Tiny)
FROM alpine:${ALPINE_VERSION} AS runtime
WORKDIR /app
RUN apk add --no-cache libpcap ca-certificates && update-ca-certificates
COPY --from=builder /out/${BIN_NAME} ./${BIN_NAME}
RUN addgroup -S app && adduser -S app -G app
USER app:app
ENTRYPOINT ["./sybil"]
