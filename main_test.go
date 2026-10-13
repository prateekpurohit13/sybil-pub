package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sophic00/sybil/internal/config"
	"github.com/sophic00/sybil/internal/telemetry"
)

func TestRedisCircuitTripsAndRecovers(t *testing.T) {
	registry := telemetry.NewRegistry("pcap", "lo")
	circuit := newRedisCircuit(registry, 2, 30*time.Second)
	now := time.Now()

	if !circuit.allow(now) {
		t.Fatal("fresh circuit should allow")
	}
	circuit.failure(now)
	if !circuit.allow(now) {
		t.Fatal("circuit should stay closed below the failure threshold")
	}
	circuit.failure(now)
	if circuit.allow(now) {
		t.Fatal("circuit should open at the failure threshold")
	}
	if !circuit.allow(now.Add(31 * time.Second)) {
		t.Fatal("circuit should allow a half-open probe after the cooldown")
	}

	// A failed probe reopens the breaker for another cooldown.
	circuit.failure(now.Add(31 * time.Second))
	circuit.failure(now.Add(31 * time.Second))
	if circuit.allow(now.Add(32 * time.Second)) {
		t.Fatal("failed probes should reopen the circuit")
	}

	// A successful probe closes it.
	if !circuit.allow(now.Add(70 * time.Second)) {
		t.Fatal("circuit should half-open again")
	}
	circuit.success()
	if !circuit.allow(now.Add(71 * time.Second)) {
		t.Fatal("circuit should stay closed after a successful probe")
	}
}

func healthPayload(t *testing.T, registry *telemetry.Registry) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	registry.HealthHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode healthz: %v", err)
	}
	return payload
}

func TestHealthHandlerReportsRedisDegraded(t *testing.T) {
	registry := telemetry.NewRegistry("pcap", "lo")

	payload := healthPayload(t, registry)
	if _, ok := payload["redis"]; ok {
		t.Fatalf("redis state should be unreported before SetRedisUp, got %v", payload["redis"])
	}

	registry.SetRedisUp(false)
	payload = healthPayload(t, registry)
	if payload["status"] != "degraded" || payload["redis"] != "down" {
		t.Fatalf("expected degraded/down health, got %v", payload)
	}

	registry.SetRedisUp(true)
	payload = healthPayload(t, registry)
	if payload["status"] != "ok" || payload["redis"] != "up" {
		t.Fatalf("expected ok/up health, got %v", payload)
	}
}

func TestOpenRedisClientDegradesToCaptureOnly(t *testing.T) {
	registry := telemetry.NewRegistry("pcap", "lo")
	cfg := config.Risk{
		RedisAddr:            "127.0.0.1:1",
		RedisConnectAttempts: 1,
		RedisDialTimeout:     50 * time.Millisecond,
		RedisReadTimeout:     50 * time.Millisecond,
		RedisWriteTimeout:    50 * time.Millisecond,
	}

	client, closeFn := openRedisClient(context.Background(), cfg, registry)
	defer closeFn()
	if client != nil {
		t.Fatal("expected nil client on unreachable Redis")
	}

	payload := healthPayload(t, registry)
	if payload["status"] != "degraded" || payload["redis"] != "down" {
		t.Fatalf("expected degraded health after failed startup, got %v", payload)
	}
}
