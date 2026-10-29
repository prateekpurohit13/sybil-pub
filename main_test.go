package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sophic00/sybil/internal/config"
	"github.com/sophic00/sybil/internal/dataset"
	sybildb "github.com/sophic00/sybil/internal/db"
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

func TestStartHTTPServerBindFailureIsFatal(t *testing.T) {
	// Occupy a port so the next bind fails. startHTTPServer must return the
	// error (main logs it as fatal) instead of serving headless.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := telemetry.NewRegistry("pcap", "lo")
	closeFn, err := startHTTPServer(ctx, config.Observability{HTTPAddr: ln.Addr().String()}, registry, nil)
	if err == nil {
		if closeFn != nil {
			closeFn()
		}
		t.Fatal("expected bind failure for an already-used port")
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

func TestNewLookupPrefersCSV(t *testing.T) {
	cfg := config.Risk{
		JA4CSVPath:   filepath.Join("datasets", "ja4plus-mapping.csv"),
		JA4LookupURL: "http://127.0.0.1:1/should-not-be-used",
	}

	lookup, closeLookup, err := newLookup(cfg)
	if err != nil {
		t.Fatalf("newLookup: %v", err)
	}
	defer closeLookup()

	record, err := lookup.Lookup(context.Background(), "t13d1516h2_8daaf6152771_02713d6af862")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if record.Application != "Chromium Browser" {
		t.Fatalf("unexpected record: %+v", record)
	}
}

func TestNewLookupDisabled(t *testing.T) {
	lookup, closeLookup, err := newLookup(config.Risk{})
	if err != nil {
		t.Fatalf("newLookup: %v", err)
	}
	defer closeLookup()
	if lookup != nil {
		t.Fatalf("expected nil lookup, got %T", lookup)
	}
}

func TestNewLookupFromSQLite(t *testing.T) {
	ctx := context.Background()
	store, err := dataset.Load(filepath.Join("datasets", "ja4plus-mapping.csv"))
	if err != nil {
		t.Fatalf("load dataset: %v", err)
	}

	dsn := "file:" + filepath.Join(t.TempDir(), "ja4.db")
	dbCfg := sybildb.SQLiteConfig{Driver: "libsql", DSN: dsn}
	if _, err := dataset.ExportSQLite(ctx, store, dbCfg, true); err != nil {
		t.Fatalf("export dataset: %v", err)
	}

	lookup, closeLookup, err := newLookup(config.Risk{JA4DBURL: dsn})
	if err != nil {
		t.Fatalf("newLookup: %v", err)
	}
	defer closeLookup()

	record, err := lookup.Lookup(ctx, "t13d1516h2_8daaf6152771_02713d6af862")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if record.Application != "Chromium Browser" {
		t.Fatalf("unexpected record: %+v", record)
	}
}
