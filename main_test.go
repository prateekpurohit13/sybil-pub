package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sophic00/sybil/internal/config"
	"github.com/sophic00/sybil/internal/dataset"
	sybildb "github.com/sophic00/sybil/internal/db"
)

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
