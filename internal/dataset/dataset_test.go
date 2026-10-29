package dataset

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	sybildb "github.com/sophic00/sybil/internal/db"
	"github.com/sophic00/sybil/internal/risk"
)

func writeDataset(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapping.csv")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write dataset: %v", err)
	}
	return path
}

func TestLoadAndLookup(t *testing.T) {
	path := writeDataset(t, `Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes
Chromium Browser,,,,t13d1516h2_8daaf6152771_02713d6af862,,,,,,
,GoLang,,,t13d190900_9dc949149365_97f8aa674fd9,,,,,,
Sliver Agent,GoLang,,,t13d190900_9dc949149365_97f8aa674fd9,t130200_1301_a56c5b993250,,,,,
,,,Windows 10,,,,,64240_2-1-3-1-1-4_1460_8,,
`)

	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	stats := store.Stats()
	if stats.Rows != 4 || stats.JA4Rows != 3 || stats.UniqueJA4 != 2 || stats.DuplicateJA4 != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	chrome := store.Candidates("t13d1516h2_8daaf6152771_02713d6af862")
	if len(chrome) != 1 || chrome[0].Application != "Chromium Browser" {
		t.Fatalf("unexpected chrome candidates: %+v", chrome)
	}

	ambiguous := store.Candidates("t13d190900_9dc949149365_97f8aa674fd9")
	if len(ambiguous) != 2 {
		t.Fatalf("expected two ambiguous candidates, got %+v", ambiguous)
	}
	if ambiguous[0].Application != "Sliver Agent" {
		t.Fatalf("expected the more specific application first, got %+v", ambiguous)
	}

	record, err := store.Lookup(context.Background(), "t13d190900_9dc949149365_97f8aa674fd9")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if record.Application != "Sliver Agent" || record.JA4Fingerprint == "" {
		t.Fatalf("unexpected record: %+v", record)
	}

	if _, err := store.Lookup(context.Background(), "t13d000000_000000000000_000000000000"); !errors.Is(err, risk.ErrFingerprintNotFound) {
		t.Fatalf("expected ErrFingerprintNotFound, got %v", err)
	}
}

func TestPrefixCandidates(t *testing.T) {
	path := writeDataset(t, `Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes
Chromium Browser,,,,t13d1516h2_8daaf6152771_02713d6af862,,,,,,
Chromium Browser,,,,t13d1516h2_8daaf6152771_b0da82dd1658,,,,,,
Firefox,,,,t13d1715h2_5b57614c22b0_7121afd63204,,,,,,
`)

	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	candidates := store.PrefixCandidates("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb")
	if len(candidates) != 2 {
		t.Fatalf("expected two prefix candidates, got %+v", candidates)
	}
}

func TestLoadRejectsMalformedJA4(t *testing.T) {
	path := writeDataset(t, `Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes
Bad,,,,not-a-ja4,,,,,,
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected malformed ja4 error")
	}
}

func TestLoadRequiresJA4Column(t *testing.T) {
	path := writeDataset(t, "Application,Library\nChrome,\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected missing ja4 column error")
	}
}

func TestLoadJA4DBAliases(t *testing.T) {
	path := writeDataset(t, `application,library,device,os,user_agent_string,certificate_authority,verified,notes,observation_count,ja4_fingerprint,ja4_fingerprint_string,ja4h_fingerprint,ja4s_fingerprint,ja4t_fingerprint,ja4ts_fingerprint,ja4tscan_fingerprint,ja4x_fingerprint
Chromium Browser,BoringSSL,,Windows 10,Mozilla/5.0,DigiCert,true,known browser,42,t13d1516h2_8daaf6152771_02713d6af862,t13d1516h2_8daaf6152771_02713d6af862,ge11nn08enus_050dd5cfb971_000000000000_000000000000,t130200_1301_a56c5b993250,,,,d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae
`)

	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	candidates := store.Candidates("t13d1516h2_8daaf6152771_02713d6af862")
	if len(candidates) != 1 {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
	entry := candidates[0]
	if entry.UserAgentString != "Mozilla/5.0" || !entry.Verified || entry.ObservationCount != 42 {
		t.Fatalf("aliased fields not loaded: %+v", entry)
	}
	if entry.JA4S == "" || entry.JA4H == "" || entry.JA4X == "" {
		t.Fatalf("fingerprint aliases not loaded: %+v", entry)
	}
}

func TestLenientSkipsInvalidJA4(t *testing.T) {
	path := writeDataset(t, `Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes
Good,,,,t13d1516h2_8daaf6152771_02713d6af862,,,,,,
Bad,,,,not-a-ja4,,,,,,
Hidden,Library,,,t13d190900_9dc949149365_97f8aa674fd9,,,,,,
`)

	store, err := LoadLenient(path)
	if err != nil {
		t.Fatalf("LoadLenient: %v", err)
	}

	stats := store.Stats()
	if stats.Rows != 3 || stats.JA4Rows != 2 || stats.InvalidJA4 != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if len(store.Candidates("not-a-ja4")) != 0 {
		t.Fatal("invalid row must not be indexed")
	}
}

func TestExportAndLoadSQLite(t *testing.T) {
	store, err := Load(filepath.Join("..", "..", "datasets", "ja4plus-mapping.csv"))
	if err != nil {
		t.Fatalf("load repository dataset: %v", err)
	}

	cfg := sybildb.SQLiteConfig{
		Driver: "libsql",
		DSN:    "file:" + filepath.Join(t.TempDir(), "ja4.db"),
	}
	ctx := context.Background()

	inserted, err := ExportSQLite(ctx, store, cfg, true)
	if err != nil {
		t.Fatalf("ExportSQLite: %v", err)
	}
	if inserted != 35 {
		t.Fatalf("inserted = %d, want 35", inserted)
	}

	loaded, err := LoadSQLite(ctx, cfg)
	if err != nil {
		t.Fatalf("LoadSQLite: %v", err)
	}
	stats := loaded.Stats()
	if stats.Rows != 35 || stats.JA4Rows != 35 || stats.UniqueJA4 != 32 ||
		stats.DuplicateJA4 != 3 || stats.InvalidJA4 != 0 {
		t.Fatalf("unexpected database stats: %+v", stats)
	}

	ambiguous := loaded.Candidates("t13d190900_9dc949149365_97f8aa674fd9")
	if len(ambiguous) != 2 || ambiguous[0].Application != "Sliver Agent" {
		t.Fatalf("unexpected candidates from database: %+v", ambiguous)
	}

	client, closeClient, err := risk.NewLibSQLLookupClient(cfg)
	if err != nil {
		t.Fatalf("NewLibSQLLookupClient: %v", err)
	}
	defer closeClient()

	record, err := client.Lookup(ctx, "t13d190900_9dc949149365_97f8aa674fd9")
	if err != nil {
		t.Fatalf("database lookup: %v", err)
	}
	if record.Application != "Sliver Agent" {
		t.Fatalf("database lookup preferred %q, want Sliver Agent", record.Application)
	}
}

func TestRepositoryDataset(t *testing.T) {
	store, err := Load(filepath.Join("..", "..", "datasets", "ja4plus-mapping.csv"))
	if err != nil {
		t.Fatalf("load repository dataset: %v", err)
	}

	stats := store.Stats()
	if stats.Rows != 66 || stats.JA4Rows != 35 || stats.UniqueJA4 != 32 || stats.DuplicateJA4 != 3 {
		t.Fatalf("unexpected repository dataset stats: %+v", stats)
	}

	record, err := store.Lookup(context.Background(), "t13d1516h2_8daaf6152771_02713d6af862")
	if err != nil {
		t.Fatalf("lookup chrome fingerprint: %v", err)
	}
	if record.Application != "Chromium Browser" {
		t.Fatalf("unexpected chrome record: %+v", record)
	}

	clients := store.Candidates("t13d190900_9dc949149365_97f8aa674fd9")
	if len(clients) != 2 || clients[0].Application != "Sliver Agent" {
		t.Fatalf("unexpected ambiguous sliver candidates: %+v", clients)
	}
}
