// Package dataset loads JA4+ reference data from the FoxIO mapping CSV, a
// JA4DB-style CSV, or a libSQL/SQLite fingerprints table.
package dataset

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	sybildb "github.com/sophic00/sybil/internal/db"
	"github.com/sophic00/sybil/internal/risk"
)

// Entry is one reference row.
type Entry struct {
	Application          string `json:"application,omitempty"`
	Library              string `json:"library,omitempty"`
	Device               string `json:"device,omitempty"`
	OS                   string `json:"os,omitempty"`
	UserAgentString      string `json:"user_agent_string,omitempty"`
	CertificateAuthority string `json:"certificate_authority,omitempty"`
	Verified             bool   `json:"verified,omitempty"`
	Notes                string `json:"notes,omitempty"`
	ObservationCount     int64  `json:"observation_count,omitempty"`
	JA4                  string `json:"ja4,omitempty"`
	JA4S                 string `json:"ja4s,omitempty"`
	JA4H                 string `json:"ja4h,omitempty"`
	JA4X                 string `json:"ja4x,omitempty"`
	JA4T                 string `json:"ja4t,omitempty"`
	JA4TS                string `json:"ja4ts,omitempty"`
	JA4TSCAN             string `json:"ja4tscan,omitempty"`
}

// Options controls CSV loading.
type Options struct {
	// Lenient skips invalid JA4 rows instead of failing the load.
	Lenient bool
}

// Stats summarizes a loaded dataset.
type Stats struct {
	Rows         int    `json:"rows"`
	JA4Rows      int    `json:"ja4_rows"`
	UniqueJA4    int    `json:"unique_ja4"`
	DuplicateJA4 int    `json:"duplicate_ja4"`
	InvalidJA4   int    `json:"invalid_ja4"`
	Path         string `json:"path"`
}

// Store is an in-memory view of reference data. It implements
// risk.LookupClient.
type Store struct {
	path     string
	entries  []Entry
	byJA4    map[string][]int
	byPrefix map[string][]int
	invalid  int
}

// Load reads a JA4+ reference CSV strictly.
func Load(path string) (*Store, error) {
	return LoadWithOptions(path, Options{})
}

// LoadLenient reads a CSV, skipping rows whose JA4 is malformed.
func LoadLenient(path string) (*Store, error) {
	return LoadWithOptions(path, Options{Lenient: true})
}

// LoadWithOptions reads a JA4+ reference CSV.
func LoadWithOptions(path string, opts Options) (*Store, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open dataset: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read dataset header: %w", err)
	}

	columns, err := mapColumns(header)
	if err != nil {
		return nil, err
	}

	entries := make([]Entry, 0)
	invalid := 0

	for row := 2; ; row++ {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read dataset row %d: %w", row, err)
		}

		entry := Entry{
			Application:          field(record, columns, "application"),
			Library:              field(record, columns, "library"),
			Device:               field(record, columns, "device"),
			OS:                   field(record, columns, "os"),
			UserAgentString:      field(record, columns, "user_agent_string"),
			CertificateAuthority: field(record, columns, "certificate_authority"),
			Verified:             parseBool(field(record, columns, "verified")),
			Notes:                field(record, columns, "notes"),
			ObservationCount:     parseInt64(field(record, columns, "observation_count")),
			JA4:                  field(record, columns, "ja4"),
			JA4S:                 field(record, columns, "ja4s"),
			JA4H:                 field(record, columns, "ja4h"),
			JA4X:                 field(record, columns, "ja4x"),
			JA4T:                 field(record, columns, "ja4t"),
			JA4TS:                field(record, columns, "ja4ts"),
			JA4TSCAN:             field(record, columns, "ja4tscan"),
		}

		if entry.JA4 != "" {
			if err := validateJA4(entry.JA4); err != nil {
				if opts.Lenient {
					invalid++
					continue
				}
				return nil, fmt.Errorf("dataset row %d: %w", row, err)
			}
		}

		entries = append(entries, entry)
	}

	return newStore(path, entries, invalid), nil
}

// LoadSQLite reads every row from a fingerprints table into memory.
func LoadSQLite(ctx context.Context, cfg sybildb.SQLiteConfig) (*Store, error) {
	conn, err := sybildb.OpenSQLite(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	rows, err := conn.QueryContext(ctx, `
		SELECT
			application,
			library,
			device,
			os,
			user_agent_string,
			certificate_authority,
			verified,
			notes,
			ja4_fingerprint,
			ja4s_fingerprint,
			ja4h_fingerprint,
			ja4x_fingerprint,
			ja4t_fingerprint,
			ja4ts_fingerprint,
			ja4tscan_fingerprint
		FROM fingerprints`)
	if err != nil {
		return nil, fmt.Errorf("query fingerprints: %w", err)
	}
	defer rows.Close()

	entries := make([]Entry, 0)
	invalid := 0
	for rows.Next() {
		var (
			entry                                           Entry
			application, library, device, osName, userAgent sql.NullString
			certificateAuthority, notes, ja4, ja4s, ja4h    sql.NullString
			ja4x, ja4t, ja4ts, ja4tscan                     sql.NullString
			verified                                        sql.NullInt64
		)
		if err := rows.Scan(
			&application,
			&library,
			&device,
			&osName,
			&userAgent,
			&certificateAuthority,
			&verified,
			&notes,
			&ja4,
			&ja4s,
			&ja4h,
			&ja4x,
			&ja4t,
			&ja4ts,
			&ja4tscan,
		); err != nil {
			return nil, fmt.Errorf("scan fingerprint: %w", err)
		}

		entry = Entry{
			Application:          strings.TrimSpace(application.String),
			Library:              strings.TrimSpace(library.String),
			Device:               strings.TrimSpace(device.String),
			OS:                   strings.TrimSpace(osName.String),
			UserAgentString:      strings.TrimSpace(userAgent.String),
			CertificateAuthority: strings.TrimSpace(certificateAuthority.String),
			Verified:             verified.Valid && verified.Int64 != 0,
			Notes:                strings.TrimSpace(notes.String),
			JA4:                  strings.TrimSpace(ja4.String),
			JA4S:                 strings.TrimSpace(ja4s.String),
			JA4H:                 strings.TrimSpace(ja4h.String),
			JA4X:                 strings.TrimSpace(ja4x.String),
			JA4T:                 strings.TrimSpace(ja4t.String),
			JA4TS:                strings.TrimSpace(ja4ts.String),
			JA4TSCAN:             strings.TrimSpace(ja4tscan.String),
		}

		if entry.JA4 == "" {
			continue
		}
		if err := validateJA4(entry.JA4); err != nil {
			invalid++
			continue
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read fingerprints: %w", err)
	}

	return newStore(cfg.DSN, entries, invalid), nil
}

const createTableSQL = `
CREATE TABLE IF NOT EXISTS fingerprints (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	application TEXT,
	library TEXT,
	device TEXT,
	os TEXT,
	user_agent_string TEXT,
	certificate_authority TEXT,
	verified INTEGER,
	notes TEXT,
	ja4_fingerprint TEXT,
	ja4_fingerprint_string TEXT,
	ja4s_fingerprint TEXT,
	ja4h_fingerprint TEXT,
	ja4x_fingerprint TEXT,
	ja4t_fingerprint TEXT,
	ja4ts_fingerprint TEXT,
	ja4tscan_fingerprint TEXT
)`

const createIndexSQL = `CREATE INDEX IF NOT EXISTS idx_fingerprints_ja4 ON fingerprints(ja4_fingerprint)`

const insertSQL = `
INSERT INTO fingerprints (
	application, library, device, os, user_agent_string,
	certificate_authority, verified, notes,
	ja4_fingerprint, ja4_fingerprint_string,
	ja4s_fingerprint, ja4h_fingerprint, ja4x_fingerprint,
	ja4t_fingerprint, ja4ts_fingerprint, ja4tscan_fingerprint
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// ExportSQLite writes entries with a JA4 value to a libSQL/SQLite database.
// Replacing drops and recreates the fingerprints table first.
func ExportSQLite(ctx context.Context, store *Store, cfg sybildb.SQLiteConfig, replace bool) (int, error) {
	if store == nil {
		return 0, fmt.Errorf("nil dataset")
	}

	conn, err := sybildb.OpenSQLite(cfg)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if replace {
		if _, err := conn.ExecContext(ctx, `DROP TABLE IF EXISTS fingerprints`); err != nil {
			return 0, fmt.Errorf("drop fingerprints table: %w", err)
		}
	}
	if _, err := conn.ExecContext(ctx, createTableSQL); err != nil {
		return 0, fmt.Errorf("create fingerprints table: %w", err)
	}
	if _, err := conn.ExecContext(ctx, createIndexSQL); err != nil {
		return 0, fmt.Errorf("create fingerprints index: %w", err)
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin import transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		return 0, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	inserted := 0
	for _, entry := range store.entries {
		if entry.JA4 == "" {
			continue
		}
		verified := 0
		if entry.Verified {
			verified = 1
		}
		if _, err := stmt.ExecContext(ctx,
			entry.Application, entry.Library, entry.Device, entry.OS, entry.UserAgentString,
			entry.CertificateAuthority, verified, entry.Notes,
			entry.JA4, entry.JA4,
			entry.JA4S, entry.JA4H, entry.JA4X,
			entry.JA4T, entry.JA4TS, entry.JA4TSCAN,
		); err != nil {
			return 0, fmt.Errorf("insert fingerprint %s: %w", entry.JA4, err)
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit import: %w", err)
	}
	return inserted, nil
}

// Stats returns dataset counts.
func (s *Store) Stats() Stats {
	if s == nil {
		return Stats{}
	}

	duplicates := 0
	for _, indexes := range s.byJA4 {
		if len(indexes) > 1 {
			duplicates += len(indexes) - 1
		}
	}

	return Stats{
		Rows:         len(s.entries) + s.invalid,
		JA4Rows:      s.ja4Rows(),
		UniqueJA4:    len(s.byJA4),
		DuplicateJA4: duplicates,
		InvalidJA4:   s.invalid,
		Path:         s.path,
	}
}

// Entries returns a copy of every dataset row.
func (s *Store) Entries() []Entry {
	if s == nil {
		return nil
	}
	out := make([]Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Candidates returns every dataset row whose full JA4 matches, most specific
// identity first. A single JA4 can map to more than one label.
func (s *Store) Candidates(ja4 string) []Entry {
	ja4 = strings.TrimSpace(ja4)
	if s == nil || ja4 == "" {
		return nil
	}

	indexes := s.byJA4[ja4]
	if len(indexes) == 0 {
		return nil
	}

	candidates := make([]Entry, 0, len(indexes))
	for _, index := range indexes {
		candidates = append(candidates, s.entries[index])
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := specificity(candidates[i]), specificity(candidates[j])
		if left != right {
			return left > right
		}
		return candidates[i].Application < candidates[j].Application
	})
	return candidates
}

// PrefixCandidates returns dataset rows sharing the JA4_a prefix. It is useful
// for explaining near misses when a full fingerprint is not present.
func (s *Store) PrefixCandidates(ja4 string) []Entry {
	prefix := ja4Prefix(ja4)
	if s == nil || prefix == "" {
		return nil
	}

	seen := make(map[string]struct{})
	out := make([]Entry, 0)
	for _, index := range s.byPrefix[prefix] {
		entry := s.entries[index]
		key := entry.JA4 + "\x00" + entry.Application + "\x00" + entry.Library + "\x00" + entry.Notes
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, entry)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return specificity(out[i]) > specificity(out[j])
	})
	return out
}

// Lookup implements risk.LookupClient.
func (s *Store) Lookup(_ context.Context, ja4 string) (*risk.FingerprintRecord, error) {
	candidates := s.Candidates(ja4)
	if len(candidates) == 0 {
		return nil, risk.ErrFingerprintNotFound
	}
	return recordFromEntry(candidates[0]), nil
}

func newStore(path string, entries []Entry, invalid int) *Store {
	store := &Store{
		path:     path,
		entries:  entries,
		byJA4:    make(map[string][]int, len(entries)),
		byPrefix: make(map[string][]int, len(entries)),
		invalid:  invalid,
	}
	for index, entry := range entries {
		if entry.JA4 == "" {
			continue
		}
		store.byJA4[entry.JA4] = append(store.byJA4[entry.JA4], index)
		prefix := ja4Prefix(entry.JA4)
		store.byPrefix[prefix] = append(store.byPrefix[prefix], index)
	}
	return store
}

func (s *Store) ja4Rows() int {
	count := 0
	for _, entry := range s.entries {
		if entry.JA4 != "" {
			count++
		}
	}
	return count
}

func recordFromEntry(entry Entry) *risk.FingerprintRecord {
	return &risk.FingerprintRecord{
		Application:          entry.Application,
		Library:              entry.Library,
		Device:               entry.Device,
		OS:                   entry.OS,
		UserAgentString:      entry.UserAgentString,
		CertificateAuthority: entry.CertificateAuthority,
		Verified:             entry.Verified,
		Notes:                entry.Notes,
		JA4Fingerprint:       entry.JA4,
		JA4SFingerprint:      entry.JA4S,
		JA4HFingerprint:      entry.JA4H,
		JA4XFingerprint:      entry.JA4X,
		JA4TFingerprint:      entry.JA4T,
		JA4TSFingerprint:     entry.JA4TS,
		JA4TScanFingerprint:  entry.JA4TSCAN,
	}
}

func specificity(entry Entry) int {
	score := 0
	for _, value := range []string{entry.Application, entry.Library, entry.Device, entry.OS, entry.Notes} {
		if value != "" {
			score++
		}
	}
	if entry.Application != "" {
		// Application is the strongest human-facing identity.
		score += 2
	}
	return score
}

var columnAliases = map[string][]string{
	"application":           {"application"},
	"library":               {"library"},
	"device":                {"device"},
	"os":                    {"os"},
	"user_agent_string":     {"user_agent_string", "useragent"},
	"certificate_authority": {"certificate_authority"},
	"verified":              {"verified"},
	"notes":                 {"notes"},
	"observation_count":     {"observation_count"},
	"ja4":                   {"ja4", "ja4_fingerprint"},
	"ja4s":                  {"ja4s", "ja4s_fingerprint"},
	"ja4h":                  {"ja4h", "ja4h_fingerprint"},
	"ja4x":                  {"ja4x", "ja4x_fingerprint"},
	"ja4t":                  {"ja4t", "ja4t_fingerprint"},
	"ja4ts":                 {"ja4ts", "ja4ts_fingerprint"},
	"ja4tscan":              {"ja4tscan", "ja4tscan_fingerprint"},
}

func mapColumns(header []string) (map[string]int, error) {
	aliases := make(map[string]string, len(columnAliases))
	for canonical, names := range columnAliases {
		for _, name := range names {
			aliases[name] = canonical
		}
	}

	columns := make(map[string]int, len(header))
	for index, name := range header {
		name = normalizeColumn(name)
		canonical, ok := aliases[name]
		if !ok {
			continue
		}
		if _, exists := columns[canonical]; exists {
			continue
		}
		columns[canonical] = index
	}
	if _, ok := columns["ja4"]; !ok {
		return nil, fmt.Errorf("dataset is missing ja4 or ja4_fingerprint column")
	}
	return columns, nil
}

func normalizeColumn(name string) string {
	name = strings.TrimPrefix(strings.TrimSpace(name), "\ufeff")
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

func field(record []string, columns map[string]int, name string) string {
	index, ok := columns[name]
	if !ok || index >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[index])
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y":
		return true
	default:
		return false
	}
}

func parseInt64(value string) int64 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func validateJA4(value string) error {
	parts := strings.Split(value, "_")
	if len(parts) != 3 {
		return fmt.Errorf("invalid ja4 %q: expected three underscore-separated parts", value)
	}
	if len(parts[0]) != 10 {
		return fmt.Errorf("invalid ja4 %q: prefix must be 10 characters", value)
	}
	for _, part := range parts[1:] {
		if len(part) != 12 {
			return fmt.Errorf("invalid ja4 %q: hash must be 12 characters", value)
		}
		for index := range len(part) {
			ch := part[index]
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
				return fmt.Errorf("invalid ja4 %q: hash must be lowercase hex", value)
			}
		}
	}
	return nil
}

func ja4Prefix(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.IndexByte(value, '_'); index >= 0 {
		return value[:index]
	}
	return value
}
