// Package dataset loads the FoxIO JA4+ mapping CSV and exposes it as a
// read-only fingerprint lookup source.
package dataset

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sophic00/sybil/internal/risk"
)

// Entry is one row from the JA4+ mapping CSV.
type Entry struct {
	Application string `json:"application,omitempty"`
	Library     string `json:"library,omitempty"`
	Device      string `json:"device,omitempty"`
	OS          string `json:"os,omitempty"`
	JA4         string `json:"ja4,omitempty"`
	JA4S        string `json:"ja4s,omitempty"`
	JA4H        string `json:"ja4h,omitempty"`
	JA4X        string `json:"ja4x,omitempty"`
	JA4T        string `json:"ja4t,omitempty"`
	JA4TS       string `json:"ja4ts,omitempty"`
	JA4TSCAN    string `json:"ja4tscan,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

// Stats summarizes a loaded dataset.
type Stats struct {
	Rows         int    `json:"rows"`
	JA4Rows      int    `json:"ja4_rows"`
	UniqueJA4    int    `json:"unique_ja4"`
	DuplicateJA4 int    `json:"duplicate_ja4"`
	Path         string `json:"path"`
}

// Store is an in-memory view of the mapping CSV. It implements
// risk.LookupClient.
type Store struct {
	path    string
	entries []Entry
	byJA4   map[string][]int
}

// Load reads a JA4+ mapping CSV.
func Load(path string) (*Store, error) {
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

	store := &Store{
		path:  path,
		byJA4: make(map[string][]int),
	}

	for row := 2; ; row++ {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read dataset row %d: %w", row, err)
		}

		entry := Entry{
			Application: field(record, columns, "application"),
			Library:     field(record, columns, "library"),
			Device:      field(record, columns, "device"),
			OS:          field(record, columns, "os"),
			JA4:         field(record, columns, "ja4"),
			JA4S:        field(record, columns, "ja4s"),
			JA4H:        field(record, columns, "ja4h"),
			JA4X:        field(record, columns, "ja4x"),
			JA4T:        field(record, columns, "ja4t"),
			JA4TS:       field(record, columns, "ja4ts"),
			JA4TSCAN:    field(record, columns, "ja4tscan"),
			Notes:       field(record, columns, "notes"),
		}

		if entry.JA4 != "" {
			if err := validateJA4(entry.JA4); err != nil {
				return nil, fmt.Errorf("dataset row %d: %w", row, err)
			}
		}

		index := len(store.entries)
		store.entries = append(store.entries, entry)
		if entry.JA4 != "" {
			store.byJA4[entry.JA4] = append(store.byJA4[entry.JA4], index)
		}
	}

	return store, nil
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

	ja4Rows := 0
	for _, entry := range s.entries {
		if entry.JA4 != "" {
			ja4Rows++
		}
	}

	return Stats{
		Rows:         len(s.entries),
		JA4Rows:      ja4Rows,
		UniqueJA4:    len(s.byJA4),
		DuplicateJA4: duplicates,
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
	for _, entry := range s.entries {
		if entry.JA4 == "" || ja4Prefix(entry.JA4) != prefix {
			continue
		}
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

func recordFromEntry(entry Entry) *risk.FingerprintRecord {
	return &risk.FingerprintRecord{
		Application:         entry.Application,
		Library:             entry.Library,
		Device:              entry.Device,
		OS:                  entry.OS,
		Notes:               entry.Notes,
		JA4Fingerprint:      entry.JA4,
		JA4SFingerprint:     entry.JA4S,
		JA4HFingerprint:     entry.JA4H,
		JA4XFingerprint:     entry.JA4X,
		JA4TFingerprint:     entry.JA4T,
		JA4TSFingerprint:    entry.JA4TS,
		JA4TScanFingerprint: entry.JA4TSCAN,
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

func mapColumns(header []string) (map[string]int, error) {
	columns := make(map[string]int, len(header))
	for index, name := range header {
		name = strings.TrimPrefix(strings.TrimSpace(name), "\ufeff")
		columns[strings.ToLower(name)] = index
	}
	if _, ok := columns["ja4"]; !ok {
		return nil, fmt.Errorf("dataset is missing ja4 column")
	}
	return columns, nil
}

func field(record []string, columns map[string]int, name string) string {
	index, ok := columns[name]
	if !ok || index >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[index])
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
