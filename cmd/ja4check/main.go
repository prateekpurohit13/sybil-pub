// Command ja4check compares computed JA4 fingerprints against the FoxIO JA4+
// mapping dataset. It can inspect offline pcap files and/or explicit
// fingerprint values.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/sophic00/sybil/internal/capture"
	"github.com/sophic00/sybil/internal/dataset"
	sybildb "github.com/sophic00/sybil/internal/db"
	"github.com/sophic00/sybil/internal/stream"
	"github.com/sophic00/sybil/internal/tlshello"
)

const (
	statusExact            = "exact"
	statusAmbiguous        = "ambiguous"
	statusPrefix           = "prefix"
	statusUnknown          = "unknown"
	statusParseError       = "parse_error"
	statusFingerprintError = "fingerprint_error"
	statusMissingJA4       = "missing_ja4"
)

type options struct {
	datasetPath string
	dbPath      string
	dbAuthToken string
	pcapPath    string
	ja4Inputs   []string
	ja4File     string
	jsonOutput  bool
	strict      bool
	lenient     bool
	maxMatches  int
	port        uint
}

type observation struct {
	Origin          string          `json:"origin"`
	JA4             string          `json:"ja4,omitempty"`
	SNI             string          `json:"sni,omitempty"`
	SourceIP        string          `json:"source_ip,omitempty"`
	SourcePort      string          `json:"source_port,omitempty"`
	DestinationIP   string          `json:"destination_ip,omitempty"`
	DestinationPort string          `json:"destination_port,omitempty"`
	Status          string          `json:"status"`
	Error           string          `json:"error,omitempty"`
	MatchCount      int             `json:"match_count"`
	Matches         []dataset.Entry `json:"matches,omitempty"`
}

type summary struct {
	DirectLookups int `json:"direct_lookups"`
	ClientHellos  int `json:"client_hellos"`
	Exact         int `json:"exact"`
	Ambiguous     int `json:"ambiguous"`
	Prefix        int `json:"prefix"`
	Unknown       int `json:"unknown"`
	Errors        int `json:"errors"`
}

type report struct {
	Dataset       dataset.Stats `json:"dataset"`
	Observations  []observation `json:"observations"`
	Summary       summary       `json:"summary"`
	Strict        bool          `json:"strict"`
	StrictFailure bool          `json:"strict_failure"`
}

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	opts := parseFlags()

	result, err := run(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ja4check: %v\n", err)
		os.Exit(2)
	}

	if opts.jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "ja4check: encode report: %v\n", err)
			os.Exit(2)
		}
	} else {
		printReport(os.Stdout, result)
	}

	if opts.strict && result.StrictFailure {
		os.Exit(1)
	}
}

func parseFlags() options {
	var opts options
	var inputs stringList

	flags := flag.NewFlagSet("ja4check", flag.ExitOnError)
	flags.StringVar(&opts.datasetPath, "dataset", "datasets/ja4plus-mapping.csv", "JA4+ mapping CSV")
	flags.StringVar(&opts.dbPath, "db", "", "libSQL/SQLite database with a fingerprints table (overrides -dataset)")
	flags.StringVar(&opts.dbAuthToken, "db-auth-token", "", "Auth token for a remote libSQL database")
	flags.StringVar(&opts.pcapPath, "pcap", "", "Optional pcap/pcapng file to analyze")
	flags.BoolVar(&opts.lenient, "lenient", false, "Skip invalid JA4 rows in the CSV instead of failing")
	flags.IntVar(&opts.maxMatches, "max-matches", 20, "Maximum matches reported per fingerprint; 0 disables the cap")
	flags.Var(&inputs, "ja4", "JA4 fingerprint to compare (repeatable)")
	flags.StringVar(&opts.ja4File, "ja4-file", "", "File containing one JA4 fingerprint per line")
	flags.BoolVar(&opts.jsonOutput, "json", false, "Emit JSON instead of a table")
	flags.BoolVar(&opts.strict, "strict", false, "Exit non-zero when a fingerprint has no exact match")
	flags.UintVar(&opts.port, "port", 0, "Only inspect TCP traffic where either port matches")
	_ = flags.Parse(os.Args[1:])

	opts.ja4Inputs = inputs
	return opts
}

func run(ctx context.Context, opts options) (report, error) {
	var store *dataset.Store
	var err error
	if strings.TrimSpace(opts.dbPath) != "" {
		store, err = dataset.LoadSQLite(ctx, sybildb.SQLiteConfig{
			Driver:    "libsql",
			DSN:       opts.dbPath,
			AuthToken: opts.dbAuthToken,
		})
	} else {
		store, err = dataset.LoadWithOptions(opts.datasetPath, dataset.Options{Lenient: opts.lenient})
	}
	if err != nil {
		return report{}, err
	}

	result := report{Dataset: store.Stats(), Strict: opts.strict}

	inputs, err := collectInputs(opts.ja4Inputs, opts.ja4File)
	if err != nil {
		return report{}, err
	}
	for _, fingerprint := range inputs {
		status, matches, total := classify(store, fingerprint)
		result.Observations = append(result.Observations, observation{
			Origin:     "input",
			JA4:        fingerprint,
			Status:     status,
			MatchCount: total,
			Matches:    limitMatches(matches, opts.maxMatches),
		})
	}

	if opts.pcapPath != "" {
		pcapObservations, err := analyzePCAP(ctx, opts.pcapPath, opts.port, store, opts.maxMatches)
		if err != nil {
			return report{}, err
		}
		result.Observations = append(result.Observations, pcapObservations...)
	}

	result.Summary = summarize(result.Observations)
	result.StrictFailure = result.Summary.Prefix+result.Summary.Unknown+result.Summary.Errors > 0
	return result, nil
}

func collectInputs(values []string, filePath string) ([]string, error) {
	inputs := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			inputs = append(inputs, trimmed)
		}
	}

	if strings.TrimSpace(filePath) != "" {
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read ja4 file: %w", err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			inputs = append(inputs, line)
		}
	}

	seen := make(map[string]struct{}, len(inputs))
	unique := make([]string, 0, len(inputs))
	for _, value := range inputs {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique, nil
}

func analyzePCAP(ctx context.Context, path string, matchPort uint, store *dataset.Store, maxMatches int) ([]observation, error) {
	source, err := capture.OpenOffline(path, matchPort)
	if err != nil {
		return nil, err
	}
	defer source.Close()

	observations := make([]observation, 0)
	processor := stream.NewProcessor(stream.Options{
		MatchPort: matchPort,
		OnEvent: func(event stream.Event) {
			if event.Hello == nil || event.Hello.Type != tlshello.ClientHello {
				return
			}

			item := observation{
				Origin:          "pcap",
				SourceIP:        event.NetFlow.Src().String(),
				SourcePort:      event.TransportFlow.Src().String(),
				DestinationIP:   event.NetFlow.Dst().String(),
				DestinationPort: event.TransportFlow.Dst().String(),
			}
			if event.Fields != nil {
				item.SNI = event.Fields.SNIHost
			}

			switch {
			case event.ParseError != nil:
				item.Status = statusParseError
				item.Error = event.ParseError.Error()
			case event.FingerprintError != nil:
				item.Status = statusFingerprintError
				item.Error = event.FingerprintError.Error()
			case event.JA4 == nil:
				item.Status = statusMissingJA4
				item.Error = "no ja4 fingerprint produced"
			default:
				item.JA4 = event.JA4.Fingerprint
				status, matches, total := classify(store, item.JA4)
				item.Status = status
				item.MatchCount = total
				item.Matches = limitMatches(matches, maxMatches)
			}

			observations = append(observations, item)
		},
	})

	for {
		packet, err := source.NextPacket(ctx)
		if errors.Is(err, capture.ErrClosed) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read pcap %s: %w", path, err)
		}
		processor.ProcessPacket(packet)
	}
	processor.FlushAll()

	return observations, nil
}

func classify(store *dataset.Store, fingerprint string) (string, []dataset.Entry, int) {
	exact := store.Candidates(fingerprint)
	switch len(exact) {
	case 1:
		return statusExact, exact, len(exact)
	case 0:
		// Fall through to prefix matching.
	default:
		return statusAmbiguous, exact, len(exact)
	}

	prefix := store.PrefixCandidates(fingerprint)
	if len(prefix) > 0 {
		return statusPrefix, prefix, len(prefix)
	}
	return statusUnknown, nil, 0
}

// limitMatches removes duplicate identities and caps the displayed matches.
func limitMatches(entries []dataset.Entry, limit int) []dataset.Entry {
	if len(entries) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(entries))
	out := make([]dataset.Entry, 0, len(entries))
	for _, entry := range entries {
		key := matchKey(entry)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, entry)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func matchKey(entry dataset.Entry) string {
	return strings.Join([]string{
		entry.JA4,
		entry.Application,
		entry.Library,
		entry.Device,
		entry.OS,
		entry.UserAgentString,
		entry.CertificateAuthority,
		strconv.FormatBool(entry.Verified),
		entry.Notes,
	}, "\x00")
}

func summarize(observations []observation) summary {
	var result summary
	for _, item := range observations {
		if item.Origin == "pcap" {
			result.ClientHellos++
		} else {
			result.DirectLookups++
		}

		switch item.Status {
		case statusExact:
			result.Exact++
		case statusAmbiguous:
			result.Ambiguous++
		case statusPrefix:
			result.Prefix++
		case statusUnknown:
			result.Unknown++
		case statusParseError, statusFingerprintError, statusMissingJA4:
			result.Errors++
		}
	}
	return result
}

func printReport(out io.Writer, result report) {
	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	defer writer.Flush()

	stats := result.Dataset
	fmt.Fprintf(writer, "dataset:\t%s\n", stats.Path)
	fmt.Fprintf(writer, "rows:\t%d\n", stats.Rows)
	fmt.Fprintf(writer, "ja4 rows:\t%d\n", stats.JA4Rows)
	fmt.Fprintf(writer, "unique ja4:\t%d\n", stats.UniqueJA4)
	fmt.Fprintf(writer, "duplicate ja4:\t%d\n", stats.DuplicateJA4)
	fmt.Fprintf(writer, "invalid ja4:\t%d\n", stats.InvalidJA4)
	fmt.Fprintln(writer)

	if len(result.Observations) == 0 {
		fmt.Fprintln(writer, "no fingerprints to compare")
		return
	}

	fmt.Fprintln(writer, "status\torigin\tja4\tsource\tsni\tidentity")
	for _, item := range result.Observations {
		source := "-"
		if item.SourceIP != "" {
			source = fmt.Sprintf("%s:%s -> %s:%s", item.SourceIP, item.SourcePort, item.DestinationIP, item.DestinationPort)
		}
		fingerprint := item.JA4
		if fingerprint == "" {
			fingerprint = "-"
		}
		identity := identityLabel(item)
		if item.Error != "" {
			identity = item.Error
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\n",
			item.Status, item.Origin, fingerprint, source, emptyDash(item.SNI), identity)
	}

	statsSummary := result.Summary
	fmt.Fprintln(writer)
	fmt.Fprintf(writer, "summary:\tdirect=%d\tclient_hellos=%d\texact=%d\tambiguous=%d\tprefix=%d\tunknown=%d\terrors=%d\n",
		statsSummary.DirectLookups, statsSummary.ClientHellos, statsSummary.Exact,
		statsSummary.Ambiguous, statsSummary.Prefix, statsSummary.Unknown, statsSummary.Errors)
	switch {
	case !result.Strict:
		fmt.Fprintln(writer, "strict:\tnot requested")
	case result.StrictFailure:
		fmt.Fprintln(writer, "strict:\tFAIL")
	default:
		fmt.Fprintln(writer, "strict:\tPASS")
	}
}

func identityLabel(item observation) string {
	if len(item.Matches) == 0 {
		return "-"
	}

	match := item.Matches[0]
	parts := make([]string, 0, 4)
	for _, value := range []string{match.Application, match.Library, match.Device, match.OS} {
		if value != "" {
			parts = append(parts, value)
		}
	}
	label := strings.Join(parts, ", ")
	if label == "" {
		label = match.Notes
	}
	if label == "" {
		label = "unknown"
	}
	if item.MatchCount > 1 {
		label = fmt.Sprintf("%s (+%d more)", label, item.MatchCount-1)
	}
	return label
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
