// Command ja4import loads a JA4+ mapping CSV into a libSQL/SQLite database
// with the fingerprints table expected by Sybil.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sophic00/sybil/internal/dataset"
	sybildb "github.com/sophic00/sybil/internal/db"
)

func main() {
	var (
		datasetPath string
		dbPath      string
		authToken   string
		replace     bool
		lenient     bool
	)
	flag.StringVar(&datasetPath, "dataset", "datasets/ja4plus-mapping.csv", "JA4+ mapping CSV")
	flag.StringVar(&dbPath, "db", "", "libSQL/SQLite DSN, for example file:datasets/ja4.db")
	flag.StringVar(&authToken, "db-auth-token", "", "Auth token for a remote libSQL database")
	flag.BoolVar(&replace, "replace", false, "Drop and recreate the fingerprints table")
	flag.BoolVar(&lenient, "lenient", false, "Skip invalid JA4 rows instead of failing")
	flag.Parse()

	if strings.TrimSpace(dbPath) == "" {
		fmt.Fprintln(os.Stderr, "ja4import: -db is required")
		os.Exit(2)
	}

	store, err := dataset.LoadWithOptions(datasetPath, dataset.Options{Lenient: lenient})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ja4import: %v\n", err)
		os.Exit(2)
	}

	inserted, err := dataset.ExportSQLite(context.Background(), store, sybildb.SQLiteConfig{
		Driver:    "libsql",
		DSN:       dbPath,
		AuthToken: authToken,
	}, replace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ja4import: %v\n", err)
		os.Exit(2)
	}

	stats := store.Stats()
	fmt.Printf("dataset: %s\n", stats.Path)
	fmt.Printf("rows=%d ja4_rows=%d unique_ja4=%d duplicates=%d invalid=%d\n",
		stats.Rows, stats.JA4Rows, stats.UniqueJA4, stats.DuplicateJA4, stats.InvalidJA4)
	fmt.Printf("database: %s\n", dbPath)
	fmt.Printf("inserted=%d\n", inserted)
}
