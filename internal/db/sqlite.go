package db

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteConfig struct {
	Driver string
	DSN    string
}

func OpenSQLite(cfg SQLiteConfig) (*sql.DB, error) {
	driver := strings.TrimSpace(cfg.Driver)
	if driver == "" {
		driver = "sqlite3"
	}

	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("missing sqlite dsn")
	}

	conn, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", driver, err)
	}

	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ping %s database: %w", driver, err)
	}

	return conn, nil
}

func OpenSQLiteFromEnv() (*sql.DB, error) {
	dsn := strings.TrimSpace(os.Getenv("DB_URL"))
	if dsn == "" {
		return nil, fmt.Errorf("missing DB_URL environment variable")
	}

	return OpenSQLite(SQLiteConfig{
		Driver: "sqlite3",
		DSN:    dsn,
	})
}
