package utils

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// Fingerprint struct to represent the fingerprint data
type Fingerprint struct {
	Application          *string `json:"application"`
	Library              *string `json:"library"`
	Device               *string `json:"device"`
	OS                   *string `json:"os"`
	UserAgentString      string  `json:"user_agent_string"`
	CertificateAuthority *string `json:"certificate_authority"`
	Verified             bool    `json:"verified"`
	Notes                *string `json:"notes"`
	JA4Fingerprint       string  `json:"ja4_fingerprint"`
	JA4FingerprintString string  `json:"ja4_fingerprint_string"`
	JA4SFingerprint      *string `json:"ja4s_fingerprint"`
	JA4HFingerprint      string  `json:"ja4h_fingerprint"`
	JA4XFingerprint      *string `json:"ja4x_fingerprint"`
	JA4TFingerprint      *string `json:"ja4t_fingerprint"`
	JA4TSFingerprint     *string `json:"ja4ts_fingerprint"`
	JA4TScanFingerprint  *string `json:"ja4tscan_fingerprint"`
}

func GetFingerprint(input string) (string, error) {
	dbURL := os.Getenv("DB_URL")
	authToken := os.Getenv("AUTH_TOKEN")

	if dbURL == "" || authToken == "" {
		return "", fmt.Errorf("missing database URL or authentication token in environment variables")
	}
	db, err := sql.Open("sqlite3", dbURL)
	if err != nil {
		return "", fmt.Errorf("failed to connect to database: %v", err)
	}
	defer db.Close()

	if authToken != "expected_token_value" {
		return "", fmt.Errorf("invalid authentication token")
	}

	query := `SELECT application, library, device, os, user_agent_string, certificate_authority, verified, notes,
		ja4_fingerprint, ja4_fingerprint_string, ja4s_fingerprint, ja4h_fingerprint, ja4x_fingerprint,
		ja4t_fingerprint, ja4ts_fingerprint, ja4tscan_fingerprint
		FROM fingerprints WHERE ja4_fingerprint = ?`

	row := db.QueryRow(query, input)

	var fingerprint Fingerprint
	var verified int
	err = row.Scan(
		&fingerprint.Application,
		&fingerprint.Library,
		&fingerprint.Device,
		&fingerprint.OS,
		&fingerprint.UserAgentString,
		&fingerprint.CertificateAuthority,
		&verified,
		&fingerprint.Notes,
	)

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("404 not found")
	} else if err != nil {
		return "", fmt.Errorf("failed to query database: %v", err)
	}

	fingerprint.Verified = verified == 1

	jsonData, err := json.Marshal(fingerprint)
	if err != nil {
		return "", fmt.Errorf("failed to convert fingerprint to JSON: %v", err)
	}

	return string(jsonData), nil

}
