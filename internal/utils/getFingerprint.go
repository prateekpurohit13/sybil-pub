package utils

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sophic00/sybil/internal/db"
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
	authToken := os.Getenv("AUTH_TOKEN")

	if authToken == "" {
		return "", fmt.Errorf("missing authentication token in environment variables")
	}

	conn, err := db.OpenSQLiteFromEnv()
	if err != nil {
		return "", fmt.Errorf("failed to connect to database: %v", err)
	}
	defer conn.Close()

	if authToken != "expected_token_value" {
		return "", fmt.Errorf("invalid authentication token")
	}

	query := `SELECT application, library, device, os, user_agent_string, certificate_authority, verified, notes,
		ja4_fingerprint, ja4_fingerprint_string, ja4s_fingerprint, ja4h_fingerprint, ja4x_fingerprint,
		ja4t_fingerprint, ja4ts_fingerprint, ja4tscan_fingerprint
		FROM fingerprints WHERE ja4_fingerprint = ?`

	row := conn.QueryRow(query, input)

	var (
		fingerprint          Fingerprint
		application          sql.NullString
		library              sql.NullString
		device               sql.NullString
		osName               sql.NullString
		userAgent            sql.NullString
		certificateAuthority sql.NullString
		verified             int
		notes                sql.NullString
		ja4Fingerprint       sql.NullString
		ja4FingerprintString sql.NullString
		ja4sFingerprint      sql.NullString
		ja4hFingerprint      sql.NullString
		ja4xFingerprint      sql.NullString
		ja4tFingerprint      sql.NullString
		ja4tsFingerprint     sql.NullString
		ja4tscanFingerprint  sql.NullString
	)
	err = row.Scan(
		&application,
		&library,
		&device,
		&osName,
		&userAgent,
		&certificateAuthority,
		&verified,
		&notes,
		&ja4Fingerprint,
		&ja4FingerprintString,
		&ja4sFingerprint,
		&ja4hFingerprint,
		&ja4xFingerprint,
		&ja4tFingerprint,
		&ja4tsFingerprint,
		&ja4tscanFingerprint,
	)

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("404 not found")
	} else if err != nil {
		return "", fmt.Errorf("failed to query database: %v", err)
	}

	fingerprint.Application = nullStringPtr(application)
	fingerprint.Library = nullStringPtr(library)
	fingerprint.Device = nullStringPtr(device)
	fingerprint.OS = nullStringPtr(osName)
	fingerprint.UserAgentString = nullStringValue(userAgent)
	fingerprint.CertificateAuthority = nullStringPtr(certificateAuthority)
	fingerprint.Verified = verified == 1
	fingerprint.Notes = nullStringPtr(notes)
	fingerprint.JA4Fingerprint = nullStringValue(ja4Fingerprint)
	fingerprint.JA4FingerprintString = nullStringValue(ja4FingerprintString)
	fingerprint.JA4SFingerprint = nullStringPtr(ja4sFingerprint)
	fingerprint.JA4HFingerprint = nullStringValue(ja4hFingerprint)
	fingerprint.JA4XFingerprint = nullStringPtr(ja4xFingerprint)
	fingerprint.JA4TFingerprint = nullStringPtr(ja4tFingerprint)
	fingerprint.JA4TSFingerprint = nullStringPtr(ja4tsFingerprint)
	fingerprint.JA4TScanFingerprint = nullStringPtr(ja4tscanFingerprint)

	jsonData, err := json.Marshal(fingerprint)
	if err != nil {
		return "", fmt.Errorf("failed to convert fingerprint to JSON: %v", err)
	}

	return string(jsonData), nil

}

func nullStringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}

	copy := value.String
	return &copy
}

func nullStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}
