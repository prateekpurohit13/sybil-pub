package risk

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/sophic00/sybil/internal/db"
)

type LibSQLLookupClient struct {
	db *sql.DB
}

func NewLibSQLLookupClient(cfg db.SQLiteConfig) (*LibSQLLookupClient, func(), error) {
	conn, err := db.OpenSQLite(cfg)
	if err != nil {
		return nil, func() {}, err
	}
	return &LibSQLLookupClient{db: conn}, func() { _ = conn.Close() }, nil
}

func (c *LibSQLLookupClient) Lookup(ctx context.Context, ja4 string) (*FingerprintRecord, error) {
	if c == nil || c.db == nil {
		return nil, nil
	}

	row := c.db.QueryRowContext(ctx, `
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
			ja4_fingerprint_string,
			ja4s_fingerprint,
			ja4h_fingerprint,
			ja4x_fingerprint,
			ja4t_fingerprint,
			ja4ts_fingerprint,
			ja4tscan_fingerprint
		FROM fingerprints
		WHERE ja4_fingerprint = ?
		ORDER BY
			(application IS NOT NULL AND TRIM(application) <> '') DESC,
			(library IS NOT NULL AND TRIM(library) <> '') DESC,
			(device IS NOT NULL AND TRIM(device) <> '') DESC,
			(os IS NOT NULL AND TRIM(os) <> '') DESC,
			(notes IS NOT NULL AND TRIM(notes) <> '') DESC
		LIMIT 1`, strings.TrimSpace(ja4))

	var (
		record               FingerprintRecord
		application          sql.NullString
		library              sql.NullString
		device               sql.NullString
		osName               sql.NullString
		userAgent            sql.NullString
		certificateAuthority sql.NullString
		verified             sql.NullInt64
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
	if err := row.Scan(
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
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrFingerprintNotFound
		}
		return nil, fmt.Errorf("query fingerprint db: %w", err)
	}

	record.Application = application.String
	record.Library = library.String
	record.Device = device.String
	record.OS = osName.String
	record.UserAgentString = userAgent.String
	record.CertificateAuthority = certificateAuthority.String
	record.Verified = verified.Valid && verified.Int64 != 0
	record.Notes = notes.String
	record.JA4Fingerprint = ja4Fingerprint.String
	record.JA4FingerprintString = ja4FingerprintString.String
	record.JA4SFingerprint = ja4sFingerprint.String
	record.JA4HFingerprint = ja4hFingerprint.String
	record.JA4XFingerprint = ja4xFingerprint.String
	record.JA4TFingerprint = ja4tFingerprint.String
	record.JA4TSFingerprint = ja4tsFingerprint.String
	record.JA4TScanFingerprint = ja4tscanFingerprint.String
	if strings.TrimSpace(record.JA4Fingerprint) == "" {
		record.JA4Fingerprint = strings.TrimSpace(ja4)
	}

	return &record, nil
}
