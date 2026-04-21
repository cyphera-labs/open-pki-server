package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store provides PKI lifecycle storage backed by SQLite.
type Store struct {
	db *sql.DB
}

// Open creates or opens a SQLite database at the given path.
// Use ":memory:" for in-memory testing.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS cas (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			name            TEXT NOT NULL,
			type            TEXT NOT NULL CHECK(type IN ('root', 'intermediate')),
			parent_ca_id    INTEGER REFERENCES cas(id),
			subject         TEXT NOT NULL,
			serial          TEXT NOT NULL UNIQUE,
			not_before      TEXT NOT NULL,
			not_after       TEXT NOT NULL,
			certificate_pem TEXT NOT NULL,
			key_ref         TEXT NOT NULL DEFAULT 'local',
			status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked', 'expired')),
			created_at      TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS certificates (
			id                    INTEGER PRIMARY KEY AUTOINCREMENT,
			ca_id                 INTEGER NOT NULL REFERENCES cas(id),
			serial                TEXT NOT NULL UNIQUE,
			subject               TEXT NOT NULL,
			common_name           TEXT NOT NULL,
			sans_json             TEXT NOT NULL DEFAULT '[]',
			profile               TEXT NOT NULL,
			not_before            TEXT NOT NULL,
			not_after             TEXT NOT NULL,
			certificate_pem       TEXT NOT NULL,
			public_key_fingerprint TEXT NOT NULL,
			status                TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked', 'expired')),
			revoked_at            TEXT,
			revocation_reason     TEXT,
			created_at            TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at            TEXT NOT NULL DEFAULT (datetime('now')),
			renewed_from_serial   TEXT
		);

		CREATE TABLE IF NOT EXISTS private_keys (
			id                INTEGER PRIMARY KEY AUTOINCREMENT,
			owner_type        TEXT NOT NULL CHECK(owner_type IN ('ca', 'certificate')),
			owner_id          INTEGER NOT NULL,
			key_ref           TEXT NOT NULL DEFAULT 'local',
			encrypted_key_pem TEXT NOT NULL,
			algorithm         TEXT NOT NULL,
			created_at        TEXT NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS audit_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp    TEXT NOT NULL DEFAULT (datetime('now')),
			actor        TEXT NOT NULL DEFAULT 'cli',
			action       TEXT NOT NULL,
			target_type  TEXT NOT NULL,
			target_id    TEXT NOT NULL,
			details_json TEXT NOT NULL DEFAULT '{}'
		);

		CREATE INDEX IF NOT EXISTS idx_certificates_ca_id ON certificates(ca_id);
		CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
		CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
		CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
	`)
	return err
}

// --- CA records ---

// CARecord represents a stored CA.
type CARecord struct {
	ID             int64
	Name           string
	Type           string
	ParentCAID     *int64
	Subject        string
	Serial         string
	NotBefore      time.Time
	NotAfter       time.Time
	CertificatePEM string
	KeyRef         string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// InsertCA stores a new CA record and returns its ID.
func (s *Store) InsertCA(r *CARecord) (int64, error) {
	res, err := s.db.Exec(`
		INSERT INTO cas (name, type, parent_ca_id, subject, serial, not_before, not_after, certificate_pem, key_ref, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Type, r.ParentCAID, r.Subject, r.Serial,
		r.NotBefore.UTC().Format(time.RFC3339), r.NotAfter.UTC().Format(time.RFC3339),
		r.CertificatePEM, r.KeyRef, r.Status,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetCA retrieves a CA by ID.
func (s *Store) GetCA(id int64) (*CARecord, error) {
	r := &CARecord{}
	var notBefore, notAfter, createdAt, updatedAt string
	err := s.db.QueryRow(`SELECT id, name, type, parent_ca_id, subject, serial, not_before, not_after, certificate_pem, key_ref, status, created_at, updated_at FROM cas WHERE id = ?`, id).
		Scan(&r.ID, &r.Name, &r.Type, &r.ParentCAID, &r.Subject, &r.Serial, &notBefore, &notAfter, &r.CertificatePEM, &r.KeyRef, &r.Status, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	r.NotBefore, _ = time.Parse(time.RFC3339, notBefore)
	r.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
	r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	r.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return r, nil
}

// ListCAs returns all CA records.
func (s *Store) ListCAs() ([]*CARecord, error) {
	rows, err := s.db.Query(`SELECT id, name, type, parent_ca_id, subject, serial, not_before, not_after, key_ref, status, created_at FROM cas ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cas []*CARecord
	for rows.Next() {
		r := &CARecord{}
		var notBefore, notAfter, createdAt string
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.ParentCAID, &r.Subject, &r.Serial, &notBefore, &notAfter, &r.KeyRef, &r.Status, &createdAt); err != nil {
			return nil, err
		}
		r.NotBefore, _ = time.Parse(time.RFC3339, notBefore)
		r.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		cas = append(cas, r)
	}
	return cas, nil
}

// --- Certificate records ---

// CertRecord represents a stored certificate.
type CertRecord struct {
	ID                   int64
	CAID                 int64
	Serial               string
	Subject              string
	CommonName           string
	SANs                 []string
	Profile              string
	NotBefore            time.Time
	NotAfter             time.Time
	CertificatePEM       string
	PublicKeyFingerprint string
	Status               string
	RevokedAt            *time.Time
	RevocationReason     string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	RenewedFromSerial    string
}

// InsertCert stores a new certificate record and returns its ID.
func (s *Store) InsertCert(r *CertRecord) (int64, error) {
	sansJSON, _ := json.Marshal(r.SANs)
	res, err := s.db.Exec(`
		INSERT INTO certificates (ca_id, serial, subject, common_name, sans_json, profile, not_before, not_after, certificate_pem, public_key_fingerprint, status, renewed_from_serial)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.CAID, r.Serial, r.Subject, r.CommonName, string(sansJSON), r.Profile,
		r.NotBefore.UTC().Format(time.RFC3339), r.NotAfter.UTC().Format(time.RFC3339),
		r.CertificatePEM, r.PublicKeyFingerprint, r.Status, r.RenewedFromSerial,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetCertBySerial retrieves a certificate by serial number.
func (s *Store) GetCertBySerial(serial string) (*CertRecord, error) {
	r := &CertRecord{}
	var sansJSON, notBefore, notAfter, createdAt, updatedAt string
	var revokedAt sql.NullString
	err := s.db.QueryRow(`
		SELECT id, ca_id, serial, subject, common_name, sans_json, profile, not_before, not_after,
		       certificate_pem, public_key_fingerprint, status, revoked_at, revocation_reason,
		       created_at, updated_at, renewed_from_serial
		FROM certificates WHERE serial = ?`, serial).
		Scan(&r.ID, &r.CAID, &r.Serial, &r.Subject, &r.CommonName, &sansJSON, &r.Profile,
			&notBefore, &notAfter, &r.CertificatePEM, &r.PublicKeyFingerprint,
			&r.Status, &revokedAt, &r.RevocationReason, &createdAt, &updatedAt, &r.RenewedFromSerial)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(sansJSON), &r.SANs)
	r.NotBefore, _ = time.Parse(time.RFC3339, notBefore)
	r.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
	r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	r.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if revokedAt.Valid {
		t, _ := time.Parse(time.RFC3339, revokedAt.String)
		r.RevokedAt = &t
	}
	return r, nil
}

// ListCerts returns all certificate records, ordered by creation time.
func (s *Store) ListCerts() ([]*CertRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, ca_id, serial, subject, common_name, sans_json, profile, not_before, not_after,
		       public_key_fingerprint, status, created_at
		FROM certificates ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*CertRecord
	for rows.Next() {
		r := &CertRecord{}
		var sansJSON, notBefore, notAfter, createdAt string
		if err := rows.Scan(&r.ID, &r.CAID, &r.Serial, &r.Subject, &r.CommonName, &sansJSON, &r.Profile,
			&notBefore, &notAfter, &r.PublicKeyFingerprint, &r.Status, &createdAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(sansJSON), &r.SANs)
		r.NotBefore, _ = time.Parse(time.RFC3339, notBefore)
		r.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		certs = append(certs, r)
	}
	return certs, nil
}

// ListExpiring returns certificates expiring within the given number of days.
func (s *Store) ListExpiring(days int) ([]*CertRecord, error) {
	deadline := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)
	rows, err := s.db.Query(`
		SELECT id, ca_id, serial, subject, common_name, sans_json, profile, not_before, not_after,
		       public_key_fingerprint, status, created_at
		FROM certificates
		WHERE status = 'active' AND not_after <= ?
		ORDER BY not_after ASC`, deadline)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*CertRecord
	for rows.Next() {
		r := &CertRecord{}
		var sansJSON, notBefore, notAfter, createdAt string
		if err := rows.Scan(&r.ID, &r.CAID, &r.Serial, &r.Subject, &r.CommonName, &sansJSON, &r.Profile,
			&notBefore, &notAfter, &r.PublicKeyFingerprint, &r.Status, &createdAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(sansJSON), &r.SANs)
		r.NotBefore, _ = time.Parse(time.RFC3339, notBefore)
		r.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		certs = append(certs, r)
	}
	return certs, nil
}

// RevokeCert marks a certificate as revoked.
func (s *Store) RevokeCert(serial, reason string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`
		UPDATE certificates SET status = 'revoked', revoked_at = ?, revocation_reason = ?, updated_at = ?
		WHERE serial = ? AND status = 'active'`, now, reason, now, serial)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("certificate %s not found or already revoked", serial)
	}
	return nil
}

// ListRevoked returns all revoked certificate serials and revocation times (for CRL generation).
func (s *Store) ListRevoked(caID int64) ([]RevokedEntry, error) {
	rows, err := s.db.Query(`
		SELECT serial, revoked_at FROM certificates
		WHERE ca_id = ? AND status = 'revoked'
		ORDER BY revoked_at`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []RevokedEntry
	for rows.Next() {
		var e RevokedEntry
		var revokedAt string
		if err := rows.Scan(&e.Serial, &revokedAt); err != nil {
			return nil, err
		}
		e.RevokedAt, _ = time.Parse(time.RFC3339, revokedAt)
		entries = append(entries, e)
	}
	return entries, nil
}

// RevokedEntry holds a revoked cert serial and revocation time.
type RevokedEntry struct {
	Serial    string
	RevokedAt time.Time
}

// --- Private key records ---

// InsertKey stores a private key record.
func (s *Store) InsertKey(ownerType string, ownerID int64, keyRef, encryptedPEM, algorithm string) error {
	_, err := s.db.Exec(`
		INSERT INTO private_keys (owner_type, owner_id, key_ref, encrypted_key_pem, algorithm)
		VALUES (?, ?, ?, ?, ?)`, ownerType, ownerID, keyRef, encryptedPEM, algorithm)
	return err
}

// GetKey retrieves a private key PEM by owner.
func (s *Store) GetKey(ownerType string, ownerID int64) (string, error) {
	var keyPEM string
	err := s.db.QueryRow(`SELECT encrypted_key_pem FROM private_keys WHERE owner_type = ? AND owner_id = ?`, ownerType, ownerID).Scan(&keyPEM)
	return keyPEM, err
}

// --- Audit ---

// InsertAudit logs an audit event.
func (s *Store) InsertAudit(actor, action, targetType, targetID string, details map[string]any) error {
	detailsJSON, _ := json.Marshal(details)
	_, err := s.db.Exec(`
		INSERT INTO audit_events (actor, action, target_type, target_id, details_json)
		VALUES (?, ?, ?, ?, ?)`, actor, action, targetType, targetID, string(detailsJSON))
	return err
}

// AuditEvent represents a stored audit event.
type AuditEvent struct {
	ID         int64
	Timestamp  time.Time
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	Details    map[string]any
}

// ListAudit returns recent audit events.
func (s *Store) ListAudit(limit int) ([]*AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`
		SELECT id, timestamp, actor, action, target_type, target_id, details_json
		FROM audit_events ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*AuditEvent
	for rows.Next() {
		e := &AuditEvent{}
		var ts, detailsJSON string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &detailsJSON); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		_ = json.Unmarshal([]byte(detailsJSON), &e.Details)
		events = append(events, e)
	}
	return events, nil
}

// Stats returns summary counts.
type Stats struct {
	TotalCAs     int
	TotalCerts   int
	ActiveCerts  int
	RevokedCerts int
	ExpiringSoon int // within 30 days
}

// GetStats returns dashboard summary stats.
func (s *Store) GetStats() (*Stats, error) {
	st := &Stats{}
	s.db.QueryRow(`SELECT COUNT(*) FROM cas`).Scan(&st.TotalCAs)
	s.db.QueryRow(`SELECT COUNT(*) FROM certificates`).Scan(&st.TotalCerts)
	s.db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE status = 'active'`).Scan(&st.ActiveCerts)
	s.db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE status = 'revoked'`).Scan(&st.RevokedCerts)

	deadline := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	s.db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE status = 'active' AND not_after <= ?`, deadline).Scan(&st.ExpiringSoon)

	return st, nil
}
