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
			revocation_comment    TEXT,
			revoked_by            TEXT,
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

// --- Revocation reason codes (X.509 CRL) ---

// RevocationReasonCode maps string reasons to X.509 reason codes.
var RevocationReasonCode = map[string]int{
	"unspecified":            0,
	"key_compromise":         1,
	"ca_compromise":          2,
	"affiliation_changed":    3,
	"superseded":             4,
	"cessation_of_operation": 5,
	"certificate_hold":       6,
	"remove_from_crl":        8,
	"privilege_withdrawn":    9,
	"aa_compromise":          10,
}

// ValidRevocationReason checks if a reason string is valid.
func ValidRevocationReason(reason string) bool {
	_, ok := RevocationReasonCode[reason]
	return ok
}

// --- CA records ---

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

func (s *Store) GetCAByName(name string) (*CARecord, error) {
	r := &CARecord{}
	var notBefore, notAfter, createdAt, updatedAt string
	err := s.db.QueryRow(`SELECT id, name, type, parent_ca_id, subject, serial, not_before, not_after, certificate_pem, key_ref, status, created_at, updated_at FROM cas WHERE name = ?`, name).
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
	RevocationComment    string
	RevokedBy            string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	RenewedFromSerial    string
}

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

func (s *Store) GetCertBySerial(serial string) (*CertRecord, error) {
	r := &CertRecord{}
	var sansJSON, notBefore, notAfter, createdAt, updatedAt string
	var revokedAt, revComment, revokedBy sql.NullString
	err := s.db.QueryRow(`
		SELECT id, ca_id, serial, subject, common_name, sans_json, profile, not_before, not_after,
		       certificate_pem, public_key_fingerprint, status, revoked_at, revocation_reason,
		       revocation_comment, revoked_by, created_at, updated_at, renewed_from_serial
		FROM certificates WHERE serial = ?`, serial).
		Scan(&r.ID, &r.CAID, &r.Serial, &r.Subject, &r.CommonName, &sansJSON, &r.Profile,
			&notBefore, &notAfter, &r.CertificatePEM, &r.PublicKeyFingerprint,
			&r.Status, &revokedAt, &r.RevocationReason, &revComment, &revokedBy,
			&createdAt, &updatedAt, &r.RenewedFromSerial)
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
	if revComment.Valid {
		r.RevocationComment = revComment.String
	}
	if revokedBy.Valid {
		r.RevokedBy = revokedBy.String
	}
	return r, nil
}

func (s *Store) ListCerts() ([]*CertRecord, error) {
	return s.ListCertsFiltered("")
}

// ListCertsFiltered returns certificates optionally filtered by status.
func (s *Store) ListCertsFiltered(status string) ([]*CertRecord, error) {
	query := `SELECT id, ca_id, serial, subject, common_name, sans_json, profile, not_before, not_after,
	                 public_key_fingerprint, status, revoked_at, revocation_reason, created_at
	          FROM certificates`
	var args []any
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*CertRecord
	for rows.Next() {
		r := &CertRecord{}
		var sansJSON, notBefore, notAfter, createdAt string
		var revokedAt, revReason sql.NullString
		if err := rows.Scan(&r.ID, &r.CAID, &r.Serial, &r.Subject, &r.CommonName, &sansJSON, &r.Profile,
			&notBefore, &notAfter, &r.PublicKeyFingerprint, &r.Status, &revokedAt, &revReason, &createdAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(sansJSON), &r.SANs)
		r.NotBefore, _ = time.Parse(time.RFC3339, notBefore)
		r.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if revokedAt.Valid {
			t, _ := time.Parse(time.RFC3339, revokedAt.String)
			r.RevokedAt = &t
		}
		if revReason.Valid {
			r.RevocationReason = revReason.String
		}
		certs = append(certs, r)
	}
	return certs, nil
}

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

// RevokeOpts holds revocation parameters.
type RevokeOpts struct {
	Serial  string
	Reason  string
	Comment string
	Actor   string
}

// RevokeCert marks a certificate as revoked with full metadata.
func (s *Store) RevokeCert(opts RevokeOpts) error {
	if opts.Reason == "" {
		opts.Reason = "unspecified"
	}
	if opts.Actor == "" {
		opts.Actor = "cli"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`
		UPDATE certificates SET status = 'revoked', revoked_at = ?, revocation_reason = ?,
		       revocation_comment = ?, revoked_by = ?, updated_at = ?
		WHERE serial = ? AND status = 'active'`,
		now, opts.Reason, opts.Comment, opts.Actor, now, opts.Serial)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("certificate %s not found or already revoked", opts.Serial)
	}
	return nil
}

// RevokedEntry holds a revoked cert's serial, revocation time, and reason code.
type RevokedEntry struct {
	Serial     string
	RevokedAt  time.Time
	ReasonCode int
}

// ListRevoked returns all revoked certificate entries for a CA (for CRL generation).
func (s *Store) ListRevoked(caID int64) ([]RevokedEntry, error) {
	rows, err := s.db.Query(`
		SELECT serial, revoked_at, revocation_reason FROM certificates
		WHERE ca_id = ? AND status = 'revoked'
		ORDER BY revoked_at`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []RevokedEntry
	for rows.Next() {
		var serial, revokedAt string
		var reason sql.NullString
		if err := rows.Scan(&serial, &revokedAt, &reason); err != nil {
			return nil, err
		}
		e := RevokedEntry{Serial: serial}
		e.RevokedAt, _ = time.Parse(time.RFC3339, revokedAt)
		if reason.Valid {
			if code, ok := RevocationReasonCode[reason.String]; ok {
				e.ReasonCode = code
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// --- Private key records ---

func (s *Store) InsertKey(ownerType string, ownerID int64, keyRef, encryptedPEM, algorithm string) error {
	_, err := s.db.Exec(`
		INSERT INTO private_keys (owner_type, owner_id, key_ref, encrypted_key_pem, algorithm)
		VALUES (?, ?, ?, ?, ?)`, ownerType, ownerID, keyRef, encryptedPEM, algorithm)
	return err
}

func (s *Store) GetKey(ownerType string, ownerID int64) (string, error) {
	var keyPEM string
	err := s.db.QueryRow(`SELECT encrypted_key_pem FROM private_keys WHERE owner_type = ? AND owner_id = ?`, ownerType, ownerID).Scan(&keyPEM)
	return keyPEM, err
}

// --- Audit ---

func (s *Store) InsertAudit(actor, action, targetType, targetID string, details map[string]any) error {
	detailsJSON, _ := json.Marshal(details)
	_, err := s.db.Exec(`
		INSERT INTO audit_events (actor, action, target_type, target_id, details_json)
		VALUES (?, ?, ?, ?, ?)`, actor, action, targetType, targetID, string(detailsJSON))
	return err
}

type AuditEvent struct {
	ID         int64
	Timestamp  time.Time
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	Details    map[string]any
}

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

// --- Stats ---

type Stats struct {
	TotalCAs     int
	TotalCerts   int
	ActiveCerts  int
	RevokedCerts int
	ExpiringSoon int
}

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
