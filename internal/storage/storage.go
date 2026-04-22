package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

// Store provides PKI lifecycle storage backed by SQLite.
type Store struct {
	db *sql.DB
}

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
	if _, err := db.Exec("PRAGMA secure_delete=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable secure_delete: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	// Harden file permissions
	os.Chmod(path, 0600)
	os.Chmod(path+"-wal", 0600)
	os.Chmod(path+"-shm", 0600)

	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		-- ============================================================
		-- PKI artifact tables (certificate-native facts only)
		-- ============================================================

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
			id                     INTEGER PRIMARY KEY AUTOINCREMENT,
			ca_id                  INTEGER NOT NULL REFERENCES cas(id),
			serial                 TEXT NOT NULL UNIQUE,
			subject                TEXT NOT NULL,
			common_name            TEXT NOT NULL,
			sans_json              TEXT NOT NULL DEFAULT '[]',
			profile                TEXT NOT NULL,
			not_before             TEXT NOT NULL,
			not_after              TEXT NOT NULL,
			certificate_pem        TEXT NOT NULL,
			public_key_fingerprint TEXT NOT NULL,
			key_algorithm          TEXT NOT NULL DEFAULT 'ed25519',
			issuance_mode          TEXT NOT NULL DEFAULT 'generated' CHECK(issuance_mode IN ('generated', 'csr')),
			status                 TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked', 'expired')),
			revoked_at             TEXT,
			revocation_reason      TEXT,
			revocation_comment     TEXT,
			revoked_by             TEXT,
			renewed_from_serial    TEXT,
			created_at             TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at             TEXT NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS private_keys (
			id                INTEGER PRIMARY KEY AUTOINCREMENT,
			owner_type        TEXT NOT NULL CHECK(owner_type IN ('ca', 'certificate')),
			owner_id          INTEGER NOT NULL,
			key_ref           TEXT NOT NULL DEFAULT 'local',
			key_pem TEXT NOT NULL,
			algorithm         TEXT NOT NULL,
			created_at        TEXT NOT NULL DEFAULT (datetime('now'))
		);

		-- ============================================================
		-- Generic asset graph (reusable across certs, keys, secrets, etc.)
		-- ============================================================

		CREATE TABLE IF NOT EXISTS assets (
			id         TEXT PRIMARY KEY,
			asset_type TEXT NOT NULL,
			native_id  TEXT NOT NULL,
			source     TEXT NOT NULL DEFAULT 'open-pki-server',
			name       TEXT NOT NULL,
			status     TEXT NOT NULL DEFAULT 'active',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS asset_metadata (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			asset_id   TEXT NOT NULL REFERENCES assets(id),
			key        TEXT NOT NULL,
			value      TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now')),
			UNIQUE(asset_id, key)
		);

		CREATE TABLE IF NOT EXISTS tags (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			name       TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS asset_tags (
			asset_id TEXT NOT NULL REFERENCES assets(id),
			tag_id   INTEGER NOT NULL REFERENCES tags(id),
			PRIMARY KEY(asset_id, tag_id)
		);

		CREATE TABLE IF NOT EXISTS asset_relationships (
			id                INTEGER PRIMARY KEY AUTOINCREMENT,
			from_asset_id     TEXT NOT NULL REFERENCES assets(id),
			relationship_type TEXT NOT NULL,
			to_asset_id       TEXT NOT NULL,
			metadata_json     TEXT NOT NULL DEFAULT '{}',
			created_at        TEXT NOT NULL DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS asset_lifecycle_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			asset_id     TEXT NOT NULL,
			event_type   TEXT NOT NULL,
			actor        TEXT NOT NULL DEFAULT 'system',
			timestamp    TEXT NOT NULL DEFAULT (datetime('now')),
			result       TEXT NOT NULL DEFAULT 'success',
			details_json TEXT NOT NULL DEFAULT '{}'
		);

		-- ============================================================
		-- Indexes
		-- ============================================================

		CREATE INDEX IF NOT EXISTS idx_certificates_ca_id ON certificates(ca_id);
		CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
		CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
		CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
		CREATE INDEX IF NOT EXISTS idx_asset_metadata_asset ON asset_metadata(asset_id);
		CREATE INDEX IF NOT EXISTS idx_asset_metadata_key_value ON asset_metadata(key, value);
		CREATE INDEX IF NOT EXISTS idx_asset_relationships_from ON asset_relationships(from_asset_id);
		CREATE INDEX IF NOT EXISTS idx_asset_relationships_to ON asset_relationships(to_asset_id);
		CREATE INDEX IF NOT EXISTS idx_asset_lifecycle_asset ON asset_lifecycle_events(asset_id);
		CREATE INDEX IF NOT EXISTS idx_asset_lifecycle_type ON asset_lifecycle_events(event_type);
	`)
	return err
}

// ============================================================
// Revocation reason codes
// ============================================================

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

func ValidRevocationReason(reason string) bool {
	_, ok := RevocationReasonCode[reason]
	return ok
}

// ============================================================
// CA records
// ============================================================

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

// ============================================================
// Certificate records (PKI facts only)
// ============================================================

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
	KeyAlgorithm         string
	IssuanceMode         string
	Status               string
	RevokedAt            *time.Time
	RevocationReason     string
	RevocationComment    string
	RevokedBy            string
	RenewedFromSerial    string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (s *Store) InsertCert(r *CertRecord) (int64, error) {
	sansJSON, _ := json.Marshal(r.SANs)
	if r.KeyAlgorithm == "" {
		r.KeyAlgorithm = "ed25519"
	}
	if r.IssuanceMode == "" {
		r.IssuanceMode = "generated"
	}
	res, err := s.db.Exec(`
		INSERT INTO certificates (ca_id, serial, subject, common_name, sans_json, profile, not_before, not_after, certificate_pem, public_key_fingerprint, key_algorithm, issuance_mode, status, renewed_from_serial)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.CAID, r.Serial, r.Subject, r.CommonName, string(sansJSON), r.Profile,
		r.NotBefore.UTC().Format(time.RFC3339), r.NotAfter.UTC().Format(time.RFC3339),
		r.CertificatePEM, r.PublicKeyFingerprint, r.KeyAlgorithm, r.IssuanceMode, r.Status, r.RenewedFromSerial,
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
		       certificate_pem, public_key_fingerprint, key_algorithm, issuance_mode, status,
		       revoked_at, revocation_reason, revocation_comment, revoked_by,
		       renewed_from_serial, created_at, updated_at
		FROM certificates WHERE serial = ?`, serial).
		Scan(&r.ID, &r.CAID, &r.Serial, &r.Subject, &r.CommonName, &sansJSON, &r.Profile,
			&notBefore, &notAfter, &r.CertificatePEM, &r.PublicKeyFingerprint,
			&r.KeyAlgorithm, &r.IssuanceMode, &r.Status,
			&revokedAt, &r.RevocationReason, &revComment, &revokedBy,
			&r.RenewedFromSerial, &createdAt, &updatedAt)
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
		FROM certificates WHERE status = 'active' AND not_after <= ?
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

// ============================================================
// Revocation
// ============================================================

type RevokeOpts struct {
	Serial  string
	Reason  string
	Comment string
	Actor   string
}

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

type RevokedEntry struct {
	Serial     string
	RevokedAt  time.Time
	ReasonCode int
}

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

// ============================================================
// Private keys
// ============================================================

// InsertKey stores a private key. NOTE: key_pem is stored as plaintext PEM in this alpha.
// Envelope encryption is planned but not yet implemented.
func (s *Store) InsertKey(ownerType string, ownerID int64, keyRef, keyPEM, algorithm string) error {
	_, err := s.db.Exec(`
		INSERT INTO private_keys (owner_type, owner_id, key_ref, key_pem, algorithm)
		VALUES (?, ?, ?, ?, ?)`, ownerType, ownerID, keyRef, keyPEM, algorithm)
	return err
}

func (s *Store) GetKey(ownerType string, ownerID int64) (string, error) {
	var keyPEM string
	err := s.db.QueryRow(`SELECT key_pem FROM private_keys WHERE owner_type = ? AND owner_id = ?`, ownerType, ownerID).Scan(&keyPEM)
	return keyPEM, err
}

// ============================================================
// Asset graph — generic inventory/context layer
// ============================================================

// RegisterAsset creates an asset record. Idempotent — upserts on id.
func (s *Store) RegisterAsset(id, assetType, nativeID, name, status string) error {
	_, err := s.db.Exec(`
		INSERT INTO assets (id, asset_type, native_id, source, name, status)
		VALUES (?, ?, ?, 'open-pki-server', ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, status = excluded.status, updated_at = datetime('now')`,
		id, assetType, nativeID, name, status)
	return err
}

// SetMetadata sets a metadata key-value on an asset. Upserts.
func (s *Store) SetMetadata(assetID, key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO asset_metadata (asset_id, key, value)
		VALUES (?, ?, ?)
		ON CONFLICT(asset_id, key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
		assetID, key, value)
	return err
}

// GetMetadata returns all metadata for an asset.
func (s *Store) GetMetadata(assetID string) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM asset_metadata WHERE asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[string]string)
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		m[k] = v
	}
	return m, nil
}

// TagAsset attaches a tag to an asset. Creates the tag if needed.
func (s *Store) TagAsset(assetID, tagName string) error {
	s.db.Exec(`INSERT OR IGNORE INTO tags (name) VALUES (?)`, tagName)
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO asset_tags (asset_id, tag_id)
		SELECT ?, id FROM tags WHERE name = ?`, assetID, tagName)
	return err
}

// GetTags returns all tag names for an asset.
func (s *Store) GetTags(assetID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT t.name FROM tags t JOIN asset_tags at ON t.id = at.tag_id WHERE at.asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		tags = append(tags, name)
	}
	return tags, nil
}

// AddRelationship links two assets.
func (s *Store) AddRelationship(fromAssetID, relType, toAssetID string, metadata map[string]any) error {
	metaJSON, _ := json.Marshal(metadata)
	_, err := s.db.Exec(`
		INSERT INTO asset_relationships (from_asset_id, relationship_type, to_asset_id, metadata_json)
		VALUES (?, ?, ?, ?)`, fromAssetID, relType, toAssetID, string(metaJSON))
	return err
}

// AssetRelationship represents a relationship between two assets.
type AssetRelationship struct {
	Type     string         `json:"type"`
	Target   string         `json:"target"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// GetRelationships returns all relationships from an asset.
func (s *Store) GetRelationships(assetID string) ([]AssetRelationship, error) {
	rows, err := s.db.Query(`SELECT relationship_type, to_asset_id, metadata_json FROM asset_relationships WHERE from_asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rels []AssetRelationship
	for rows.Next() {
		var r AssetRelationship
		var metaJSON string
		rows.Scan(&r.Type, &r.Target, &metaJSON)
		_ = json.Unmarshal([]byte(metaJSON), &r.Metadata)
		rels = append(rels, r)
	}
	return rels, nil
}

// EmitLifecycleEvent records a lifecycle event on an asset.
func (s *Store) EmitLifecycleEvent(assetID, eventType, actor string, details map[string]any) error {
	detailsJSON, _ := json.Marshal(details)
	_, err := s.db.Exec(`
		INSERT INTO asset_lifecycle_events (asset_id, event_type, actor, details_json)
		VALUES (?, ?, ?, ?)`, assetID, eventType, actor, string(detailsJSON))
	return err
}

// LifecycleEvent represents a lifecycle event.
type LifecycleEvent struct {
	ID        int64          `json:"id"`
	AssetID   string         `json:"asset_id"`
	EventType string         `json:"event_type"`
	Actor     string         `json:"actor"`
	Timestamp time.Time      `json:"timestamp"`
	Result    string         `json:"result"`
	Details   map[string]any `json:"details,omitempty"`
}

// ListLifecycleEvents returns events, optionally filtered by asset.
func (s *Store) ListLifecycleEvents(assetID string, limit int) ([]*LifecycleEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	var query string
	var args []any
	if assetID != "" {
		query = `SELECT id, asset_id, event_type, actor, timestamp, result, details_json
		         FROM asset_lifecycle_events WHERE asset_id = ? ORDER BY timestamp DESC LIMIT ?`
		args = []any{assetID, limit}
	} else {
		query = `SELECT id, asset_id, event_type, actor, timestamp, result, details_json
		         FROM asset_lifecycle_events ORDER BY timestamp DESC LIMIT ?`
		args = []any{limit}
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []*LifecycleEvent
	for rows.Next() {
		e := &LifecycleEvent{}
		var ts, detailsJSON string
		if err := rows.Scan(&e.ID, &e.AssetID, &e.EventType, &e.Actor, &ts, &e.Result, &detailsJSON); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		_ = json.Unmarshal([]byte(detailsJSON), &e.Details)
		events = append(events, e)
	}
	return events, nil
}

// ============================================================
// Inventory — full asset view
// ============================================================

// AssetView is the combined view returned by inventory endpoints.
type AssetView struct {
	ID            string              `json:"id"`
	Type          string              `json:"type"`
	Source        string              `json:"source"`
	Name          string              `json:"name"`
	Status        string              `json:"status"`
	CreatedAt     string              `json:"created_at"`
	ExpiresAt     string              `json:"expires_at,omitempty"`
	Fingerprint   string              `json:"fingerprint,omitempty"`
	Metadata      map[string]string   `json:"metadata,omitempty"`
	Tags          []string            `json:"tags,omitempty"`
	Relationships []AssetRelationship `json:"relationships,omitempty"`
}

// ListInventory returns full asset views for all registered assets.
func (s *Store) ListInventory() ([]*AssetView, error) {
	rows, err := s.db.Query(`SELECT id, asset_type, name, status, created_at FROM assets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var views []*AssetView
	for rows.Next() {
		v := &AssetView{Source: "open-pki-server"}
		var createdAt string
		if err := rows.Scan(&v.ID, &v.Type, &v.Name, &v.Status, &createdAt); err != nil {
			return nil, err
		}
		v.CreatedAt = createdAt
		v.Metadata, _ = s.GetMetadata(v.ID)
		v.Tags, _ = s.GetTags(v.ID)
		v.Relationships, _ = s.GetRelationships(v.ID)
		views = append(views, v)
	}
	return views, nil
}

// FindAssetsByMetadata finds assets with a given metadata key-value.
func (s *Store) FindAssetsByMetadata(key, value string) ([]string, error) {
	rows, err := s.db.Query(`SELECT asset_id FROM asset_metadata WHERE key = ? AND value = ?`, key, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, nil
}

// ============================================================
// Stats (dashboard)
// ============================================================

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

// ============================================================
// Legacy audit compat — delegates to lifecycle events
// ============================================================

func (s *Store) InsertAudit(actor, action, targetType, targetID string, details map[string]any) error {
	return s.EmitLifecycleEvent(targetType+":"+targetID, action, actor, details)
}

func (s *Store) ListAudit(limit int) ([]*LifecycleEvent, error) {
	return s.ListLifecycleEvents("", limit)
}
