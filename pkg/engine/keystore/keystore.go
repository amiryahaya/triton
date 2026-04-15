// Package keystore is the engine-side encrypted secret store. Secrets
// (delivered from the portal as sealed boxes and decrypted by the
// credential handler) are persisted in a local SQLite database at rest
// under ChaCha20-Poly1305 with a 32-byte master key.
//
// The master key is supplied by the caller and should be derived from
// an operator-supplied passphrase or generated once and stored outside
// this DB.
package keystore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

// ErrNotFound is returned by Get when secret_ref is unknown.
var ErrNotFound = errors.New("keystore: secret not found")

// Keystore owns the SQLite connection pool and AEAD master key.
type Keystore struct {
	db        *sql.DB
	masterKey []byte
}

// SecretMeta is the metadata row returned by List.
type SecretMeta struct {
	SecretRef string
	ProfileID string
	AuthType  string
	CreatedAt time.Time
}

// Open initialises the keystore at path (created if absent) and
// ensures the schema exists. masterKey must be exactly 32 bytes.
func Open(path string, masterKey []byte) (*Keystore, error) {
	if len(masterKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", chacha20poly1305.KeySize, len(masterKey))
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &Keystore{db: db, masterKey: append([]byte(nil), masterKey...)}, nil
}

const schemaDDL = `
CREATE TABLE IF NOT EXISTS secrets (
    secret_ref TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    auth_type  TEXT NOT NULL,
    payload    BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    created_at INTEGER NOT NULL
)`

// Close releases the underlying DB pool.
func (k *Keystore) Close() error {
	return k.db.Close()
}

// Put encrypts plaintext under a freshly generated 12-byte nonce and
// upserts the row keyed by secretRef. Callers SHOULD zero plaintext
// after Put returns.
func (k *Keystore) Put(ctx context.Context, secretRef, profileID, authType string, plaintext []byte) error {
	aead, err := chacha20poly1305.New(k.masterKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	payload := aead.Seal(nil, nonce, plaintext, nil)
	_, err = k.db.ExecContext(ctx, `
INSERT INTO secrets (secret_ref, profile_id, auth_type, payload, nonce, created_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (secret_ref) DO UPDATE SET
    profile_id = excluded.profile_id,
    auth_type  = excluded.auth_type,
    payload    = excluded.payload,
    nonce      = excluded.nonce,
    created_at = excluded.created_at
`, secretRef, profileID, authType, payload, nonce, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("upsert secret: %w", err)
	}
	return nil
}

// Get decrypts and returns the stored plaintext along with its
// auth_type. Callers SHOULD zero the returned plaintext when done.
func (k *Keystore) Get(ctx context.Context, secretRef string) (authType string, plaintext []byte, err error) {
	var payload, nonce []byte
	row := k.db.QueryRowContext(ctx,
		`SELECT auth_type, payload, nonce FROM secrets WHERE secret_ref = ?`, secretRef)
	if err := row.Scan(&authType, &payload, &nonce); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, ErrNotFound
		}
		return "", nil, err
	}
	aead, err := chacha20poly1305.New(k.masterKey)
	if err != nil {
		return "", nil, err
	}
	pt, err := aead.Open(nil, nonce, payload, nil)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt: %w", err)
	}
	return authType, pt, nil
}

// Delete removes a secret by secretRef. Missing rows are not an error.
func (k *Keystore) Delete(ctx context.Context, secretRef string) error {
	_, err := k.db.ExecContext(ctx, `DELETE FROM secrets WHERE secret_ref = ?`, secretRef)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}

// List returns all secret metadata (no ciphertext) ordered newest first.
func (k *Keystore) List(ctx context.Context) ([]SecretMeta, error) {
	rows, err := k.db.QueryContext(ctx,
		`SELECT secret_ref, profile_id, auth_type, created_at FROM secrets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		var ts int64
		if err := rows.Scan(&m.SecretRef, &m.ProfileID, &m.AuthType, &ts); err != nil {
			return nil, err
		}
		m.CreatedAt = time.Unix(ts, 0).UTC()
		out = append(out, m)
	}
	return out, rows.Err()
}
