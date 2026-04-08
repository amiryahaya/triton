package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew_InvalidEncryptionKey_ReturnsError verifies that an invalid
// DataEncryptionKeyHex causes server.New to return an error instead of
// silently logging FATAL and continuing with encryption disabled. This
// closes the H1 finding from the Phase 3+4 review (silent data-at-rest
// downgrade when the operator provides a malformed key).
//
// The test passes a nil store because the key MUST be validated before
// the store type is inspected. That guarantees the error surfaces in
// every deployment — not only when a *PostgresStore happens to be in use.
func TestNew_InvalidEncryptionKey_ReturnsError(t *testing.T) {
	cfg := &Config{
		ListenAddr:           ":0",
		DataEncryptionKeyHex: "not-valid-hex-zzzz",
	}
	srv, err := New(cfg, nil)
	assert.Error(t, err, "New must reject invalid encryption keys")
	assert.Nil(t, srv, "New must not return a server on error")
}

// TestNew_ValidEncryptionKey_Succeeds verifies that a correctly-formatted
// 32-byte hex key is accepted. The store is nil because New should not
// touch it beyond the encryptor type-assertion.
func TestNew_ValidEncryptionKey_Succeeds(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":0",
		// 64 hex chars = 32 bytes = AES-256 key
		DataEncryptionKeyHex: "0011223344556677889900112233445566778899001122334455667788990011",
	}
	srv, err := New(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, srv)
}

// TestNew_NoEncryptionKey_Succeeds verifies the zero-value path (no key
// → no encryption) still works.
func TestNew_NoEncryptionKey_Succeeds(t *testing.T) {
	cfg := &Config{ListenAddr: ":0"}
	srv, err := New(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, srv)
}
