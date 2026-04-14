package netscan

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadCredentials(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("TRITON_SCANNER_CRED_KEY", hex.EncodeToString(key))

	path := filepath.Join(t.TempDir(), "credentials.yaml")
	creds := []Credential{
		{Name: "prod-ssh", Type: "ssh-key", Username: "triton-scanner", PrivateKeyPath: "/etc/triton/keys/prod"},
		{Name: "cisco-tacacs", Type: "ssh-password", Username: "readonly", Password: "s3cret"},
	}

	require.NoError(t, SaveCredentials(path, creds))

	store, err := LoadCredentials(path)
	require.NoError(t, err)

	c1 := store.Get("prod-ssh")
	require.NotNil(t, c1)
	assert.Equal(t, "triton-scanner", c1.Username)

	c2 := store.Get("cisco-tacacs")
	require.NotNil(t, c2)
	assert.Equal(t, "s3cret", c2.Password)

	all := store.All()
	assert.Len(t, all, 2)
}

func TestLoadCredentials_MissingKey(t *testing.T) {
	t.Setenv("TRITON_SCANNER_CRED_KEY", "")
	_, err := LoadCredentials("/nonexistent")
	assert.ErrorContains(t, err, "TRITON_SCANNER_CRED_KEY")
}

func TestLoadCredentials_WrongKey(t *testing.T) {
	// Save with one key
	key1 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
	}
	t.Setenv("TRITON_SCANNER_CRED_KEY", hex.EncodeToString(key1))
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	require.NoError(t, SaveCredentials(path, []Credential{{Name: "x", Type: "ssh-key"}}))

	// Load with a different key — should fail cleanly
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i) + 1
	}
	t.Setenv("TRITON_SCANNER_CRED_KEY", hex.EncodeToString(key2))
	_, err := LoadCredentials(path)
	assert.Error(t, err)
}
