package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// randomKeyHex generates a 32-byte hex-encoded key for tests.
func randomKeyHex(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return hex.EncodeToString(key)
}

// --- Construction ---

func TestNewEncryptor_EmptyKeyReturnsNil(t *testing.T) {
	enc, err := NewEncryptor("")
	require.NoError(t, err)
	assert.Nil(t, enc, "empty key must return nil encryptor")
}

func TestNewEncryptor_InvalidHexReturnsError(t *testing.T) {
	_, err := NewEncryptor("not-hex")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hex")
}

func TestNewEncryptor_WrongKeyLengthReturnsError(t *testing.T) {
	// 16 bytes instead of 32
	_, err := NewEncryptor(hex.EncodeToString(make([]byte, 16)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestNewEncryptor_ValidKey(t *testing.T) {
	enc, err := NewEncryptor(randomKeyHex(t))
	require.NoError(t, err)
	assert.NotNil(t, enc)
}

// --- Round-trip ---

func TestEncryptor_RoundTrip(t *testing.T) {
	enc, _ := NewEncryptor(randomKeyHex(t))

	plaintext := []byte(`{"id":"scan-123","findings":42,"org":"acme"}`)
	ciphertext, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	// Output must be valid JSON (it's going into a JSONB column)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(ciphertext, &envelope))
	assert.NotEmpty(t, envelope["enc_v1"])

	// Decrypt must recover the plaintext
	decrypted, err := enc.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptor_UniqueNoncePerEncryption(t *testing.T) {
	enc, _ := NewEncryptor(randomKeyHex(t))

	plaintext := []byte(`{"id":"same"}`)
	c1, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	c2, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	// Same plaintext → different ciphertexts because nonces are random
	assert.NotEqual(t, c1, c2,
		"encrypting the same plaintext twice must produce different ciphertexts")
}

// --- Backward-compat passthrough ---

func TestEncryptor_DecryptPlainJSONPassesThrough(t *testing.T) {
	enc, _ := NewEncryptor(randomKeyHex(t))

	// A row written before encryption was enabled — plain JSON, no envelope.
	plain := []byte(`{"id":"legacy-scan","tier":"pro"}`)
	out, err := enc.Decrypt(plain)
	require.NoError(t, err)
	assert.Equal(t, plain, out, "plain JSON must pass through Decrypt unchanged")
}

func TestEncryptor_DecryptNonEnvelopeJSONPassesThrough(t *testing.T) {
	enc, _ := NewEncryptor(randomKeyHex(t))

	// Valid JSON with no enc_v1 key — treated as plain legacy
	stored := []byte(`{"some_other_field":"value"}`)
	out, err := enc.Decrypt(stored)
	require.NoError(t, err)
	assert.Equal(t, stored, out)
}

// --- Tamper detection ---

func TestEncryptor_TamperedCiphertextFails(t *testing.T) {
	enc, _ := NewEncryptor(randomKeyHex(t))

	ciphertext, err := enc.Encrypt([]byte(`{"a":1}`))
	require.NoError(t, err)

	// Parse the envelope, flip one character in the base64 payload,
	// and re-pack. This guarantees we tamper with the ciphertext
	// rather than the envelope's JSON structure.
	var env encryptedEnvelope
	require.NoError(t, json.Unmarshal(ciphertext, &env))
	require.NotEmpty(t, env.EncV1)

	// Flip the middle character. Base64url alphabet is A-Z a-z 0-9 - _.
	// If the middle char is 'A', change to 'B'; otherwise subtract 1
	// from whatever it is (all changes stay in the valid alphabet).
	runes := []byte(env.EncV1)
	mid := len(runes) / 2
	if runes[mid] == 'A' {
		runes[mid] = 'B'
	} else if runes[mid] > 'A' {
		runes[mid]--
	} else {
		runes[mid]++
	}
	env.EncV1 = string(runes)
	tampered, err := json.Marshal(env)
	require.NoError(t, err)

	_, err = enc.Decrypt(tampered)
	require.Error(t, err, "tampered ciphertext must fail GCM authentication")
}

// --- Wrong key ---

func TestEncryptor_WrongKeyFails(t *testing.T) {
	enc1, _ := NewEncryptor(randomKeyHex(t))
	enc2, _ := NewEncryptor(randomKeyHex(t)) // different key

	ciphertext, err := enc1.Encrypt([]byte(`{"secret":"data"}`))
	require.NoError(t, err)

	_, err = enc2.Decrypt(ciphertext)
	require.Error(t, err, "decrypting with wrong key must fail authentication")
}

// --- Truncated envelope ---

func TestEncryptor_TruncatedEnvelopeFails(t *testing.T) {
	enc, _ := NewEncryptor(randomKeyHex(t))

	// Build an envelope with a too-short base64 payload (just the nonce,
	// no ciphertext + tag)
	shortEnv := []byte(`{"enc_v1":"` + "aaaaaaaaaaaa" + `"}`) // 12 chars → ~9 bytes after decode
	_, err := enc.Decrypt(shortEnv)
	// Either decode error or GCM Open failure — both are acceptable
	require.Error(t, err)
}
