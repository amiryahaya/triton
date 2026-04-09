package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Encryptor wraps a scan_data payload in an AES-256-GCM envelope for
// at-rest encryption in the scans.result_json column.
//
// Phase 2.7 of the multi-tenant rework. Optional — a nil *Encryptor
// (SetEncryptor never called) means the store stores plain JSON as
// before. Enabling encryption on an existing database works forward-
// compatibly: new writes are encrypted, old rows remain plain JSON,
// and the decrypt path detects each row's format.
//
// Disabling encryption after rows have been encrypted is a ONE-WAY
// door — without the key, the encrypted rows are unreadable. Don't
// rotate keys without migrating rows first.
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor parses a hex-encoded 32-byte key into an AES-256-GCM
// encryptor. Empty keyHex returns (nil, nil) — callers should treat
// a nil Encryptor as "encryption disabled".
func NewEncryptor(keyHex string) (*Encryptor, error) {
	if keyHex == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding encryption key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes (%d hex chars); got %d", 64, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM mode: %w", err)
	}
	return &Encryptor{aead: aead}, nil
}

// encryptedEnvelope is the JSON shape of an encrypted row. Exists as
// a discriminator: rows whose JSON has the "enc_v1" top-level key are
// treated as encrypted; anything else is plain legacy JSON.
type encryptedEnvelope struct {
	EncV1 string `json:"enc_v1"`
}

// Encrypt wraps a plain JSON payload in an encrypted envelope. The
// output is itself valid JSON that can be stored in a JSONB column:
//
//	{"enc_v1": "<base64url(nonce||ciphertext||tag)>"}
//
// A fresh random nonce is generated for every call. The AEAD tag is
// appended to the ciphertext by the cipher.AEAD interface.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext := e.aead.Seal(nil, nonce, plaintext, nil)

	// Pack nonce||ciphertext into one base64url blob
	packed := make([]byte, 0, len(nonce)+len(ciphertext))
	packed = append(packed, nonce...)
	packed = append(packed, ciphertext...)

	envelope := encryptedEnvelope{
		EncV1: base64.RawURLEncoding.EncodeToString(packed),
	}
	return json.Marshal(envelope)
}

// Decrypt unwraps an encrypted envelope and returns the plain JSON
// payload. If the input is NOT an encrypted envelope (no "enc_v1"
// key), Decrypt returns it as-is — this is the migration path for
// rows written before encryption was enabled.
func (e *Encryptor) Decrypt(stored []byte) ([]byte, error) {
	// Try to parse as envelope. If it's not one, pass through.
	var envelope encryptedEnvelope
	if err := json.Unmarshal(stored, &envelope); err != nil || envelope.EncV1 == "" {
		return stored, nil // legacy plain JSON
	}

	packed, err := base64.RawURLEncoding.DecodeString(envelope.EncV1)
	if err != nil {
		return nil, fmt.Errorf("decoding envelope base64: %w", err)
	}
	nonceSize := e.aead.NonceSize()
	if len(packed) < nonceSize {
		return nil, errors.New("encrypted envelope too short — truncated or corrupt")
	}
	nonce, ciphertext := packed[:nonceSize], packed[nonceSize:]

	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting envelope: %w", err)
	}
	return plaintext, nil
}
