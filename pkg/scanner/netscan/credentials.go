package netscan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Credential represents one authentication bundle.
type Credential struct {
	Name           string `yaml:"name"`
	Type           string `yaml:"type"` // ssh-key | ssh-password | enable-password
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	PrivateKeyPath string `yaml:"private_key_path"`
	Passphrase     string `yaml:"passphrase"`
}

// credentialsFile is the logical (decrypted) on-disk shape.
type credentialsFile struct {
	Version     int          `yaml:"version"`
	Credentials []Credential `yaml:"credentials"`
}

// CredentialStore holds decrypted credentials in memory.
type CredentialStore struct {
	creds map[string]*Credential
}

// LoadCredentials reads an encrypted YAML file and decrypts with
// TRITON_SCANNER_CRED_KEY (hex-encoded 32 bytes).
func LoadCredentials(path string) (*CredentialStore, error) {
	key, err := loadKey()
	if err != nil {
		return nil, err
	}

	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials %s: %w", path, err)
	}
	plaintext, err := decryptAES256GCM(key, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt credentials: %w", err)
	}

	var doc credentialsFile
	if err := yaml.Unmarshal(plaintext, &doc); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}

	store := &CredentialStore{creds: make(map[string]*Credential)}
	for i := range doc.Credentials {
		c := &doc.Credentials[i]
		if c.Name == "" {
			return nil, fmt.Errorf("credential %d: name is required", i)
		}
		if _, exists := store.creds[c.Name]; exists {
			return nil, fmt.Errorf("duplicate credential name: %s", c.Name)
		}
		store.creds[c.Name] = c
	}
	return store, nil
}

// Get returns the credential by name, or nil if not found.
func (s *CredentialStore) Get(name string) *Credential {
	return s.creds[name]
}

// All returns a copy of all stored credentials. Used by the CLI for
// list/add/rotate/delete operations.
func (s *CredentialStore) All() []Credential {
	out := make([]Credential, 0, len(s.creds))
	for _, c := range s.creds {
		out = append(out, *c)
	}
	return out
}

// SaveCredentials encrypts and writes the credential store to path.
func SaveCredentials(path string, creds []Credential) error {
	key, err := loadKey()
	if err != nil {
		return err
	}

	doc := credentialsFile{Version: 1, Credentials: creds}
	plaintext, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	encrypted, err := encryptAES256GCM(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}
	return os.WriteFile(path, encrypted, 0o600)
}

// loadKey reads TRITON_SCANNER_CRED_KEY and returns 32 raw bytes.
func loadKey() ([]byte, error) {
	keyHex := os.Getenv("TRITON_SCANNER_CRED_KEY")
	if keyHex == "" {
		return nil, fmt.Errorf("TRITON_SCANNER_CRED_KEY env var is required")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("TRITON_SCANNER_CRED_KEY must be 32 hex bytes (64 chars)")
	}
	return key, nil
}

// encryptAES256GCM produces base64(nonce || ciphertext || tag).
func encryptAES256GCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	raw := make([]byte, 0, len(nonce)+len(ct))
	raw = append(raw, nonce...)
	raw = append(raw, ct...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	return encoded, nil
}

// decryptAES256GCM reverses encryptAES256GCM.
func decryptAES256GCM(key, encoded []byte) ([]byte, error) {
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(raw, encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	raw = raw[:n]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}
