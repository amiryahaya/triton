// Package engine is the Onboarding Phase 2 engine-enrollment bounded
// context. It owns the per-org X.509 CA used to issue engine client
// certificates, the engines table (one row per enrolled engine), and
// the bundle/heartbeat lifecycle.
//
// All persisted CA private keys are encrypted with XChaCha20-Poly1305
// using a master key held in the server process (REPORT_SERVER_DATA_
// ENCRYPTION_KEY or a derivation thereof). The plaintext key never
// touches disk.
package engine

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// CA is a per-org signing authority. CACertPEM is the PEM-encoded
// self-signed CA certificate (P-256 ECDSA). CAKeyEncrypted is the
// XChaCha20-Poly1305 ciphertext of the PKCS#8-DER-encoded CA private
// key, with CAKeyNonce as the 24-byte nonce used to encrypt it.
type CA struct {
	CACertPEM      []byte
	CAKeyEncrypted []byte
	CAKeyNonce     []byte
}

// caValidity is the self-signed CA cert lifetime. Engines are issued
// short-lived leaves (see SignEngineCert), so the CA itself can live
// much longer; 10y matches typical internal-CA practice.
const caValidity = 10 * 365 * 24 * time.Hour

// engineCertValidity is the lifetime of an engine leaf certificate.
// Engines re-enroll on rotation; 1y is a comfortable manual-rotation
// cadence for the MVP.
const engineCertValidity = 365 * 24 * time.Hour

// GenerateCA mints a fresh P-256 ECDSA CA for an org and returns it
// with the private key encrypted under masterKey (which must be the
// 32 bytes XChaCha20-Poly1305 expects).
func GenerateCA(masterKey []byte) (*CA, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Triton Engine CA",
			Organization: []string{"Triton"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}

	enc, nonce, err := encryptWithMasterKey(masterKey, keyDER)
	if err != nil {
		return nil, fmt.Errorf("encrypt CA key: %w", err)
	}

	return &CA{
		CACertPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CAKeyEncrypted: enc,
		CAKeyNonce:     nonce,
	}, nil
}

// SignEngineCert issues an Ed25519 engine leaf certificate signed by
// this CA. label is used as the cert CommonName so operators can match
// audit-log entries to the human-friendly engine label. pubKey is the
// engine-generated public key whose corresponding private key never
// leaves the engine.
//
// masterKey must be the same key used to encrypt the CA at
// GenerateCA time.
func (c *CA) SignEngineCert(masterKey []byte, label string, pubKey ed25519.PublicKey) ([]byte, error) {
	if c == nil {
		return nil, errors.New("nil CA")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(pubKey))
	}

	caCert, caKey, err := c.parseAndDecrypt(masterKey)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate engine serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   label,
			Organization: []string{"Triton Engine"},
		},
		NotBefore:   time.Now().Add(-1 * time.Minute),
		NotAfter:    time.Now().Add(engineCertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, pubKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign engine cert: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// parseAndDecrypt loads the CA cert and decrypts the CA private key.
func (c *CA) parseAndDecrypt(masterKey []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(c.CACertPEM)
	if block == nil {
		return nil, nil, errors.New("CA cert PEM is invalid")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyDER, err := decryptWithMasterKey(masterKey, c.CAKeyEncrypted, c.CAKeyNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt CA key: %w", err)
	}

	rawKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	caKey, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not ECDSA: %T", rawKey)
	}
	return caCert, caKey, nil
}

// encryptWithMasterKey wraps plaintext with XChaCha20-Poly1305. The
// 24-byte nonce is generated randomly and returned alongside the
// ciphertext for storage.
func encryptWithMasterKey(masterKey, plaintext []byte) (ciphertext, nonce []byte, err error) {
	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("init XChaCha20-Poly1305: %w", err)
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// decryptWithMasterKey is the inverse of encryptWithMasterKey. Returns
// an error (not silent corruption) if the master key is wrong, the
// nonce is tampered, or the ciphertext is truncated.
func decryptWithMasterKey(masterKey, ciphertext, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, fmt.Errorf("init XChaCha20-Poly1305: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: %d (want %d)", len(nonce), aead.NonceSize())
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
