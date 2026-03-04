package scanner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCertPublicKeyInfo_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	algo, size := certPublicKeyInfo(cert)
	assert.Equal(t, "RSA-2048", algo)
	assert.Equal(t, 2048, size)
}

func TestCertPublicKeyInfo_ECDSA_P256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	algo, size := certPublicKeyInfo(cert)
	assert.Equal(t, "ECDSA-P256", algo)
	assert.Equal(t, 256, size)
}

func TestCertPublicKeyInfo_ECDSA_P384(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	algo, size := certPublicKeyInfo(cert)
	assert.Equal(t, "ECDSA-P384", algo)
	assert.Equal(t, 384, size)
}

func TestCertPublicKeyInfo_Ed25519(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{PublicKey: pub}
	algo, size := certPublicKeyInfo(cert)
	assert.Equal(t, "Ed25519", algo)
	assert.Equal(t, 256, size)
}

func TestCertPublicKeyInfo_UnknownKeyType(t *testing.T) {
	// Use a raw int as public key — simulates unknown key type
	cert := &x509.Certificate{
		PublicKey:          42,
		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
	}
	algo, size := certPublicKeyInfo(cert)
	assert.NotEmpty(t, algo)
	assert.Equal(t, 0, size)
}
