package tpmfs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadEKCert_ParsesRSACert(t *testing.T) {
	// Generate a throwaway self-signed RSA-2048 cert and write DER to a tempdir.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ek"},
		Issuer:       pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "endorsement_key_cert")
	if err := os.WriteFile(p, der, 0o644); err != nil {
		t.Fatal(err)
	}

	ek, err := ReadEKCert(p)
	if err != nil {
		t.Fatalf("ReadEKCert: %v", err)
	}
	if ek == nil {
		t.Fatal("nil EK cert returned")
		return
	}
	if ek.Algorithm != "RSA" {
		t.Errorf("Algorithm = %q, want RSA", ek.Algorithm)
	}
	if ek.KeySize != 2048 {
		t.Errorf("KeySize = %d, want 2048", ek.KeySize)
	}
	if ek.Subject == "" {
		t.Error("Subject empty")
	}
}

func TestReadEKCert_MissingFileReturnsNilNoError(t *testing.T) {
	ek, err := ReadEKCert("/does/not/exist")
	if err != nil {
		t.Errorf("missing file should not error, got %v", err)
	}
	if ek != nil {
		t.Errorf("ek = %+v, want nil", ek)
	}
}

func TestReadEKCert_CorruptFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bogus")
	if err := os.WriteFile(p, []byte("not a DER cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ReadEKCert(p)
	if err == nil {
		t.Error("expected error on corrupt DER")
	}
}
