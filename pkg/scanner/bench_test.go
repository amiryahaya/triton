package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// BenchmarkCertificateScan measures certificate scanning throughput.
func BenchmarkCertificateScan(b *testing.B) {
	tmpDir := b.TempDir()

	// Generate 10 PEM certificates for realistic workload
	for i := 0; i < 10; i++ {
		writeBenchCert(b, tmpDir, i)
	}

	cfg := &config.Config{MaxFileSize: 10 * 1024 * 1024}
	m := NewCertificateModule(cfg)
	target := model.ScanTarget{
		Type:  model.TargetFilesystem,
		Value: tmpDir,
		Depth: -1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings := make(chan *model.Finding, 100)
		go func() {
			for range findings {
			}
		}()
		m.Scan(context.Background(), target, findings)
	}
}

// BenchmarkKeyScan measures key scanning throughput.
func BenchmarkKeyScan(b *testing.B) {
	tmpDir := b.TempDir()

	// Generate PEM private keys
	for i := 0; i < 10; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			b.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		os.WriteFile(filepath.Join(tmpDir, "key-"+string(rune('a'+i))+".pem"), keyPEM, 0600)
	}

	cfg := &config.Config{MaxFileSize: 10 * 1024 * 1024}
	m := NewKeyModule(cfg)
	target := model.ScanTarget{
		Type:  model.TargetFilesystem,
		Value: tmpDir,
		Depth: -1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings := make(chan *model.Finding, 100)
		go func() {
			for range findings {
			}
		}()
		m.Scan(context.Background(), target, findings)
	}
}

// BenchmarkWalker measures filesystem traversal speed.
func BenchmarkWalker(b *testing.B) {
	tmpDir := b.TempDir()

	// Create a directory tree with 100 files across 10 subdirectories
	for d := 0; d < 10; d++ {
		dir := filepath.Join(tmpDir, "dir"+string(rune('0'+d)))
		os.MkdirAll(dir, 0755)
		for f := 0; f < 10; f++ {
			os.WriteFile(filepath.Join(dir, "file"+string(rune('0'+f))+".pem"), []byte("data"), 0644)
		}
	}

	cfg := &config.Config{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		walkTarget(walkerConfig{
			target: model.ScanTarget{
				Type:  model.TargetFilesystem,
				Value: tmpDir,
				Depth: -1,
			},
			config:      cfg,
			matchFile:   func(path string) bool { return filepath.Ext(path) == ".pem" },
			processFile: func(path string) error { return nil },
		})
	}
}

func writeBenchCert(b *testing.B, dir string, idx int) {
	b.Helper()

	var (
		certPEM []byte
	)

	if idx%2 == 0 {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			b.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(idx + 1)),
			Subject:      pkix.Name{CommonName: "bench-cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			b.Fatal(err)
		}
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(idx + 1)),
			Subject:      pkix.Name{CommonName: "bench-cert-ec"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			b.Fatal(err)
		}
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	name := filepath.Join(dir, "cert-"+string(rune('a'+idx))+".pem")
	if err := os.WriteFile(name, certPEM, 0644); err != nil {
		b.Fatal(err)
	}
}
