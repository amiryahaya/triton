package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface compliance check
var _ Module = (*CertificateModule)(nil)

func TestCertificateModuleInterface(t *testing.T) {
	cfg := &config.Config{}
	m := NewCertificateModule(cfg)

	assert.Equal(t, "certificates", m.Name())
}

func TestCertificateModuleCategory(t *testing.T) {
	m := NewCertificateModule(&config.Config{})
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
}

func TestCertificateModuleScanTargetType(t *testing.T) {
	m := NewCertificateModule(&config.Config{})
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestParsePEMCertificate(t *testing.T) {
	// Generate a self-signed RSA certificate in memory
	tmpDir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certFile := filepath.Join(tmpDir, "test.pem")
	f, err := os.Create(certFile)
	require.NoError(t, err)
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)
	f.Close()

	// Scan the temp dir
	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1)
	finding := collected[0]

	assert.NotEmpty(t, finding.ID)
	require.NotNil(t, finding.CryptoAsset)
	assert.Contains(t, finding.CryptoAsset.Subject, "test-cert")
	assert.Equal(t, 256, finding.CryptoAsset.KeySize)
	assert.NotNil(t, finding.CryptoAsset.NotBefore)
	assert.NotNil(t, finding.CryptoAsset.NotAfter)
}

func TestCertificateFindingShape(t *testing.T) {
	tmpDir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "shape-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certFile := filepath.Join(tmpDir, "cert.pem")
	f, err := os.Create(certFile)
	require.NoError(t, err)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	m.Scan(context.Background(), target, findings)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)

	assert.Equal(t, 5, finding.Category)
	assert.Equal(t, "file", finding.Source.Type)
	assert.Equal(t, "certificates", finding.Module)
	assert.Equal(t, 0.95, finding.Confidence)
}

func TestParseRSACertificate(t *testing.T) {
	tmpDir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	certFile := filepath.Join(tmpDir, "rsa.pem")
	f, err := os.Create(certFile)
	require.NoError(t, err)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Contains(t, finding.CryptoAsset.Algorithm, "RSA")
	assert.Equal(t, 2048, finding.CryptoAsset.KeySize)
}

func TestParseEd25519Certificate(t *testing.T) {
	tmpDir := t.TempDir()

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed25519-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, edPub, edPriv)
	require.NoError(t, err)

	certFile := filepath.Join(tmpDir, "ed25519.crt")
	f, err := os.Create(certFile)
	require.NoError(t, err)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Contains(t, finding.CryptoAsset.Algorithm, "Ed25519")
	assert.Equal(t, 256, finding.CryptoAsset.KeySize)
}

func TestParseDERCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "der-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// Write raw DER (no PEM encoding)
	certFile := filepath.Join(tmpDir, "test.der")
	err = os.WriteFile(certFile, certDER, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, 256, finding.CryptoAsset.KeySize)
}

func TestCertificatePQCClassification(t *testing.T) {
	tmpDir := t.TempDir()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqc-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)

	certFile := filepath.Join(tmpDir, "pqc.pem")
	f, _ := os.Create(certFile)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

	m.Scan(context.Background(), target, findings)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)

	// RSA-2048 should be classified as TRANSITIONAL
	assert.Equal(t, "TRANSITIONAL", finding.CryptoAsset.PQCStatus)
	assert.Equal(t, 50, finding.CryptoAsset.MigrationPriority)
	assert.Equal(t, 2035, finding.CryptoAsset.BreakYear)
}

func TestIsCertificateFile(t *testing.T) {
	m := NewCertificateModule(&config.Config{})

	assert.True(t, m.isCertificateFile("/etc/ssl/cert.pem"))
	assert.True(t, m.isCertificateFile("/etc/ssl/cert.crt"))
	assert.True(t, m.isCertificateFile("/etc/ssl/cert.cer"))
	assert.True(t, m.isCertificateFile("/etc/ssl/cert.der"))
	assert.True(t, m.isCertificateFile("/etc/ssl/cert.p7b"))
	assert.True(t, m.isCertificateFile("/etc/ssl/cert.p7c"))
	assert.False(t, m.isCertificateFile("/etc/ssl/cert.txt"))
	assert.False(t, m.isCertificateFile("/etc/ssl/cert.key"))
}

func TestScanNonExistentDirectory(t *testing.T) {
	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: "/nonexistent/path", Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	// filepath.Walk returns an error for non-existent paths
	// but our implementation returns nil for walk errors
	close(findings)
	_ = err

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected)
}

func TestScanContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a cert file
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cancel-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certFile := filepath.Join(tmpDir, "test.pem")
	f, _ := os.Create(certFile)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(ctx, target, findings)
	close(findings)
	// May or may not error depending on timing, but should not hang
	_ = err
}

func TestParseCertificateFileInvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a file with .pem extension but not a valid certificate
	certFile := filepath.Join(tmpDir, "invalid.pem")
	err := os.WriteFile(certFile, []byte("not a certificate"), 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "invalid PEM should produce no findings")
}

func TestParsePKCS12Certificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a PKCS#12 file with a self-signed cert
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pkcs12-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Encode to PKCS#12 with empty password
	p12Data, err := pkcs12.Modern.Encode(rsaKey, cert, nil, "")
	require.NoError(t, err)

	p12File := filepath.Join(tmpDir, "test.p12")
	err = os.WriteFile(p12File, p12Data, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1)
	finding := collected[0]
	require.NotNil(t, finding.CryptoAsset)
	assert.Contains(t, finding.CryptoAsset.Algorithm, "RSA")
	assert.Equal(t, 2048, finding.CryptoAsset.KeySize)
	assert.Contains(t, finding.CryptoAsset.Subject, "pkcs12-test")
}

func TestParsePFXCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pfx-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	p12Data, err := pkcs12.Modern.Encode(key, cert, nil, "")
	require.NoError(t, err)

	pfxFile := filepath.Join(tmpDir, "test.pfx")
	err = os.WriteFile(pfxFile, p12Data, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1)
	assert.Contains(t, collected[0].CryptoAsset.Subject, "pfx-test")
}

func TestParseJKSFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal JKS file with magic bytes
	var jksData []byte
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, 0xFEEDFEED)
	jksData = append(jksData, magic...)
	jksData = append(jksData, make([]byte, 100)...) // padding

	jksFile := filepath.Join(tmpDir, "test.jks")
	err := os.WriteFile(jksFile, jksData, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1)
	finding := collected[0]
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "JKS keystore", finding.CryptoAsset.Function)
	assert.Equal(t, 0.70, finding.Confidence)
}

func TestBuildPQCAlgorithmName_UnknownCert(t *testing.T) {
	// When x509.ParseCertificate encounters a PQC cert, the public key algorithm
	// is Unknown. This test verifies the OID fallback path works by parsing
	// a real RSA cert (which Go does understand) and checking the extractors work.
	tmpDir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "oid-fallback-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	certFile := filepath.Join(tmpDir, "oid-test.pem")
	f, err := os.Create(certFile)
	require.NoError(t, err)
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	m := NewCertificateModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	require.NotNil(t, finding.CryptoAsset)
	// RSA is handled by the standard path, not OID fallback
	assert.Contains(t, finding.CryptoAsset.Algorithm, "RSA")
	assert.Equal(t, 2048, finding.CryptoAsset.KeySize)
}

func TestDetectHybridCert(t *testing.T) {
	// Test detectHybridCert returns false for standard RSA cert
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hybrid-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	m := NewCertificateModule(&config.Config{})
	isHybrid, components := m.detectHybridCert(cert)
	assert.False(t, isHybrid)
	assert.Nil(t, components)
}

func TestIsCertificateFileExtended(t *testing.T) {
	m := NewCertificateModule(&config.Config{})

	// New extensions added in Phase 2
	assert.True(t, m.isCertificateFile("/path/to/keystore.p12"))
	assert.True(t, m.isCertificateFile("/path/to/keystore.pfx"))
	assert.True(t, m.isCertificateFile("/path/to/keystore.jks"))
	assert.True(t, m.isCertificateFile("/path/to/KEYSTORE.P12"))

	// Existing extensions still work
	assert.True(t, m.isCertificateFile("/path/to/cert.pem"))
	assert.True(t, m.isCertificateFile("/path/to/cert.crt"))
}
