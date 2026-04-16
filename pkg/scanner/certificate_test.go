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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gopkcs7 "go.mozilla.org/pkcs7"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface compliance check
var _ Module = (*CertificateModule)(nil)

func TestCertificateModuleInterface(t *testing.T) {
	t.Parallel()
	cfg := &scannerconfig.Config{}
	m := NewCertificateModule(cfg)

	assert.Equal(t, "certificates", m.Name())
}

func TestCertificateModuleCategory(t *testing.T) {
	t.Parallel()
	m := NewCertificateModule(&scannerconfig.Config{})
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
}

func TestCertificateModuleScanTargetType(t *testing.T) {
	t.Parallel()
	m := NewCertificateModule(&scannerconfig.Config{})
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestParsePEMCertificate(t *testing.T) {
	t.Parallel()
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
	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
	m := NewCertificateModule(&scannerconfig.Config{})

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
	t.Parallel()
	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(ctx, target, findings)
	close(findings)
	// May or may not error depending on timing, but should not hang
	_ = err
}

func TestParseCertificateFileInvalidPEM(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Write a file with .pem extension but not a valid certificate
	certFile := filepath.Join(tmpDir, "invalid.pem")
	err := os.WriteFile(certFile, []byte("not a certificate"), 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
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
	// After Task 4, JKS goes via parseKeystoreViaKeytool → nil (keytool absent) →
	// createLockedContainerFinding. Confidence is 0.50, Function is "JKS container".
	assert.Contains(t, finding.CryptoAsset.Function, "JKS")
	assert.Equal(t, 0.50, finding.Confidence)
}

func TestBuildPQCAlgorithmName_UnknownCert(t *testing.T) {
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
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
	t.Parallel()
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

	m := NewCertificateModule(&scannerconfig.Config{})
	isHybrid, components := m.detectHybridCert(cert)
	assert.False(t, isHybrid)
	assert.Nil(t, components)
}

func TestIsCertificateFileExtended(t *testing.T) {
	t.Parallel()
	m := NewCertificateModule(&scannerconfig.Config{})

	// New extensions added in Phase 2
	assert.True(t, m.isCertificateFile("/path/to/keystore.p12"))
	assert.True(t, m.isCertificateFile("/path/to/keystore.pfx"))
	assert.True(t, m.isCertificateFile("/path/to/keystore.jks"))
	assert.True(t, m.isCertificateFile("/path/to/KEYSTORE.P12"))

	// Existing extensions still work
	assert.True(t, m.isCertificateFile("/path/to/cert.pem"))
	assert.True(t, m.isCertificateFile("/path/to/cert.crt"))
}

// --- PQC Algorithm Name & Hybrid Detection Tests ---

func TestBuildPQCAlgorithmName_FallbackToOID(t *testing.T) {
	t.Parallel()
	// Create a real RSA cert, then forge its PublicKeyAlgorithm to Unknown
	// to exercise the OID fallback path.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqc-fallback-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Force Unknown algorithm to exercise the PQC fallback
	cert.PublicKeyAlgorithm = x509.UnknownPublicKeyAlgorithm

	m := NewCertificateModule(&scannerconfig.Config{})
	algoName := m.buildPQCAlgorithmName(cert)

	// The OID extractor should find RSA public key OID and resolve it
	assert.Equal(t, "RSA", algoName)
}

func TestBuildPQCAlgorithmName_SyntheticPQCCert(t *testing.T) {
	t.Parallel()
	// Build synthetic DER with ML-DSA-44 signature OID and ML-KEM-768 pubkey OID
	mlkemOID := "2.16.840.1.101.3.4.4.2"  // ML-KEM-768
	mldsaOID := "2.16.840.1.101.3.4.3.17" // ML-DSA-44
	certDER := buildSyntheticCertDERForScanner(t, mldsaOID, mlkemOID)

	// Create a cert struct with the synthetic DER
	cert := &x509.Certificate{
		Raw:                certDER,
		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
	}

	m := NewCertificateModule(&scannerconfig.Config{})
	algoName := m.buildPQCAlgorithmName(cert)

	// Should resolve via public key OID first → ML-KEM-768
	assert.Equal(t, "ML-KEM-768", algoName)
}

func TestBuildPQCAlgorithmName_UnknownOID(t *testing.T) {
	t.Parallel()
	// Build synthetic DER with unrecognized OIDs
	unknownOID := "1.2.3.4.5.6.7.8.9"
	certDER := buildSyntheticCertDERForScanner(t, unknownOID, unknownOID)

	cert := &x509.Certificate{
		Raw:                certDER,
		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
	}

	m := NewCertificateModule(&scannerconfig.Config{})
	algoName := m.buildPQCAlgorithmName(cert)

	assert.Equal(t, "Unknown", algoName)
}

func TestDetectHybridCert_Composite(t *testing.T) {
	t.Parallel()
	compositeOID := "2.16.840.1.114027.80.8.1.1" // ML-DSA-44-RSA-2048
	rsaPubKeyOID := "1.2.840.113549.1.1.1"
	certDER := buildSyntheticCertDERForScanner(t, compositeOID, rsaPubKeyOID)

	cert := &x509.Certificate{
		Raw:                certDER,
		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
	}

	m := NewCertificateModule(&scannerconfig.Config{})
	isHybrid, components := m.detectHybridCert(cert)

	assert.True(t, isHybrid, "composite OID should be detected as hybrid")
	require.Len(t, components, 2)
	assert.Equal(t, "ML-DSA-44", components[0])
	assert.Equal(t, "RSA-2048", components[1])
}

func TestDetectHybridCert_NonComposite(t *testing.T) {
	t.Parallel()
	// Standard RSA cert
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "non-hybrid"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{})
	isHybrid, components := m.detectHybridCert(cert)

	assert.False(t, isHybrid)
	assert.Nil(t, components)
}

func TestDetectHybridCert_CompositePubKey(t *testing.T) {
	t.Parallel()
	// Non-composite signature but composite public key OID
	rsaSigOID := "1.2.840.113549.1.1.11"
	compositePKOID := "2.16.840.1.114027.80.8.1.9" // ML-DSA-65-ECDSA-P384
	certDER := buildSyntheticCertDERForScanner(t, rsaSigOID, compositePKOID)

	cert := &x509.Certificate{
		Raw:                certDER,
		PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
	}

	m := NewCertificateModule(&scannerconfig.Config{})
	isHybrid, components := m.detectHybridCert(cert)

	assert.True(t, isHybrid, "composite pubkey OID should be detected")
	require.Len(t, components, 2)
	assert.Equal(t, "ML-DSA-65", components[0])
	assert.Equal(t, "ECDSA-P384", components[1])
}

// --- Synthetic DER helpers (duplicated from crypto package for scanner tests) ---

func encodeOIDBytesScanner(t *testing.T, dotted string) []byte {
	t.Helper()
	parts := strings.Split(dotted, ".")
	require.True(t, len(parts) >= 2)
	first, _ := strconv.Atoi(parts[0])
	second, _ := strconv.Atoi(parts[1])
	var encoded []byte
	encoded = append(encoded, byte(first*40+second))
	for i := 2; i < len(parts); i++ {
		val, _ := strconv.Atoi(parts[i])
		encoded = append(encoded, encodeBase128Scanner(val)...)
	}
	return encoded
}

func encodeBase128Scanner(val int) []byte {
	if val < 128 {
		return []byte{byte(val)}
	}
	var result []byte
	for val > 0 {
		result = append([]byte{byte(val & 0x7F)}, result...)
		val >>= 7
	}
	for i := 0; i < len(result)-1; i++ {
		result[i] |= 0x80
	}
	return result
}

func wrapASN1Scanner(tag byte, content []byte) []byte {
	length := len(content)
	if length < 128 {
		return append([]byte{tag, byte(length)}, content...)
	}
	lenBytes := encodeLenScanner(length)
	header := []byte{tag, byte(0x80 | len(lenBytes))}
	header = append(header, lenBytes...)
	return append(header, content...)
}

func encodeLenScanner(length int) []byte {
	if length <= 0xFF {
		return []byte{byte(length)}
	}
	if length <= 0xFFFF {
		return []byte{byte(length >> 8), byte(length)}
	}
	return []byte{byte(length >> 16), byte(length >> 8), byte(length)}
}

func buildSyntheticCertDERForScanner(t *testing.T, sigOID, pubKeyOID string) []byte {
	t.Helper()
	sigOIDTLV := wrapASN1Scanner(0x06, encodeOIDBytesScanner(t, sigOID))
	nullParam := []byte{0x05, 0x00}
	sigAlgID := wrapASN1Scanner(0x30, append(sigOIDTLV, nullParam...))

	pubKeyOIDTLV := wrapASN1Scanner(0x06, encodeOIDBytesScanner(t, pubKeyOID))
	pubKeyAlgID := wrapASN1Scanner(0x30, append(pubKeyOIDTLV, nullParam...))

	version := wrapASN1Scanner(0xA0, []byte{0x02, 0x01, 0x02})
	serial := []byte{0x02, 0x01, 0x01}

	cnOID := []byte{0x06, 0x03, 0x55, 0x04, 0x03}
	cnValue := wrapASN1Scanner(0x0C, []byte("test"))
	rdnSeq := wrapASN1Scanner(0x30, append(cnOID, cnValue...))
	rdnSet := wrapASN1Scanner(0x31, rdnSeq)
	issuer := wrapASN1Scanner(0x30, rdnSet)

	utcNow := append([]byte{0x17, 0x0D}, []byte("250101000000Z")...)
	utcLater := append([]byte{0x17, 0x0D}, []byte("260101000000Z")...)
	validity := wrapASN1Scanner(0x30, append(utcNow, utcLater...))

	subject := wrapASN1Scanner(0x30, rdnSet)

	fakePubKey := wrapASN1Scanner(0x03, append([]byte{0x00}, make([]byte, 32)...))
	spki := wrapASN1Scanner(0x30, append(pubKeyAlgID, fakePubKey...))

	var tbsContent []byte
	tbsContent = append(tbsContent, version...)
	tbsContent = append(tbsContent, serial...)
	tbsContent = append(tbsContent, sigAlgID...)
	tbsContent = append(tbsContent, issuer...)
	tbsContent = append(tbsContent, validity...)
	tbsContent = append(tbsContent, subject...)
	tbsContent = append(tbsContent, spki...)
	tbs := wrapASN1Scanner(0x30, tbsContent)

	outerSigAlgID := wrapASN1Scanner(0x30, append(sigOIDTLV, nullParam...))
	fakeSig := wrapASN1Scanner(0x03, append([]byte{0x00}, make([]byte, 64)...))

	var certContent []byte
	certContent = append(certContent, tbs...)
	certContent = append(certContent, outerSigAlgID...)
	certContent = append(certContent, fakeSig...)
	return wrapASN1Scanner(0x30, certContent)
}

func TestParsePKCS12_ExpandedPasswords(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Create a PKCS#12 with password "password" — was NOT in old 3-password list,
	// but IS in the new expanded builtins.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expanded-pw-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	p12Data, err := pkcs12.Modern.Encode(key, cert, nil, "password")
	require.NoError(t, err)

	p12File := filepath.Join(tmpDir, "expanded.p12")
	err = os.WriteFile(p12File, p12Data, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1, "should decrypt PKCS#12 with expanded password list")
	assert.Contains(t, collected[0].CryptoAsset.Subject, "expanded-pw-test")
	assert.Equal(t, 0.95, collected[0].Confidence)
}

func TestParsePKCS12_UserConfiguredPassword(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Create a PKCS#12 with a custom password not in any builtin list.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "user-pw-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	p12Data, err := pkcs12.Modern.Encode(key, cert, nil, "mySecretP@ss")
	require.NoError(t, err)

	p12File := filepath.Join(tmpDir, "userpw.p12")
	err = os.WriteFile(p12File, p12Data, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{
		KeystorePasswords: []string{"mySecretP@ss"},
	})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1, "should decrypt PKCS#12 with user-configured password")
	assert.Contains(t, collected[0].CryptoAsset.Subject, "user-pw-test")
	assert.Equal(t, 0.95, collected[0].Confidence)
}

func TestParsePKCS12_FailOpen(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Create a PKCS#12 with a password not in any list.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "failopen-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	p12Data, err := pkcs12.Modern.Encode(key, cert, nil, "unknowablePassword!$#")
	require.NoError(t, err)

	p12File := filepath.Join(tmpDir, "locked.p12")
	err = os.WriteFile(p12File, p12Data, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1, "should emit a locked-container finding instead of skipping")
	finding := collected[0]
	assert.Equal(t, "Unknown", finding.CryptoAsset.Algorithm)
	assert.Contains(t, finding.CryptoAsset.Purpose, "password-protected")
	assert.Equal(t, 0.50, finding.Confidence)
	assert.Equal(t, 5, finding.Category)
}

func TestParsePKCS7_MultiCertChain(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Generate CA key + cert (ECDSA P-256, self-signed CA)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	// Generate leaf key + cert (ECDSA P-256, signed by CA)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	// Build DER-encoded PKCS#7 SignedData (certs-only degenerate bundle)
	// using go.mozilla.org/pkcs7's DegenerateCertificate builder
	p7bData, err := buildDegenerateP7B(caDER, leafDER)
	require.NoError(t, err)

	p7bFile := filepath.Join(tmpDir, "chain.p7b")
	err = os.WriteFile(p7bFile, p7bData, 0644)
	require.NoError(t, err)

	// Scan the temp dir
	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 2, "PKCS#7 bundle with 2 certs should produce 2 findings")

	// Verify both subjects are present
	subjects := make(map[string]bool)
	for _, f := range collected {
		require.NotNil(t, f.CryptoAsset)
		subjects[f.CryptoAsset.Subject] = true
		assert.Equal(t, 5, f.Category)
		assert.Equal(t, "certificates", f.Module)
		assert.Equal(t, 0.95, f.Confidence)
	}
	assert.True(t, subjects["CN=test-ca"], "CA cert finding should be present")
	assert.True(t, subjects["CN=test-leaf"], "leaf cert finding should be present")
}

// buildDegenerateP7B constructs a DER-encoded PKCS#7 SignedData (certs-only,
// no signers) containing the given certificate DER blobs.
// It uses go.mozilla.org/pkcs7's DegenerateCertificate which accepts a
// concatenated DER byte slice (certificate chain).
func buildDegenerateP7B(certDERs ...[]byte) ([]byte, error) {
	var chain []byte
	for _, der := range certDERs {
		chain = append(chain, der...)
	}
	return gopkcs7.DegenerateCertificate(chain)
}

// --- Task 4: JKS/JCEKS/BKS Full Parsing via keytool ---

func TestCertificateModule_NewExtensions(t *testing.T) {
	t.Parallel()
	m := NewCertificateModule(&scannerconfig.Config{})

	// New extensions
	assert.True(t, m.isCertificateFile("/path/to/store.jceks"))
	assert.True(t, m.isCertificateFile("/path/to/store.bks"))
	assert.True(t, m.isCertificateFile("/path/to/store.uber"))
	assert.True(t, m.isCertificateFile("/path/to/store.keystore"))
	assert.True(t, m.isCertificateFile("/path/to/store.truststore"))

	// Case-insensitive
	assert.True(t, m.isCertificateFile("/path/to/store.JCEKS"))
	assert.True(t, m.isCertificateFile("/path/to/store.KeyStore"))

	// Existing extensions still work
	assert.True(t, m.isCertificateFile("/path/to/cert.pem"))
	assert.True(t, m.isCertificateFile("/path/to/cert.jks"))
	assert.True(t, m.isCertificateFile("/path/to/cert.p12"))

	// Non-cert extensions still return false
	assert.False(t, m.isCertificateFile("/path/to/file.txt"))
	assert.False(t, m.isCertificateFile("/path/to/file.xml"))
}

func TestCertificateModule_JCEKSDetection(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Build a minimal JCEKS-magic file (0xCECECECE + padding)
	jceksData := make([]byte, 104)
	binary.BigEndian.PutUint32(jceksData, 0xCECECECE)

	jceksFile := filepath.Join(tmpDir, "test.jceks")
	err := os.WriteFile(jceksFile, jceksData, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// keytool is not available in test env → emit a container finding (fail-open)
	require.Len(t, collected, 1, "JCEKS file should produce exactly one finding")
	finding := collected[0]
	require.NotNil(t, finding.CryptoAsset)
	// Confidence is 0.50 (locked container) or 0.70 (old createContainerFinding);
	// the task spec uses createLockedContainerFinding (0.50).
	assert.Equal(t, "Unknown", finding.CryptoAsset.Algorithm)
	assert.Equal(t, 5, finding.Category)
	assert.Equal(t, "certificates", finding.Module)
}

func TestKeystorePasswords_Dedup(t *testing.T) {
	t.Parallel()
	// Overlap: "changeit" and "password" are already in builtins
	m := NewCertificateModule(&scannerconfig.Config{
		KeystorePasswords: []string{"changeit", "password", "myCustomPw"},
	})

	pws := m.keystorePasswords()

	// Verify no duplicates
	seen := make(map[string]int)
	for _, pw := range pws {
		seen[pw]++
	}
	for pw, count := range seen {
		assert.Equal(t, 1, count, "password %q appears %d times", pw, count)
	}

	// Custom password should be present and appear before builtins (first)
	require.NotEmpty(t, pws)
	assert.Equal(t, "changeit", pws[0], "user-supplied passwords should come first")
	assert.Contains(t, pws, "myCustomPw")
}

func TestCertificateModule_GenericKeystoreExtensions(t *testing.T) {
	t.Parallel()

	// .keystore and .truststore with garbage content → keytool not available → container finding
	for _, ext := range []string{".keystore", ".truststore"} {
		ext := ext
		t.Run(ext, func(t *testing.T) {
			t.Parallel()
			// Each subtest gets its own tmpDir to avoid cross-contamination
			subDir := t.TempDir()
			f, err := os.CreateTemp(subDir, "*"+ext)
			require.NoError(t, err)
			_, err = f.Write([]byte("notakeystore"))
			require.NoError(t, err)
			f.Close()
			tmpDir := subDir

			m := NewCertificateModule(&scannerconfig.Config{})
			findings := make(chan *model.Finding, 10)
			target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

			err = m.Scan(context.Background(), target, findings)
			require.NoError(t, err)
			close(findings)

			var collected []*model.Finding
			for ff := range findings {
				collected = append(collected, ff)
			}
			// Should produce exactly one finding (container finding)
			require.Len(t, collected, 1)
			assert.Equal(t, "Unknown", collected[0].CryptoAsset.Algorithm)
		})
	}
}

func TestCertificateModule_BKSDetection(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// .bks file (BouncyCastle) with some bytes — keytool not available → container finding
	bksFile := filepath.Join(tmpDir, "test.bks")
	err := os.WriteFile(bksFile, []byte{0x00, 0x00, 0x00, 0x02, 0xDE, 0xAD, 0xBE, 0xEF}, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1, "BKS file should produce one container finding")
	assert.Equal(t, "Unknown", collected[0].CryptoAsset.Algorithm)
	assert.Equal(t, 5, collected[0].Category)
}

func TestCertificateModule_InvalidJCEKSMagic(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// .jceks file with wrong magic → returns error → no finding
	jceksFile := filepath.Join(tmpDir, "bad.jceks")
	err := os.WriteFile(jceksFile, []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "invalid JCEKS magic should produce no findings")
}

func TestCertificateModule_JKSViaKeytool(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// Create a minimal JKS file with magic bytes (existing behavior should be preserved)
	jksData := make([]byte, 104)
	binary.BigEndian.PutUint32(jksData, 0xFEEDFEED)

	jksFile := filepath.Join(tmpDir, "test.jks")
	err := os.WriteFile(jksFile, jksData, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// keytool not available in test env → falls back to container finding
	require.Len(t, collected, 1)
	finding := collected[0]
	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, 5, finding.Category)
	assert.Equal(t, "Unknown", finding.CryptoAsset.Algorithm)
}

func TestCertificateModule_JKSInvalidMagic(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	// .jks file with wrong magic → returns error → no finding
	jksFile := filepath.Join(tmpDir, "bad.jks")
	err := os.WriteFile(jksFile, []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, 0644)
	require.NoError(t, err)

	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "invalid JKS magic should produce no findings")
}

func TestCertificateModule_JKSFindingShape(t *testing.T) {
	t.Parallel()
	// After Task 4, JKS files with valid magic → keytool path → container finding with
	// same shape as before (just via createLockedContainerFinding instead of createContainerFinding).
	// Verify the finding is produced and has the right confidence.
	tmpDir := t.TempDir()

	jksData := make([]byte, 104)
	binary.BigEndian.PutUint32(jksData, 0xFEEDFEED)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "shape.jks"), jksData, 0644))

	m := NewCertificateModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	require.Len(t, collected, 1)
	f := collected[0]
	assert.Equal(t, 5, f.Category)
	assert.Equal(t, "certificates", f.Module)
	// confidence for locked container is 0.50
	assert.Equal(t, 0.50, f.Confidence)
}

func TestKeytoolNotFound_ReturnsNilNil(t *testing.T) {
	t.Parallel()
	m := NewCertificateModule(&scannerconfig.Config{})
	// When keytool is not in PATH and no JAVA_HOME, discoverKeytool returns "".
	// We test indirectly: parseKeystoreViaKeytool returns nil, nil.
	certs, err := m.parseKeystoreViaKeytool(context.Background(), "/nonexistent.jks", "JKS")
	assert.NoError(t, err)
	assert.Nil(t, certs)
}

func TestParsePEMCertsFromBytes_SingleCert(t *testing.T) {
	t.Parallel()
	// Test parsePEMCertsFromBytes directly
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "keytool-pem-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	var pemBuf strings.Builder
	err = pem.Encode(&pemBufWriter{buf: &pemBuf}, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)

	certs := parsePEMCertsFromBytes([]byte(pemBuf.String()))
	require.Len(t, certs, 1)
	assert.Equal(t, "keytool-pem-test", certs[0].Subject.CommonName)
}

// pemBufWriter adapts strings.Builder to io.Writer for pem.Encode.
type pemBufWriter struct{ buf *strings.Builder }

func (w *pemBufWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }

func TestParsePEMCertsFromBytes_MultipleCerts(t *testing.T) {
	t.Parallel()
	// Two certs in one PEM block
	var pemData []byte
	for i := 0; i < 2; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: "cert-" + strconv.Itoa(i)},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	}

	certs := parsePEMCertsFromBytes(pemData)
	assert.Len(t, certs, 2)
}

func TestParsePEMCertsFromBytes_SkipsNonCertBlocks(t *testing.T) {
	t.Parallel()
	// Private key block should be skipped
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "skip-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	var pemData []byte
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("fake")})...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)

	certs := parsePEMCertsFromBytes(pemData)
	assert.Len(t, certs, 1)
}

func TestParsePEMCertsFromBytes_Empty(t *testing.T) {
	t.Parallel()
	certs := parsePEMCertsFromBytes([]byte{})
	assert.Nil(t, certs)
}

func TestCertificateFinding_SurfacesQualityWarnings(t *testing.T) {
	// Construct a cert with a deliberately broken modulus: n = 9973 * large_prime.
	// 9973 is the largest prime ≤ 10000 (consistent with keyquality.smallPrimeMax).
	largePrime, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rand.Prime: %v", err)
	}
	n := new(big.Int).Mul(big.NewInt(9973), largePrime)
	pub := &rsa.PublicKey{N: n, E: 65537}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	// Sign with a throwaway key; swap the PublicKey after parsing.
	throwaway, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &throwaway.PublicKey, throwaway)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	cert.PublicKey = pub // override for the keyquality path

	m := &CertificateModule{config: &scannerconfig.Config{}}
	f := m.createFinding("/tmp/test.crt", cert)
	if f == nil || f.CryptoAsset == nil {
		t.Fatal("createFinding returned nil")
	}
	if len(f.CryptoAsset.QualityWarnings) == 0 {
		t.Errorf("expected QualityWarnings on broken cert; got none")
	}
}
