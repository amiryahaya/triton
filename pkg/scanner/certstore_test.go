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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestCertStoreModule_Name(t *testing.T) {
	m := NewCertStoreModule(nil)
	assert.Equal(t, "certstore", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestCertStoreModule_ParsePEMCerts_RSA(t *testing.T) {
	// Generate a self-signed RSA certificate
	pemData := generateCertStorePEM(t, "RSA", 2048)

	m := NewCertStoreModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)

	err := m.parsePEMCerts(context.Background(), pemData, "test", "OS certificate store", findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	require.Len(t, results, 1)
	assert.Equal(t, "certstore", results[0].Module)
	assert.Equal(t, 2, results[0].Category)
	assert.Equal(t, "RSA-2048", results[0].CryptoAsset.Algorithm)
	assert.Equal(t, 2048, results[0].CryptoAsset.KeySize)
}

func TestCertStoreModule_ParsePEMCerts_ECDSA(t *testing.T) {
	pemData := generateCertStorePEM(t, "ECDSA", 256)

	m := NewCertStoreModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)

	err := m.parsePEMCerts(context.Background(), pemData, "test", "OS certificate store", findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	require.Len(t, results, 1)
	assert.Equal(t, "ECDSA-P256", results[0].CryptoAsset.Algorithm)
	assert.Equal(t, 256, results[0].CryptoAsset.KeySize)
}

func TestCertStoreModule_ParsePEMCerts_Ed25519(t *testing.T) {
	pemData := generateCertStorePEM(t, "Ed25519", 0)

	m := NewCertStoreModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)

	err := m.parsePEMCerts(context.Background(), pemData, "test", "OS certificate store", findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	require.Len(t, results, 1)
	assert.Equal(t, "Ed25519", results[0].CryptoAsset.Algorithm)
	assert.Equal(t, 256, results[0].CryptoAsset.KeySize)
}

func TestCertStoreModule_ParsePEMCerts_Multiple(t *testing.T) {
	cert1 := generateCertStorePEM(t, "RSA", 2048)
	cert2 := generateCertStorePEM(t, "ECDSA", 384)
	combined := append(cert1, cert2...)

	m := NewCertStoreModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)

	err := m.parsePEMCerts(context.Background(), combined, "test", "OS certificate store", findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	assert.Len(t, results, 2)
}

func TestCertStoreModule_ParsePEMCerts_Empty(t *testing.T) {
	m := NewCertStoreModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)

	err := m.parsePEMCerts(context.Background(), []byte("not a pem"), "test", "OS certificate store", findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	assert.Empty(t, results)
}

func TestCertStoreModule_ContextCancellation(t *testing.T) {
	pemData := generateCertStorePEM(t, "RSA", 2048)

	m := NewCertStoreModule(&scannerconfig.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	findings := make(chan *model.Finding, 50)
	err := m.parsePEMCerts(ctx, pemData, "test", "OS certificate store", findings)
	close(findings)

	assert.ErrorIs(t, err, context.Canceled)
}

func TestCertKeyInfo(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string
		keySize  int
		wantAlgo string
		wantSize int
	}{
		{"RSA-2048", "RSA", 2048, "RSA-2048", 2048},
		{"RSA-4096", "RSA", 4096, "RSA-4096", 4096},
		{"ECDSA-P256", "ECDSA", 256, "ECDSA-P256", 256},
		{"ECDSA-P384", "ECDSA", 384, "ECDSA-P384", 384},
		{"Ed25519", "Ed25519", 0, "Ed25519", 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := generateCertStoreObj(t, tt.keyType, tt.keySize)
			algo, size := certKeyInfo(cert)
			assert.Equal(t, tt.wantAlgo, algo)
			assert.Equal(t, tt.wantSize, size)
		})
	}
}

func TestCertStoreModule_Scan_Integration(t *testing.T) {
	// Integration test: runs the real OS cert store scan.
	// Non-fatal if OS store is inaccessible (CI, sandboxed env).
	//
	// Bound the overall scan at 90s via context deadline. On
	// CI runners with multiple JDKs, the Java cacerts discovery
	// may invoke keytool several times; without this bound a
	// single wedged keytool subprocess would stall the entire
	// pkg/scanner test run against the 10-minute Go test
	// timeout (observed in PR #12 first CI run).
	m := NewCertStoreModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 500)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: "/"}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	err := m.Scan(ctx, target, findings)
	close(findings)

	// Scan should not error (returns nil even if store inaccessible)
	assert.NoError(t, err)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	if len(results) == 0 {
		t.Skip("OS certificate store not accessible or empty — skipping integration assertions")
	}

	// Verify all findings have correct module and category.
	// Source.Path may now be either a synthetic "os:certstore:<os>"
	// label (for OS native stores) OR a real filesystem path to a
	// Java cacerts keystore we auto-discovered — both valid.
	// Function likewise can be "OS certificate store" or
	// "Java cacerts keystore".
	for _, f := range results {
		assert.Equal(t, "certstore", f.Module)
		assert.Equal(t, 2, f.Category)
		assert.NotEmpty(t, f.Source.Path, "source path should be set")
		require.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
		assert.NotEmpty(t, f.CryptoAsset.Function)
	}
}

func TestCertStoreModule_Scan_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	m := NewCertStoreModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: "/"}

	err := m.Scan(ctx, target, findings)
	close(findings)

	// Should return quickly (either nil or context.Canceled)
	if err != nil {
		assert.ErrorIs(t, err, context.Canceled)
	}

	// Should have few or no findings since context was cancelled
	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}
	// Just verify it didn't hang — count doesn't matter
	_ = results
}

func TestCertKeyInfo_DefaultBranch(t *testing.T) {
	// Create an ECDSA-P521 cert to test the P521 mapping branch
	cert := generateCertStoreObj(t, "ECDSA", 521)
	algo, size := certKeyInfo(cert)
	assert.Equal(t, "ECDSA-P521", algo)
	assert.Equal(t, 521, size)
}

func TestWindowsCertStore_AdditionalStores(t *testing.T) {
	// Generate a real ECDSA P-256 cert and base64-encode its DER for the mock.
	cert := generateCertStoreObj(t, "ECDSA", 256)
	import64 := encodeBase64DER(cert.Raw)

	// Track which PowerShell scripts were invoked.
	var mu sync.Mutex
	calledScripts := make([]string, 0, 5)

	mockRunner := func(_ context.Context, _ int64, name string, args ...string) ([]byte, error) {
		if name != "powershell" {
			return nil, fmt.Errorf("unexpected command: %s", name)
		}
		// Extract the script argument (last arg after "-Command").
		script := ""
		for i, a := range args {
			if a == "-Command" && i+1 < len(args) {
				script = args[i+1]
			}
		}
		mu.Lock()
		calledScripts = append(calledScripts, script)
		mu.Unlock()
		// Return one base64 DER line per call.
		return []byte(import64 + "\n"), nil
	}

	m := &CertStoreModule{
		config:           &scannerconfig.Config{},
		cmdRunnerLimited: mockRunner,
	}

	findings := make(chan *model.Finding, 50)
	err := m.scanWindowsCertStores(context.Background(), findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}

	// Expect exactly one finding per store (5 stores × 1 cert each).
	require.Len(t, results, 5)

	// Collect the source paths emitted.
	sourcePaths := make(map[string]bool)
	for _, f := range results {
		sourcePaths[f.Source.Path] = true
	}

	wantPaths := []string{
		`os:certstore:windows:LocalMachine\Root`,
		`os:certstore:windows:LocalMachine\CA`,
		`os:certstore:windows:LocalMachine\My`,
		`os:certstore:windows:CurrentUser\Root`,
		`os:certstore:windows:CurrentUser\My`,
	}
	for _, p := range wantPaths {
		assert.True(t, sourcePaths[p], "missing source path: %s", p)
	}

	// Verify PowerShell was called 5 times (once per store).
	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, calledScripts, 5)
}

// encodeBase64DER returns the standard base64 encoding of raw DER bytes.
func encodeBase64DER(der []byte) string {
	return base64.StdEncoding.EncodeToString(der)
}

// generateCertStorePEM creates a self-signed certificate in PEM format.
func generateCertStorePEM(t *testing.T, keyType string, keySize int) []byte {
	t.Helper()
	cert := generateCertStoreObj(t, keyType, keySize)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func generateCertStoreObj(t *testing.T, keyType string, keySize int) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}

	var privKey interface{}
	var pubKey interface{}

	switch keyType {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, keySize)
		require.NoError(t, err)
		privKey = key
		pubKey = &key.PublicKey
	case "ECDSA":
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKey = key
		pubKey = &key.PublicKey
	case "Ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		privKey = priv
		pubKey = pub
	default:
		t.Fatalf("unsupported key type: %s", keyType)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	return cert
}
