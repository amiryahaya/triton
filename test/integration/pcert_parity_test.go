//go:build integration

package integration_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// generateECDSAP256SelfSigned creates a fresh ECDSA P-256 self-signed certificate,
// writing the PEM-encoded DER bytes to dst. Returns the PEM block bytes for reuse.
func generateECDSAP256SelfSigned(t *testing.T, cn string) (certPEM []byte, privKey *ecdsa.PrivateKey, certDER []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate ECDSA P-256 key")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "create self-signed certificate")

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, err, "PEM-encode certificate")

	return buf.Bytes(), key, der
}

// TestPCertParity_FullScan exercises all PCert-parity capabilities in a single
// end-to-end scan:
//
//   - Plain PEM cert (ECDSA P-256 self-signed)
//   - PKCS#12 encrypted with a password in the expanded builtin list ("password")
//   - Locked PKCS#12 whose password is not in any list → fail-open "Unknown" finding
//   - RFC 1423 encrypted private key → keys module detection
//   - JAR containing a PEM cert → archive module extraction
func TestPCertParity_FullScan(t *testing.T) {
	tmpDir := t.TempDir()

	// ── Fixture 1: plain PEM certificate ─────────────────────────────────────
	certPEM, ecKey, _ := generateECDSAP256SelfSigned(t, "pcert-parity-server")
	err := os.WriteFile(filepath.Join(tmpDir, "server.crt"), certPEM, 0644)
	require.NoError(t, err, "write server.crt")

	// ── Fixture 2: PKCS#12 with expanded password ("password" is in builtins) ─
	{
		cert, err2 := x509.ParseCertificate(certDERFromPEM(t, certPEM))
		require.NoError(t, err2, "parse cert from PEM")

		p12Data, err2 := pkcs12.Modern.Encode(ecKey, cert, nil, "password")
		require.NoError(t, err2, "encode PKCS#12 with password")

		err = os.WriteFile(filepath.Join(tmpDir, "expanded.p12"), p12Data, 0644)
		require.NoError(t, err, "write expanded.p12")
	}

	// ── Fixture 3: locked PKCS#12 (unknown password → fail-open) ────────────
	{
		lockedPEM, lockedKey, _ := generateECDSAP256SelfSigned(t, "pcert-parity-locked")
		lockedCert, err2 := x509.ParseCertificate(certDERFromPEM(t, lockedPEM))
		require.NoError(t, err2, "parse locked cert")

		lockedP12, err2 := pkcs12.Modern.Encode(lockedKey, lockedCert, nil, "impossiblePW!@#$")
		require.NoError(t, err2, "encode locked PKCS#12")

		err = os.WriteFile(filepath.Join(tmpDir, "locked.pfx"), lockedP12, 0644)
		require.NoError(t, err, "write locked.pfx")
	}

	// ── Fixture 4: RFC 1423 encrypted private key ────────────────────────────
	encryptedKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,AABBCCDD00112233AABBCCDD00112233

SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBmYWtlIGVuY3J5cHRlZCBrZXkgYm9keQ==
-----END RSA PRIVATE KEY-----
`)
	err = os.WriteFile(filepath.Join(tmpDir, "encrypted.key"), encryptedKey, 0600)
	require.NoError(t, err, "write encrypted.key")

	// ── Fixture 5: JAR (ZIP) containing a PEM cert ──────────────────────────
	{
		jarPath := filepath.Join(tmpDir, "lib.jar")
		f, err2 := os.Create(jarPath)
		require.NoError(t, err2, "create lib.jar")

		zw := zip.NewWriter(f)
		w, err2 := zw.Create("META-INF/cert.pem")
		require.NoError(t, err2, "create zip entry META-INF/cert.pem")

		_, err2 = w.Write(certPEM)
		require.NoError(t, err2, "write cert PEM into jar")

		require.NoError(t, zw.Close(), "close zip writer")
		require.NoError(t, f.Close(), "close jar file")
	}

	// ── Run the scanner engine ───────────────────────────────────────────────
	cfg := scannerconfig.Load("standard")
	cfg.Modules = []string{"certificates", "keys", "archive"}
	cfg.MaxDepth = 5
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: tmpDir, Depth: 5},
	}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	progressCh := make(chan scanner.Progress, 100)
	go func() {
		for range progressCh {
		} // drain
	}()

	result := eng.Scan(ctx, progressCh)
	require.NotNil(t, result, "scan result must not be nil")

	// ── Tally findings by fixture ─────────────────────────────────────────────
	var (
		fromServerCrt  int
		fromExpandedP12 int
		fromLockedPfx  int
		fromEncryptedKey int
		fromLibJar     int
	)

	for i := range result.Findings {
		f := &result.Findings[i]
		p := f.Source.Path

		switch {
		case strings.HasSuffix(p, "server.crt"):
			fromServerCrt++
		case strings.HasSuffix(p, "expanded.p12"):
			fromExpandedP12++
		case strings.HasSuffix(p, "locked.pfx"):
			fromLockedPfx++
		case strings.HasSuffix(p, "encrypted.key"):
			fromEncryptedKey++
		case strings.Contains(p, "lib.jar"):
			fromLibJar++
		}
	}

	// ── Assertions ────────────────────────────────────────────────────────────
	assert.Equal(t, 1, fromServerCrt, "server.crt: expected 1 finding from plain PEM cert")
	assert.Equal(t, 1, fromExpandedP12, "expanded.p12: expected 1 finding (expanded password list)")
	assert.Equal(t, 1, fromLockedPfx, "locked.pfx: expected 1 fail-open finding")
	assert.Equal(t, 1, fromEncryptedKey, "encrypted.key: expected 1 finding from encrypted key detection")
	assert.Equal(t, 1, fromLibJar, "lib.jar: expected 1 finding from archive extraction")

	// Verify the locked container emits an "Unknown" algorithm (fail-open sentinel).
	for i := range result.Findings {
		f := &result.Findings[i]
		if strings.HasSuffix(f.Source.Path, "locked.pfx") {
			assert.Equal(t, "Unknown", f.CryptoAsset.Algorithm,
				"locked.pfx finding should carry Algorithm=Unknown (fail-open)")
		}
	}

	assert.GreaterOrEqual(t, len(result.Findings), 5, "total findings should be at least 5")
}

// certDERFromPEM decodes the first CERTIFICATE block from the given PEM bytes.
func certDERFromPEM(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "certDERFromPEM: no PEM block found")
	return block.Bytes
}
