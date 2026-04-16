package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// compile-time interface check
var _ Module = (*LDIFModule)(nil)

// generateSelfSignedCertBase64 creates a self-signed ECDSA P-256 certificate
// and returns its DER encoding as a base64 string.
func generateSelfSignedCertBase64(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ldif-test-cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(certDER)
}

func TestLDIF_Name(t *testing.T) {
	t.Parallel()
	m := NewLDIFModule(&scannerconfig.Config{})
	assert.Equal(t, "ldif", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestLDIF_ParseSingleCert(t *testing.T) {
	t.Parallel()
	certB64 := generateSelfSignedCertBase64(t)

	ldifContent := "dn: cn=user1,dc=example,dc=com\n" +
		"objectClass: person\n" +
		"cn: user1\n" +
		"userCertificate:: " + certB64 + "\n"

	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "users.ldif"), []byte(ldifContent), 0o600))

	m := NewLDIFModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1)
	f := collected[0]
	assert.Equal(t, "ldif", f.Module)
	assert.Equal(t, 5, f.Category)
	assert.Equal(t, "file", f.Source.Type)
	assert.True(t, strings.HasSuffix(f.Source.Path, "users.ldif"))
	require.NotNil(t, f.CryptoAsset)
	assert.Contains(t, f.CryptoAsset.Subject, "ldif-test-cert")
	assert.Contains(t, f.Source.Evidence, "cn=user1")
}

func TestLDIF_FoldedLines(t *testing.T) {
	t.Parallel()
	certB64 := generateSelfSignedCertBase64(t)

	// RFC 2849 folded lines: continuation lines start with a single space.
	// Split certB64 into chunks of 60 characters.
	const chunkSize = 60
	var sb strings.Builder
	sb.WriteString("dn: cn=folded,dc=example,dc=com\n")
	sb.WriteString("userCertificate:: ")
	for i := 0; i < len(certB64); i += chunkSize {
		end := i + chunkSize
		if end > len(certB64) {
			end = len(certB64)
		}
		if i == 0 {
			sb.WriteString(certB64[i:end])
			sb.WriteString("\n")
		} else {
			sb.WriteString(" ")
			sb.WriteString(certB64[i:end])
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n")

	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "folded.ldif"), []byte(sb.String()), 0o600))

	m := NewLDIFModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1, "folded lines should be reassembled into one certificate")
	assert.Contains(t, collected[0].CryptoAsset.Subject, "ldif-test-cert")
}

func TestLDIF_NoCerts(t *testing.T) {
	t.Parallel()
	ldifContent := "dn: cn=user2,dc=example,dc=com\n" +
		"objectClass: person\n" +
		"cn: user2\n" +
		"sn: Smith\n"

	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "nocerts.ldif"), []byte(ldifContent), 0o600))

	m := NewLDIFModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.Empty(t, collected)
}

func TestLDIF_MalformedBase64(t *testing.T) {
	t.Parallel()
	ldifContent := "dn: cn=bad,dc=example,dc=com\n" +
		"userCertificate:: NOT_VALID_BASE64!!!\n"

	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "bad.ldif"), []byte(ldifContent), 0o600))

	m := NewLDIFModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	// Should not return an error (fail-open)
	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.Empty(t, collected, "malformed base64 should be silently skipped")
}

func TestLDIF_MultipleCertAttributes(t *testing.T) {
	t.Parallel()
	cert1B64 := generateSelfSignedCertBase64(t)
	cert2B64 := generateSelfSignedCertBase64(t)

	ldifContent := "dn: cn=multi,dc=example,dc=com\n" +
		"userCertificate:: " + cert1B64 + "\n" +
		"cACertificate:: " + cert2B64 + "\n"

	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "multi.ldif"), []byte(ldifContent), 0o600))

	m := NewLDIFModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.GreaterOrEqual(t, len(collected), 2, "should find at least 2 certificates (one per cert attribute)")
	for _, f := range collected {
		assert.Equal(t, "ldif", f.Module)
		assert.Equal(t, 5, f.Category)
	}
}
