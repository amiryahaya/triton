package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// testPEMCert is a real self-signed RSA-2048 certificate generated
// by `crypto/x509.CreateCertificate`. Used as a canned fixture for
// every parser path that needs a parseable cert.
const testPEMCert = `-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIBATANBgkqhkiG9w0BAQsFADAjMQ0wCwYDVQQKEwRUZXN0
MRIwEAYDVQQDEwlUZXN0IENlcnQwHhcNMjYwNDA5MTExNDQwWhcNMjcwNDA5MTEx
NDQwWjAjMQ0wCwYDVQQKEwRUZXN0MRIwEAYDVQQDEwlUZXN0IENlcnQwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCisR54U388LpFnMt4NBgnEV7g5gP1T
idv2g5A+/hAz1ytiFXKAkcBn4FXGljgLIogXE0gY55bFtQtjcCWYrhMOJZD+PpGS
8HKlL1YMZSG38FNo0QhY3vOg7VdYw5ScD0IEliUA/sKkoiyNIZpEl5SJSz3KqU6a
DovgP4HNsFBWv9Ipb41nrlM5UTqbimrXXk70M95QbxwsR5jOvKo0OiSSMUVN/QJQ
E2ON0zF6HCeNKaC1D1frZCtAGrbJTaPeA7JkccH3RfBsLkS7KkVXVtqe+2WEsLWm
+gagMUScVWcnSY8tDv1B4tRyfWmN431aDJTyN1J3/qe1+VQG003cFUi1AgMBAAGj
QjBAMA4GA1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRs
Fe+BzhNDBk0PcuZfB7ROBh0vJTANBgkqhkiG9w0BAQsFAAOCAQEAPdPabnqI6+Q3
qH+ZsaepIkvZIN+zAlwZK2HuyusVRhfPgLng9+2rfpBXVpUaHUNjQyeEm9DS5BOA
GETLiiuI2EzHGsBwTvMabl+uCqEOSXwLYYJrr/7ms0FH4KXMZ8W4ifWh1vfXqr4K
wxlHtvf857aP217PAyEWXXaPQGQZl+HB3A9lugyxuLXTeZObbUfDGB3eLxUrd4rF
ur4yS61ne9wgwteDYAQjkOy5bJqbv6wRbK0669NmeQf4QpclPS3sdAfzZlwtn3kj
hdVj1Z+zqamMxEfIc6GYiH46Zm82SO1fzDFD69IbkDZj0rjl2RBpb8ehvxKEPs9N
/SSLdtPFbw==
-----END CERTIFICATE-----`

// stubRunnerLimited returns a cmdRunnerLimitedFunc that ignores
// the byte limit and always produces the canned output. Used by
// certstore tests that exercise the Windows store + Java cacerts
// paths, both of which go through the bounded runner after the
// H2 review fix.
func stubRunnerLimited(output string, err error) cmdRunnerLimitedFunc {
	return func(_ context.Context, _ int64, _ string, _ ...string) ([]byte, error) {
		return []byte(output), err
	}
}

// --- Windows cert store ---

func TestWindowsCertStore_ParsesPowerShellBase64Output(t *testing.T) {
	// PowerShell `Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object { [Convert]::ToBase64String($_.RawData) }`
	// emits one base64-encoded DER per line. The module decodes each
	// line, wraps it in a PEM block, and feeds it into the existing
	// parsePEMCerts path.
	//
	// For the fixture we use a single PEM cert whose base64 body we
	// need to extract. Easier: reuse the testPEMCert's base64 chunk
	// directly (the body between BEGIN/END lines, newlines stripped)
	// as a stand-in for a single-line base64 output.
	b64 := strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(testPEMCert, "-----BEGIN CERTIFICATE-----", ""),
			"-----END CERTIFICATE-----", ""),
		"\n", "")

	m := NewCertStoreModule(&config.Config{})
	m.cmdRunnerLimited = stubRunnerLimited(b64+"\n", nil)

	findings := make(chan *model.Finding, 16)
	err := m.scanWindowsCertStore(context.Background(), findings)
	close(findings)
	require.NoError(t, err)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	require.NotEmpty(t, collected, "windows cert store scan produced zero findings")

	for _, f := range collected {
		require.NotNil(t, f.CryptoAsset)
		assert.Contains(t, f.CryptoAsset.Algorithm, "RSA")
		assert.Equal(t, 2048, f.CryptoAsset.KeySize)
		assert.Contains(t, f.Source.Path, "windows")
		assert.Equal(t, "certstore", f.Module)
	}
}

func TestWindowsCertStore_EmptyOutput(t *testing.T) {
	m := NewCertStoreModule(&config.Config{})
	m.cmdRunnerLimited = stubRunnerLimited("", nil)

	findings := make(chan *model.Finding, 8)
	err := m.scanWindowsCertStore(context.Background(), findings)
	close(findings)
	assert.NoError(t, err)
	assert.Empty(t, collectChan(findings))
}

func TestWindowsCertStore_RunnerError(t *testing.T) {
	m := NewCertStoreModule(&config.Config{})
	m.cmdRunnerLimited = stubRunnerLimited("", errors.New("powershell not found"))

	findings := make(chan *model.Finding, 8)
	// Errors must not propagate — a missing PowerShell should just
	// produce zero findings, not abort the whole scan.
	err := m.scanWindowsCertStore(context.Background(), findings)
	close(findings)
	assert.NoError(t, err)
	assert.Empty(t, collectChan(findings))
}

// --- Java cacerts ---

func TestJavaCacerts_ParsesKeytoolPEMOutput(t *testing.T) {
	// `keytool -list -rfc -keystore cacerts -storepass changeit`
	// emits headers plus one or more PEM-encoded certs. The parser
	// reuses parsePEMCerts which already scans any PEM-framed blob.
	keytoolOut := `Keystore type: JKS
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: verisignclass1ca
Creation date: Jan 1, 2025
Entry type: trustedCertEntry

` + testPEMCert + `
`
	m := NewCertStoreModule(&config.Config{})
	m.cmdRunnerLimited = stubRunnerLimited(keytoolOut, nil)

	findings := make(chan *model.Finding, 16)
	err := m.scanJavaCacerts(context.Background(), "/opt/jdk/lib/security/cacerts", findings)
	close(findings)
	require.NoError(t, err)

	collected := collectChan(findings)
	require.NotEmpty(t, collected)
	for _, f := range collected {
		require.NotNil(t, f.CryptoAsset)
		assert.Contains(t, f.CryptoAsset.Algorithm, "RSA")
		assert.Contains(t, f.Source.Path, "cacerts")
		assert.Equal(t, "Java cacerts keystore", f.CryptoAsset.Function)
	}
}

func TestJavaCacerts_KeytoolMissing(t *testing.T) {
	m := NewCertStoreModule(&config.Config{})
	m.cmdRunnerLimited = stubRunnerLimited("", errors.New(`exec: "keytool": executable file not found in $PATH`))

	findings := make(chan *model.Finding, 8)
	err := m.scanJavaCacerts(context.Background(), "/opt/jdk/lib/security/cacerts", findings)
	close(findings)
	assert.NoError(t, err)
	assert.Empty(t, collectChan(findings))
}

// --- Helper ---

func collectChan(ch <-chan *model.Finding) []*model.Finding {
	var out []*model.Finding
	for f := range ch {
		out = append(out, f)
	}
	return out
}
