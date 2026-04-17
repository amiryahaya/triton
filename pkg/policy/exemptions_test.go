package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- ParseExemptions tests ---

func TestLoadExemptions_ValidYAML(t *testing.T) {
	data := []byte(`
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "Legacy system, migration planned Q4"
    expires: "2027-01-01"
    approved_by: "security-team"
  - type: thumbprint
    serial_number: "1A:2B:3C"
    issuer: "CN=Root CA"
    reason: "Vendor certificate, no replacement available"
`)
	el, err := ParseExemptions(data)
	require.NoError(t, err)
	require.NotNil(t, el)

	assert.Equal(t, "1", el.Version)
	require.Len(t, el.Exemptions, 2)

	e0 := el.Exemptions[0]
	assert.Equal(t, "algorithm", e0.Type)
	assert.Equal(t, "SHA-1", e0.Algorithm)
	assert.Equal(t, "Legacy system, migration planned Q4", e0.Reason)
	assert.Equal(t, "2027-01-01", e0.Expires)
	assert.Equal(t, "security-team", e0.ApprovedBy)

	e1 := el.Exemptions[1]
	assert.Equal(t, "thumbprint", e1.Type)
	assert.Equal(t, "1A:2B:3C", e1.SerialNumber)
	assert.Equal(t, "CN=Root CA", e1.Issuer)
}

func TestLoadExemptions_MissingReason(t *testing.T) {
	data := []byte(`
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
`)
	_, err := ParseExemptions(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reason")
}

func TestLoadExemptions_MissingVersion(t *testing.T) {
	data := []byte(`
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "test"
`)
	_, err := ParseExemptions(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

func TestLoadExemptions_InvalidType(t *testing.T) {
	data := []byte(`
version: "1"
exemptions:
  - type: unknown_type
    algorithm: SHA-1
    reason: "test"
`)
	_, err := ParseExemptions(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}

// --- IsExempt tests ---

func makeAlgoFinding(algo, path, module string) *model.Finding {
	return &model.Finding{
		Module: module,
		Source: model.FindingSource{Type: "file", Path: path},
		CryptoAsset: &model.CryptoAsset{
			Algorithm: algo,
		},
	}
}

func makeCertFinding(algo, serial, issuer string) *model.Finding {
	return &model.Finding{
		Module: "certificates",
		Source: model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
		CryptoAsset: &model.CryptoAsset{
			Algorithm:    algo,
			SerialNumber: serial,
			Issuer:       issuer,
		},
	}
}

func parseExemptionsOrFail(t *testing.T, data string) *ExemptionList {
	t.Helper()
	el, err := ParseExemptions([]byte(data))
	require.NoError(t, err)
	return el
}

func TestIsExempt_AlgorithmMatch(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "Legacy system"
    expires: "2099-01-01"
`)
	f := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "certificates")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	exempt, idx := el.IsExempt(f, now)
	assert.True(t, exempt)
	assert.Equal(t, 0, idx)
}

func TestIsExempt_AlgorithmCaseInsensitive(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: sha-1
    reason: "Legacy system"
    expires: "2099-01-01"
`)
	f := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "certificates")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	exempt, _ := el.IsExempt(f, now)
	assert.True(t, exempt)
}

func TestIsExempt_AlgorithmWithLocation(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    location: "/etc/ssl/cert.pem"
    reason: "Specific file only"
    expires: "2099-01-01"
`)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Matching path → exempt
	f1 := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "certificates")
	exempt, _ := el.IsExempt(f1, now)
	assert.True(t, exempt, "matching path should be exempt")

	// Different path → not exempt
	f2 := makeAlgoFinding("SHA-1", "/etc/ssl/other.pem", "certificates")
	exempt2, _ := el.IsExempt(f2, now)
	assert.False(t, exempt2, "different path should not be exempt")
}

func TestIsExempt_AlgorithmWithLocationGlob(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    location: "/etc/ssh/*"
    reason: "SSH host keys"
    expires: "2099-01-01"
`)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Glob match → exempt
	f1 := makeAlgoFinding("SHA-1", "/etc/ssh/sshd_config", "certificates")
	exempt, _ := el.IsExempt(f1, now)
	assert.True(t, exempt, "glob match should be exempt")

	// Outside glob → not exempt
	f2 := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "certificates")
	exempt2, _ := el.IsExempt(f2, now)
	assert.False(t, exempt2, "non-matching glob should not be exempt")
}

func TestIsExempt_AlgorithmWithModule(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    module: "certificates"
    reason: "Cert module only"
    expires: "2099-01-01"
`)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Matching module → exempt
	f1 := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "certificates")
	exempt, _ := el.IsExempt(f1, now)
	assert.True(t, exempt, "matching module should be exempt")

	// Different module → not exempt
	f2 := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "libraries")
	exempt2, _ := el.IsExempt(f2, now)
	assert.False(t, exempt2, "different module should not be exempt")
}

func TestIsExempt_Thumbprint(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: thumbprint
    serial_number: "1A:2B:3C"
    issuer: "CN=Root CA"
    reason: "Vendor cert"
    expires: "2099-01-01"
`)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Exact serial + issuer match → exempt
	f1 := makeCertFinding("SHA-1", "1A:2B:3C", "CN=Root CA")
	exempt, _ := el.IsExempt(f1, now)
	assert.True(t, exempt, "matching serial+issuer should be exempt")

	// Wrong serial → not exempt
	f2 := makeCertFinding("SHA-1", "FF:FF:FF", "CN=Root CA")
	exempt2, _ := el.IsExempt(f2, now)
	assert.False(t, exempt2, "wrong serial should not be exempt")

	// Wrong issuer → not exempt
	f3 := makeCertFinding("SHA-1", "1A:2B:3C", "CN=Other CA")
	exempt3, _ := el.IsExempt(f3, now)
	assert.False(t, exempt3, "wrong issuer should not be exempt")
}

func TestIsExempt_Expired(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "Legacy"
    expires: "2020-01-01"
`)
	// now is AFTER expiry
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "certificates")

	exempt, _ := el.IsExempt(f, now)
	assert.False(t, exempt, "expired exemption should not apply")
}

func TestIsExempt_NotExpired(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "Legacy"
    expires: "2030-01-01"
`)
	// now is BEFORE expiry
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "certificates")

	exempt, _ := el.IsExempt(f, now)
	assert.True(t, exempt, "non-expired exemption should apply")
}

func TestIsExempt_NilList(t *testing.T) {
	var el *ExemptionList
	f := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "certificates")
	now := time.Now()

	exempt, idx := el.IsExempt(f, now)
	assert.False(t, exempt)
	assert.Equal(t, -1, idx)
}

func TestIsExempt_NilAsset(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "Legacy"
`)
	now := time.Now()
	f := &model.Finding{
		Module:      "certificates",
		CryptoAsset: nil,
	}

	exempt, idx := el.IsExempt(f, now)
	assert.False(t, exempt)
	assert.Equal(t, -1, idx)
}

func TestIsExempt_AlgorithmMismatch(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "Only SHA-1 exempted"
    expires: "2099-01-01"
`)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := makeAlgoFinding("SHA-256", "/etc/ssl/cert.pem", "certificates")

	exempt, _ := el.IsExempt(f, now)
	assert.False(t, exempt, "SHA-256 finding should not match SHA-1 exemption")
}

func TestExpiredExemptions(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "Expired one"
    expires: "2020-06-15"
  - type: algorithm
    algorithm: MD5
    reason: "Still valid"
    expires: "2030-01-01"
  - type: algorithm
    algorithm: DES
    reason: "Also expired"
    expires: "2019-12-31"
    location: "/legacy/app"
`)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	expired := el.ExpiredExemptions(now)
	require.Len(t, expired, 2)

	// Check the expired entries contain the right algorithms
	algos := make(map[string]string)
	for _, e := range expired {
		algos[e.Algorithm] = e.ExpiredOn
	}

	assert.Contains(t, algos, "SHA-1")
	assert.Equal(t, "2020-06-15", algos["SHA-1"])

	assert.Contains(t, algos, "DES")
	assert.Equal(t, "2019-12-31", algos["DES"])
}

// TestIsExempt_NoExpiry verifies that an exemption without an expiry date
// is always considered active (never expires).
func TestIsExempt_NoExpiry(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: algorithm
    algorithm: SHA-1
    reason: "No expiry set"
`)
	now := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	f := makeAlgoFinding("SHA-1", "/etc/ssl/cert.pem", "certificates")

	exempt, _ := el.IsExempt(f, now)
	assert.True(t, exempt, "exemption with no expiry should always be active")
}

// TestIsExempt_ThumbprintIssuerCaseInsensitive verifies issuer comparison is
// case-insensitive for thumbprint exemptions.
func TestIsExempt_ThumbprintIssuerCaseInsensitive(t *testing.T) {
	el := parseExemptionsOrFail(t, `
version: "1"
exemptions:
  - type: thumbprint
    serial_number: "1A:2B:3C"
    issuer: "cn=root ca"
    reason: "Vendor cert"
    expires: "2099-01-01"
`)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := makeCertFinding("SHA-1", "1A:2B:3C", "CN=Root CA")

	exempt, _ := el.IsExempt(f, now)
	assert.True(t, exempt, "issuer match should be case-insensitive")
}
