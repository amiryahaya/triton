package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
)

// --- isCodeSignCandidate (extended) ---

func TestIsCodeSignCandidate_Authenticode(t *testing.T) {
	t.Parallel()
	// PE artifacts should be candidates on every platform —
	// osslsigncode runs cross-platform.
	for _, ext := range []string{".exe", ".dll", ".msi", ".sys", ".cab"} {
		assert.True(t, isCodeSignCandidate("/path/to/file"+ext), "%s should be candidate", ext)
	}
}

func TestIsCodeSignCandidate_JAR(t *testing.T) {
	t.Parallel()
	for _, ext := range []string{".jar", ".war", ".ear"} {
		assert.True(t, isCodeSignCandidate("/path/to/file"+ext), "%s should be candidate", ext)
	}
}

// --- Authenticode parser ---

// fakeOsslsigncodeOutput mimics the relevant lines from
// `osslsigncode verify -in foo.exe`.
const osslsigncodeSignedOutput = `
Current PE checksum   : 00012345
Calculated PE checksum: 00012345

Message digest algorithm  : SHA256
Current message digest    : abc123def456
Calculated message digest : abc123def456
Signature verification: ok

Signer's certificate:
        Subject : /C=US/O=Microsoft Corporation/CN=Microsoft Code Signing PCA 2011
        Issuer  : /C=US/O=Microsoft Corporation/CN=Microsoft Root Certificate Authority 2010
        Serial  : 33000001E70CF7B0FA1B47D5C2000000000001E
Number of certificates: 3

Succeeded
`

const osslsigncodeUnsignedOutput = `
Current PE checksum   : 00000000
Calculated PE checksum: 00012345

No signature found.

Failed
`

func TestParseAuthenticode_Signed(t *testing.T) {
	t.Parallel()
	m := newCodeSignModuleWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(osslsigncodeSignedOutput), nil
	})
	findings := m.checkAuthenticode(context.Background(), "/test/foo.exe")
	require.NotEmpty(t, findings)

	hasSHA256 := false
	hasSubject := false
	for _, f := range findings {
		if f.CryptoAsset == nil {
			continue
		}
		if f.CryptoAsset.Algorithm == "SHA-256" || f.CryptoAsset.Algorithm == "SHA256" {
			hasSHA256 = true
		}
		if f.CryptoAsset.Subject != "" {
			hasSubject = true
		}
	}
	assert.True(t, hasSHA256, "SHA-256 hash algo missing")
	assert.True(t, hasSubject, "signer subject missing")
}

func TestParseAuthenticode_Unsigned(t *testing.T) {
	t.Parallel()
	m := newCodeSignModuleWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(osslsigncodeUnsignedOutput), errors.New("exit status 1")
	})
	findings := m.checkAuthenticode(context.Background(), "/test/foo.exe")
	require.NotEmpty(t, findings)

	hasUnsigned := false
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "none" {
			hasUnsigned = true
		}
	}
	assert.True(t, hasUnsigned, "unsigned PE should produce a finding with algorithm=none")
}

// --- JAR signing ---

const jarsignerVerifiedOutput = `
sm     12345 Wed Jan 01 00:00:00 UTC 2020 META-INF/MANIFEST.MF
sm     54321 Wed Jan 01 00:00:00 UTC 2020 META-INF/EXAMPLE.SF
sm     65432 Wed Jan 01 00:00:00 UTC 2020 META-INF/EXAMPLE.RSA
sm      1234 Wed Jan 01 00:00:00 UTC 2020 com/example/Main.class

  s = signature was verified
  m = entry is listed in manifest
  k = at least one certificate was found in keystore

- Signed by "CN=Example Signer, O=Example Corp, C=US"
    Digest algorithm: SHA-256
    Signature algorithm: SHA256withRSA, 2048-bit key

jar verified.
`

const jarsignerUnsignedOutput = `
   12345 Wed Jan 01 00:00:00 UTC 2020 META-INF/MANIFEST.MF
    1234 Wed Jan 01 00:00:00 UTC 2020 com/example/Main.class

jar is unsigned.
`

func TestParseJARSign_Signed(t *testing.T) {
	t.Parallel()
	m := newCodeSignModuleWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(jarsignerVerifiedOutput), nil
	})
	findings := m.checkJARSignature(context.Background(), "/test/lib.jar")
	require.NotEmpty(t, findings)

	hasRSA := false
	hasSubject := false
	for _, f := range findings {
		if f.CryptoAsset == nil {
			continue
		}
		if f.CryptoAsset.Algorithm == "RSA" || f.CryptoAsset.Algorithm == "SHA256withRSA" {
			hasRSA = true
		}
		if f.CryptoAsset.Subject == "CN=Example Signer, O=Example Corp, C=US" {
			hasSubject = true
		}
	}
	assert.True(t, hasRSA, "RSA / SHA256withRSA missing")
	assert.True(t, hasSubject, "signer subject missing")
}

func TestParseJARSign_Unsigned(t *testing.T) {
	t.Parallel()
	m := newCodeSignModuleWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(jarsignerUnsignedOutput), nil
	})
	findings := m.checkJARSignature(context.Background(), "/test/lib.jar")
	require.NotEmpty(t, findings)

	hasUnsigned := false
	for _, f := range findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Algorithm == "none" {
			hasUnsigned = true
		}
	}
	assert.True(t, hasUnsigned)
}

// --- Test helper ---

func newCodeSignModuleWithRunner(runner cmdRunnerFunc) *CodeSignModule {
	m := NewCodeSignModule(&config.Config{})
	m.cmdRunner = runner
	m.cmdRunCombined = runner
	return m
}
