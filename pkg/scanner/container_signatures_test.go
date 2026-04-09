package scanner

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

var _ Module = (*ContainerSignaturesModule)(nil)

func TestContainerSignaturesModule_Interface(t *testing.T) {
	t.Parallel()
	m := NewContainerSignaturesModule(&config.Config{})
	assert.Equal(t, "container_signatures", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

// --- Matcher ---

func TestIsContainerSignatureFile(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"/home/user/cosign.pub":                               true,
		"/srv/build/cosign.key":                               true,
		"/etc/kubernetes/encryption-config.yaml":              true,
		"/etc/kubernetes/encryption-provider-config.yaml":     true,
		"/var/run/secrets/kubernetes.io/serviceaccount/token": true,
		"/run/secrets/kubernetes.io/serviceaccount/token":     true,
		"/home/user/.docker/trust/private/abc.key":            true,
		"/home/user/.sigstore/root.json":                      true,
		"/etc/passwd":                                         false,
		"/srv/random/cosign.pub.bak":                          false,
	}
	for path, want := range cases {
		got := isContainerSignatureFile(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

// --- cosign.pub parsing ---

const cosignPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwYsbF1g2gQpZyvcQM5Qe6vQ5K3XW
abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab
-----END PUBLIC KEY-----`

func TestParseCosignPub(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cosign.pub")
	require.NoError(t, os.WriteFile(path, []byte(cosignPubKey), 0o644))

	m := NewContainerSignaturesModule(&config.Config{})
	findings := m.parseCosignKey(path, []byte(cosignPubKey))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	// cosign defaults to ECDSA P-256; the registry should pick
	// up the EC OID from the PEM. Even if parsing fails, the
	// presence-only finding fires.
	hasFinding := false
	for _, a := range algos {
		if a != "" {
			hasFinding = true
		}
	}
	assert.True(t, hasFinding, "cosign key should produce ≥1 finding, got %v", algos)
}

// --- K8s service account token JWT ---

// makeFakeJWT builds a JWT-shaped string with the given alg in
// the header. The signature is a single byte; we never verify
// it, only inspect the header.
func makeFakeJWT(t *testing.T, alg string) string {
	t.Helper()
	header := `{"alg":"` + alg + `","typ":"JWT","kid":"test-key-id"}`
	payload := `{"iss":"kubernetes/serviceaccount","sub":"system:serviceaccount:default:default"}`
	enc := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	return enc(header) + "." + enc(payload) + ".AQ"
}

func TestParseK8sServiceAccountToken(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	tokenDir := filepath.Join(tmp, "var", "run", "secrets", "kubernetes.io", "serviceaccount")
	require.NoError(t, os.MkdirAll(tokenDir, 0o755))

	tokenPath := filepath.Join(tokenDir, "token")
	rs256 := makeFakeJWT(t, "RS256")
	require.NoError(t, os.WriteFile(tokenPath, []byte(rs256), 0o644))

	m := NewContainerSignaturesModule(&config.Config{})
	findings := m.parseK8sToken(tokenPath, []byte(rs256))
	require.NotEmpty(t, findings)

	// The finding should mention the alg from the header.
	hasRS256 := false
	for _, f := range findings {
		if f.CryptoAsset != nil && (strings.Contains(f.CryptoAsset.Algorithm, "RS256") ||
			strings.Contains(strings.ToUpper(f.CryptoAsset.Purpose), "RS256")) {
			hasRS256 = true
		}
	}
	assert.True(t, hasRS256, "RS256 alg not surfaced from JWT header")
}

func TestParseK8sServiceAccountToken_MalformedJWT(t *testing.T) {
	t.Parallel()
	m := NewContainerSignaturesModule(&config.Config{})
	// Not a JWT — three random tokens but the first isn't valid base64.
	findings := m.parseK8sToken("/run/secrets/kubernetes.io/serviceaccount/token", []byte("not.a.jwt"))
	// Malformed → no findings, but no panic either.
	assert.Empty(t, findings)
}

// --- K8s encryption-config.yaml ---

const k8sEncryptionConfigStrong = `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: c2VjcmV0
      - identity: {}
`

const k8sEncryptionConfigWeak = `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - identity: {}
      - aesgcm:
          keys:
            - name: key1
              secret: c2VjcmV0
`

func TestParseK8sEncryptionConfig_Strong(t *testing.T) {
	t.Parallel()
	m := NewContainerSignaturesModule(&config.Config{})
	findings := m.parseK8sEncryptionConfig("/etc/kubernetes/encryption-config.yaml", []byte(k8sEncryptionConfigStrong))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	hasAES := false
	hasIdentity := false
	for _, a := range algos {
		up := strings.ToUpper(a)
		if strings.Contains(up, "AES") {
			hasAES = true
		}
		if strings.Contains(up, "IDENTITY") || strings.Contains(up, "PLAINTEXT") {
			hasIdentity = true
		}
	}
	assert.True(t, hasAES, "AES provider missing, got %v", algos)
	assert.True(t, hasIdentity, "identity (no encryption) provider missing, got %v", algos)
}

// TestParseK8sEncryptionConfig_NoNestedKeyFalsePositives is the
// B2 regression test: before the indent-aware walker was added,
// the parser emitted `algorithm=name` / `algorithm=secret`
// findings for nested keys like `- name: key1` under the
// aescbc.keys: block. With the fix, only top-level provider
// names (aescbc/aesgcm/secretbox/kms/identity) produce findings.
func TestParseK8sEncryptionConfig_NoNestedKeyFalsePositives(t *testing.T) {
	t.Parallel()
	m := NewContainerSignaturesModule(&config.Config{})
	findings := m.parseK8sEncryptionConfig("/etc/kubernetes/encryption-config.yaml", []byte(k8sEncryptionConfigStrong))

	// Every finding must have a provider-style algorithm name.
	// Specifically, NONE should have algorithm names like
	// "name", "secret", or "keys" which are nested YAML keys.
	for _, f := range findings {
		require.NotNil(t, f)
		require.NotNil(t, f.CryptoAsset)
		algo := strings.ToLower(f.CryptoAsset.Algorithm)
		assert.NotContains(t, algo, "name", "nested key 'name' leaked as algorithm")
		assert.NotContains(t, algo, "secret", "nested key 'secret' leaked as algorithm")
		assert.NotContains(t, algo, "keys", "nested key 'keys' leaked as algorithm")
	}
}

// TestParseK8sEncryptionConfig_MultiResource ensures that a
// config with multiple resources entries correctly resets the
// provider-counting state between blocks, so an identity
// provider in the SECOND block is flagged correctly based on
// its position within its own providers list.
func TestParseK8sEncryptionConfig_MultiResource(t *testing.T) {
	t.Parallel()
	const multiResource = `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: c2VjcmV0
      - identity: {}
  - resources:
      - configmaps
    providers:
      - identity: {}
      - aesgcm:
          keys:
            - name: key2
              secret: c2VjcmV0
`
	m := NewContainerSignaturesModule(&config.Config{})
	findings := m.parseK8sEncryptionConfig("/etc/kubernetes/encryption-config.yaml", []byte(multiResource))
	require.NotEmpty(t, findings)

	// The second block's identity provider is first, so the
	// PLAINTEXT warning must fire for it.
	plaintextWarnings := 0
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(f.CryptoAsset.Purpose, "PLAINTEXT") {
			plaintextWarnings++
		}
	}
	assert.Equal(t, 1, plaintextWarnings, "exactly one PLAINTEXT warning expected (second resource, configmaps)")
}

// TestParseK8sEncryptionConfig_ProvidersWithInlineComment is
// the B5 regression test: before the fix, a `providers: #
// managed by kubeadm` line failed HasSuffix("providers:"), so
// the parser never entered the block and the whole config was
// silently skipped.
func TestParseK8sEncryptionConfig_ProvidersWithInlineComment(t *testing.T) {
	t.Parallel()
	const cfg = `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers: # managed by kubeadm
      - aescbc:
          keys:
            - name: key1
              secret: c2VjcmV0
      - identity: {}
`
	m := NewContainerSignaturesModule(&config.Config{})
	findings := m.parseK8sEncryptionConfig("/etc/kubernetes/encryption-config.yaml", []byte(cfg))
	require.NotEmpty(t, findings, "inline comment on providers: line should not silence the walker")

	// aescbc must be present.
	hasAES := false
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(f.CryptoAsset.Algorithm, "AES") {
			hasAES = true
		}
	}
	assert.True(t, hasAES, "aescbc provider missing, algos=%v", collectAlgorithms(findings))
}

func TestParseK8sEncryptionConfig_IdentityFirst(t *testing.T) {
	t.Parallel()
	// When `identity` is the FIRST provider for a resource, no
	// encryption-at-rest is applied — this is a critical
	// misconfiguration that the scanner must surface.
	m := NewContainerSignaturesModule(&config.Config{})
	findings := m.parseK8sEncryptionConfig("/etc/kubernetes/encryption-config.yaml", []byte(k8sEncryptionConfigWeak))
	require.NotEmpty(t, findings)

	hasWarning := false
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(strings.ToLower(f.CryptoAsset.Purpose), "first provider") {
			hasWarning = true
		}
	}
	assert.True(t, hasWarning, "identity-first warning missing")
}
