package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface compliance
var _ Module = (*ConfigModule)(nil)

func TestConfigModuleInterface(t *testing.T) {
	m := NewConfigModule(&config.Config{})
	assert.Equal(t, "configs", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestIsConfigFile(t *testing.T) {
	m := NewConfigModule(&config.Config{})

	assert.True(t, m.isConfigFile("/etc/ssh/sshd_config"))
	assert.True(t, m.isConfigFile("/etc/ssh/ssh_config"))
	assert.True(t, m.isConfigFile("/etc/crypto-policies/state/current"))
	assert.True(t, m.isConfigFile("/usr/lib/jvm/java-17/conf/security/java.security"))

	assert.False(t, m.isConfigFile("/etc/ssh/known_hosts"))
	assert.False(t, m.isConfigFile("/etc/hosts"))
	assert.False(t, m.isConfigFile("/tmp/current")) // not in crypto-policies path
}

func TestParseSSHConfig(t *testing.T) {
	tmpDir := t.TempDir()
	sshdConfig := filepath.Join(tmpDir, "sshd_config")
	err := os.WriteFile(sshdConfig, []byte(`
# Test SSH config
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&config.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should find: 2 kex + 2 ciphers + 2 macs + 2 hostkey = 8 findings
	require.Len(t, collected, 8)

	// Verify findings have expected attributes
	for _, f := range collected {
		assert.Equal(t, 8, f.Category)
		assert.Equal(t, "configs", f.Module)
		assert.Equal(t, "file", f.Source.Type)
		assert.Equal(t, "configuration", f.Source.DetectionMethod)
		assert.NotNil(t, f.CryptoAsset)
		assert.NotEmpty(t, f.CryptoAsset.Algorithm)
		assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
	}

	// Check specific algorithms
	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algos["X25519"], "Should find X25519 from curve25519-sha256")
	assert.True(t, algos["AES-256-GCM"], "Should find AES-256-GCM")
	assert.True(t, algos["ChaCha20-Poly1305"], "Should find ChaCha20-Poly1305")
	assert.True(t, algos["Ed25519"], "Should find Ed25519")
}

func TestParseSSHConfigComments(t *testing.T) {
	tmpDir := t.TempDir()
	sshdConfig := filepath.Join(tmpDir, "sshd_config")
	err := os.WriteFile(sshdConfig, []byte(`
# This is a comment
# Ciphers aes128-cbc
Port 22
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "Comments and non-crypto directives should produce no findings")
}

func TestParseJavaSecurity(t *testing.T) {
	tmpDir := t.TempDir()
	javaSec := filepath.Join(tmpDir, "java.security")
	err := os.WriteFile(javaSec, []byte(`
jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, 3DES_EDE_CBC, NULL
jdk.certpath.disabledAlgorithms=MD2, MD5
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&config.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should find: SSLv3, RC4, DES, 3DES, NULL from tls.disabled + MD2, MD5 from certpath
	require.Len(t, collected, 7)

	algos := make(map[string]bool)
	for _, f := range collected {
		algos[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algos["SSL 3.0"])
	assert.True(t, algos["RC4"])
	assert.True(t, algos["DES"])
	assert.True(t, algos["3DES"])
}

func TestParseJavaSecurityMultiline(t *testing.T) {
	tmpDir := t.TempDir()
	javaSec := filepath.Join(tmpDir, "java.security")
	err := os.WriteFile(javaSec, []byte(`jdk.tls.disabledAlgorithms=SSLv3, TLSv1, \
    RC4, DES
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&config.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 1}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// SSLv3, TLSv1, RC4, DES = 4 algorithms
	require.Len(t, collected, 4)
}

func TestParseCryptoPolicies(t *testing.T) {
	tmpDir := t.TempDir()
	// Must have "crypto-policies" in the path
	policyDir := filepath.Join(tmpDir, "crypto-policies", "state")
	err := os.MkdirAll(policyDir, 0755)
	require.NoError(t, err)

	policyFile := filepath.Join(policyDir, "current")
	err = os.WriteFile(policyFile, []byte("FUTURE\n"), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&config.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 5}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 1)
	assert.Contains(t, collected[0].CryptoAsset.Algorithm, "FUTURE")
	assert.Equal(t, "TRANSITIONAL", collected[0].CryptoAsset.PQCStatus)
}

func TestScanFixtureConfigs(t *testing.T) {
	// Test against the actual fixture files
	fixtureDir := filepath.Join("../../test/fixtures/configs")
	if _, err := os.Stat(filepath.Join(fixtureDir, "sshd_config")); os.IsNotExist(err) {
		t.Skip("Fixture files not found")
	}

	m := NewConfigModule(&config.Config{})
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: fixtureDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Should find multiple findings from sshd_config + java.security
	assert.NotEmpty(t, collected, "Should find findings in fixture config files")

	for _, f := range collected {
		assert.Equal(t, "configs", f.Module)
		assert.NotNil(t, f.CryptoAsset)
	}
}
