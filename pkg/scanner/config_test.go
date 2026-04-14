package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

// Compile-time interface compliance
var _ Module = (*ConfigModule)(nil)

func TestConfigModuleInterface(t *testing.T) {
	t.Parallel()
	m := NewConfigModule(&scannerconfig.Config{})
	assert.Equal(t, "configs", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestIsConfigFile(t *testing.T) {
	t.Parallel()
	m := NewConfigModule(&scannerconfig.Config{})

	assert.True(t, m.isConfigFile("/etc/ssh/sshd_config"))
	assert.True(t, m.isConfigFile("/etc/ssh/ssh_config"))
	assert.True(t, m.isConfigFile("/etc/crypto-policies/state/current"))
	assert.True(t, m.isConfigFile("/usr/lib/jvm/java-17/conf/security/java.security"))

	assert.False(t, m.isConfigFile("/etc/ssh/known_hosts"))
	assert.False(t, m.isConfigFile("/etc/hosts"))
	assert.False(t, m.isConfigFile("/tmp/current")) // not in crypto-policies path
}

func TestParseSSHConfig(t *testing.T) {
	t.Parallel()
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

	m := NewConfigModule(&scannerconfig.Config{})
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
	t.Parallel()
	tmpDir := t.TempDir()
	sshdConfig := filepath.Join(tmpDir, "sshd_config")
	err := os.WriteFile(sshdConfig, []byte(`
# This is a comment
# Ciphers aes128-cbc
Port 22
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
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
	t.Parallel()
	tmpDir := t.TempDir()
	javaSec := filepath.Join(tmpDir, "java.security")
	err := os.WriteFile(javaSec, []byte(`
jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, 3DES_EDE_CBC, NULL
jdk.certpath.disabledAlgorithms=MD2, MD5
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
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
	t.Parallel()
	tmpDir := t.TempDir()
	javaSec := filepath.Join(tmpDir, "java.security")
	err := os.WriteFile(javaSec, []byte(`jdk.tls.disabledAlgorithms=SSLv3, TLSv1, \
    RC4, DES
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
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
	t.Parallel()
	tmpDir := t.TempDir()
	// Must have "crypto-policies" in the path
	policyDir := filepath.Join(tmpDir, "crypto-policies", "state")
	err := os.MkdirAll(policyDir, 0755)
	require.NoError(t, err)

	policyFile := filepath.Join(policyDir, "current")
	err = os.WriteFile(policyFile, []byte("FUTURE\n"), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
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

func TestParseCryptoPolicies_FIPS(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "crypto-policies", "state")
	err := os.MkdirAll(policyDir, 0755)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(policyDir, "current"), []byte("FIPS\n"), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
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
	assert.Contains(t, collected[0].CryptoAsset.Algorithm, "FIPS")
	assert.Equal(t, "TRANSITIONAL", collected[0].CryptoAsset.PQCStatus)
	assert.Contains(t, collected[0].CryptoAsset.Purpose, "FIPS 140")
}

func TestParseCryptoPolicies_DEFAULT(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "crypto-policies", "state")
	err := os.MkdirAll(policyDir, 0755)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(policyDir, "current"), []byte("DEFAULT\n"), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
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
	assert.Contains(t, collected[0].CryptoAsset.Algorithm, "DEFAULT")
	assert.Equal(t, "TRANSITIONAL", collected[0].CryptoAsset.PQCStatus)
	assert.Contains(t, collected[0].CryptoAsset.Purpose, "balanced")
}

func TestParseCryptoPolicies_LEGACY(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "crypto-policies", "state")
	err := os.MkdirAll(policyDir, 0755)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(policyDir, "current"), []byte("LEGACY\n"), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
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
	assert.Contains(t, collected[0].CryptoAsset.Algorithm, "LEGACY")
	assert.Equal(t, "DEPRECATED", collected[0].CryptoAsset.PQCStatus)
	assert.Contains(t, collected[0].CryptoAsset.Purpose, "legacy")
}

func TestParseCryptoPolicies_Unknown(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "crypto-policies", "state")
	err := os.MkdirAll(policyDir, 0755)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(policyDir, "current"), []byte("CUSTOM:PQC-HYBRID\n"), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
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
	assert.Equal(t, "TRANSITIONAL", collected[0].CryptoAsset.PQCStatus)
	assert.Contains(t, collected[0].CryptoAsset.Purpose, "CUSTOM:PQC-HYBRID")
}

func TestParseCryptoPolicies_Empty(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "crypto-policies", "state")
	err := os.MkdirAll(policyDir, 0755)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(policyDir, "current"), []byte(""), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 5}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	assert.Empty(t, collected, "Empty policy file should produce no findings")
}

func TestConfigModule_CertbotRenewalConf(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	// Create letsencrypt/renewal.conf path
	renewalDir := filepath.Join(tmpDir, "etc", "letsencrypt", "renewal")
	err := os.MkdirAll(renewalDir, 0755)
	require.NoError(t, err)

	renewalConf := filepath.Join(renewalDir, "renewal.conf")
	err = os.WriteFile(renewalConf, []byte(`
# Certbot renewal config
cert = /etc/letsencrypt/live/example.com/cert.pem
privkey = /etc/letsencrypt/live/example.com/privkey.pem
key_type = ecdsa
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})

	// Verify isConfigFile matches
	assert.True(t, m.isConfigFile(renewalConf), "should match letsencrypt renewal.conf")
	assert.False(t, m.isConfigFile("/tmp/renewal.conf"), "should not match non-letsencrypt renewal.conf")

	// Parse the file
	findings := m.parseCertbotConfig(context.Background(), fsadapter.NewLocalReader(), renewalConf)
	require.Len(t, findings, 1)
	assert.Equal(t, "ACME certificate renewal", findings[0].CryptoAsset.Purpose)
	assert.Equal(t, "ECDSA-P256", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "configs", findings[0].Module)
}

func TestConfigModule_CertbotHyphenatedKeys(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	renewalDir := filepath.Join(tmpDir, "etc", "letsencrypt", "renewal")
	err := os.MkdirAll(renewalDir, 0755)
	require.NoError(t, err)

	// Use hyphenated key names (certbot's actual format)
	renewalConf := filepath.Join(renewalDir, "renewal.conf")
	err = os.WriteFile(renewalConf, []byte(`
# Certbot renewal config with hyphenated keys
cert = /etc/letsencrypt/live/example.com/cert.pem
key-type = rsa
rsa-key-size = 4096
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
	findings := m.parseCertbotConfig(context.Background(), fsadapter.NewLocalReader(), renewalConf)
	require.Len(t, findings, 1)
	assert.Equal(t, "RSA-4096", findings[0].CryptoAsset.Algorithm)
}

func TestConfigModule_CertbotDomainConf(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	renewalDir := filepath.Join(tmpDir, "etc", "letsencrypt", "renewal")
	err := os.MkdirAll(renewalDir, 0755)
	require.NoError(t, err)

	// Domain-named conf file (real certbot format)
	domainConf := filepath.Join(renewalDir, "example.com.conf")
	err = os.WriteFile(domainConf, []byte(`
cert = /etc/letsencrypt/live/example.com/cert.pem
key_type = ecdsa
`), 0644)
	require.NoError(t, err)

	m := NewConfigModule(&scannerconfig.Config{})
	assert.True(t, m.isConfigFile(domainConf), "should match domain.conf under letsencrypt/renewal/")

	findings := m.parseCertbotConfig(context.Background(), fsadapter.NewLocalReader(), domainConf)
	require.Len(t, findings, 1)
	assert.Equal(t, "ECDSA-P256", findings[0].CryptoAsset.Algorithm)
}

func TestSSHAlgorithmMap_RSASignatureAlgorithms(t *testing.T) {
	t.Parallel()
	// ssh-rsa, rsa-sha2-256, rsa-sha2-512 are signature algorithms,
	// not key types — they should map to "RSA" without a key size.
	rsaSignatureAlgos := []string{"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}
	for _, algo := range rsaSignatureAlgos {
		t.Run(algo, func(t *testing.T) {
			mapped, ok := sshAlgorithmMap[algo]
			require.True(t, ok, "algorithm %s should be in map", algo)
			assert.Equal(t, "RSA", mapped, "signature algorithm %s should map to RSA without key size", algo)
		})
	}
}

func TestScanFixtureConfigs(t *testing.T) {
	t.Parallel()
	// Test against the actual fixture files
	fixtureDir := filepath.Join("../../test/fixtures/configs")
	if _, err := os.Stat(filepath.Join(fixtureDir, "sshd_config")); os.IsNotExist(err) {
		t.Skip("Fixture files not found")
	}

	m := NewConfigModule(&scannerconfig.Config{})
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
