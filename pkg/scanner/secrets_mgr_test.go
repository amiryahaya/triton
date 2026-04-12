package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- file matcher tests ---

func TestIsSecretsMgrConfigFile(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		// Vault
		{"/etc/vault.d/vault.hcl", true},
		{"/etc/vault/vault.hcl", true},
		{"/opt/vault/config/vault.hcl", true},
		{"/etc/vault.d/vault.json", true},
		{"/etc/vault-agent.hcl", true},

		// AWS
		{"/root/.aws/config", true},
		{"/home/user/.aws/config", true},
		{"/etc/aws/config", true},

		// Azure Key Vault
		{"/etc/azure/keyvault.conf", true},
		{"/opt/azure/keyvault.json", true},

		// SOPS
		{".sops.yaml", true},
		{"/repo/.sops.yaml", true},

		// age / SOPS key files
		{"/etc/sops/age/keys.txt", true},

		// Not secrets mgr
		{"/etc/nginx/nginx.conf", false},
		{"/home/user/.ssh/config", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isSecretsMgrConfigFile(tc.path), "path: %s", tc.path)
		})
	}
}

// --- Vault config parser tests ---

func TestParseVaultConfig_TransitSeal(t *testing.T) {
	conf := `storage "raft" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/tls.crt"
  tls_key_file  = "/opt/vault/tls/tls.key"
}

seal "transit" {
  address = "https://vault.example.com:8200"
  key_name = "autounseal"
  mount_path = "transit/"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "alias/vault-unseal"
}
`
	m := &SecretsMgrModule{}
	findings := m.parseVaultConfig("/etc/vault.d/vault.hcl", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["Vault auto-unseal (transit)"])
	assert.True(t, funcSet["Vault auto-unseal (awskms)"])
	assert.True(t, funcSet["Vault TLS listener"])
}

func TestParseVaultConfig_TLSOnly(t *testing.T) {
	conf := `listener "tcp" {
  tls_cert_file = "/etc/vault/tls.crt"
  tls_key_file  = "/etc/vault/tls.key"
  tls_min_version = "tls12"
}
`
	m := &SecretsMgrModule{}
	findings := m.parseVaultConfig("/etc/vault.d/vault.hcl", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "Vault TLS listener", findings[0].CryptoAsset.Function)
}

func TestParseVaultConfig_NoTLS(t *testing.T) {
	conf := `listener "tcp" {
  tls_disable = 1
}
`
	m := &SecretsMgrModule{}
	findings := m.parseVaultConfig("/etc/vault.d/vault.hcl", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "Vault TLS disabled", findings[0].CryptoAsset.Function)
	assert.Equal(t, "plaintext", findings[0].CryptoAsset.Algorithm)
}

// --- SOPS config parser tests ---

func TestParseSOPSConfig_AgeKey(t *testing.T) {
	conf := `creation_rules:
  - path_regex: secrets/.*\.yaml
    age: >-
      age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  - path_regex: production/.*
    kms: arn:aws:kms:us-east-1:123456789:key/abcd-1234
    pgp: FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4
`
	m := &SecretsMgrModule{}
	findings := m.parseSOPSConfig("/repo/.sops.yaml", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["SOPS age encryption"])
	assert.True(t, funcSet["SOPS AWS KMS encryption"])
	assert.True(t, funcSet["SOPS PGP encryption"])
}

func TestParseSOPSConfig_Empty(t *testing.T) {
	conf := `creation_rules: []
`
	m := &SecretsMgrModule{}
	findings := m.parseSOPSConfig("/repo/.sops.yaml", []byte(conf))
	assert.Empty(t, findings)
}

// --- AWS config parser tests ---

func TestParseAWSConfig_KMS(t *testing.T) {
	conf := `[default]
region = us-east-1

[profile secrets-admin]
region = us-west-2
kms_key_id = arn:aws:kms:us-west-2:123456789:key/abcd-1234
`
	m := &SecretsMgrModule{}
	findings := m.parseAWSConfig("/root/.aws/config", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "AWS KMS key reference", findings[0].CryptoAsset.Function)
}

func TestParseAWSConfig_NoKMS(t *testing.T) {
	conf := `[default]
region = us-east-1
output = json
`
	m := &SecretsMgrModule{}
	findings := m.parseAWSConfig("/root/.aws/config", []byte(conf))
	assert.Empty(t, findings)
}

// --- Azure Key Vault tests ---

func TestParseAzureKV_VaultURL(t *testing.T) {
	conf := `vault-url: https://myorg-keyvault.vault.azure.net/
key-name: my-encryption-key
`
	m := &SecretsMgrModule{}
	findings := m.parseAzureKVConfig("/etc/azure/keyvault.conf", []byte(conf))
	require.Len(t, findings, 2)
	assert.Equal(t, "Azure Key Vault reference", findings[0].CryptoAsset.Function)
	assert.Equal(t, "Azure Key Vault key reference", findings[1].CryptoAsset.Function)
}

func TestParseAzureKV_Empty(t *testing.T) {
	m := &SecretsMgrModule{}
	findings := m.parseAzureKVConfig("/etc/azure/keyvault.conf", []byte("# empty"))
	assert.Empty(t, findings)
}

// --- SOPS age key file tests ---

func TestParseSOPSAgeKeys(t *testing.T) {
	keys := `# created: 2026-04-13T00:00:00Z
# public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
AGE-SECRET-KEY-1QFGHMRPJM5CDLGJ7M6X6FMUWD2FEDJL3ZVTZWTPAQKL93DFJSNQXV5QNQ
`
	m := &SecretsMgrModule{}
	findings := m.parseSOPSAgeKeys("/etc/sops/age/keys.txt", []byte(keys))
	require.Len(t, findings, 1)
	assert.Equal(t, "SOPS age key file", findings[0].CryptoAsset.Function)
	assert.Equal(t, "X25519", findings[0].CryptoAsset.Algorithm)
}

func TestParseSOPSAgeKeys_NoKey(t *testing.T) {
	m := &SecretsMgrModule{}
	findings := m.parseSOPSAgeKeys("/etc/sops/age/keys.txt", []byte("# just comments"))
	assert.Empty(t, findings)
}

// --- module interface tests ---

func TestSecretsMgrModuleInterface(t *testing.T) {
	m := NewSecretsMgrModule(nil)
	assert.Equal(t, "secrets_mgr", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}
