package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- file matcher tests ---

func TestIsEnrollmentFile(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		// Certbot / ACME
		{"/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/abc123/private_key.json", true},
		{"/etc/letsencrypt/renewal/example.com.conf", true},
		{"/etc/letsencrypt/live/example.com/privkey.pem", false}, // PEM handled by cert module

		// step-ca / Smallstep
		{"/etc/step/config/ca.json", true},
		{"/etc/step/config/defaults.json", true},

		// EST client configs
		{"/etc/est/est-client.conf", true},

		// SCEP
		{"/etc/scep/scep.conf", true},

		// Not enrollment
		{"/etc/nginx/nginx.conf", false},
		{"/home/user/private_key.json", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isEnrollmentFile(tc.path), "path: %s", tc.path)
		})
	}
}

// --- certbot / ACME tests ---

func TestParseCertbotRenewal(t *testing.T) {
	conf := `# Options used in the renewal process
[renewalparams]
authenticator = nginx
account = abc123def456
server = https://acme-v02.api.letsencrypt.org/directory
key_type = ecdsa
key_size = 384
`
	m := &EnrollmentModule{}
	findings := m.parseCertbotRenewal("/etc/letsencrypt/renewal/example.com.conf", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	algoSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, funcSet["ACME certificate key type"])
	assert.True(t, algoSet["ECDSA-P384"])
}

func TestParseCertbotRenewal_RSA(t *testing.T) {
	conf := `[renewalparams]
key_type = rsa
key_size = 2048
server = https://acme-v02.api.letsencrypt.org/directory
`
	m := &EnrollmentModule{}
	findings := m.parseCertbotRenewal("/etc/letsencrypt/renewal/test.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "RSA", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, 2048, findings[0].CryptoAsset.KeySize)
}

func TestParseCertbotRenewal_NoKeyType(t *testing.T) {
	conf := `[renewalparams]
authenticator = standalone
`
	m := &EnrollmentModule{}
	findings := m.parseCertbotRenewal("/etc/letsencrypt/renewal/test.conf", []byte(conf))
	assert.Empty(t, findings)
}

// --- certbot account key tests ---

func TestParseCertbotAccountKey(t *testing.T) {
	key := `{
  "kty": "EC",
  "crv": "P-256",
  "x": "f83OJ3D2xF1Bg8vub...",
  "y": "x_FEzRu9m36HLN_tue..."
}`
	m := &EnrollmentModule{}
	findings := m.parseCertbotAccountKey("/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/abc123/private_key.json", []byte(key))
	require.NotEmpty(t, findings)
	assert.Equal(t, "ACME account key", findings[0].CryptoAsset.Function)
	assert.Equal(t, "ECDSA-P256", findings[0].CryptoAsset.Algorithm)
}

func TestParseCertbotAccountKey_RSA(t *testing.T) {
	key := `{"kty": "RSA", "n": "0vx7...", "e": "AQAB"}`
	m := &EnrollmentModule{}
	findings := m.parseCertbotAccountKey("/etc/letsencrypt/accounts/acme-v02/dir/abc/private_key.json", []byte(key))
	require.NotEmpty(t, findings)
	assert.Equal(t, "RSA", findings[0].CryptoAsset.Algorithm)
}

// --- step-ca tests ---

func TestParseStepCA(t *testing.T) {
	conf := `{
  "root": "/etc/step/certs/root_ca.crt",
  "crt": "/etc/step/certs/intermediate_ca.crt",
  "key": "/etc/step/secrets/intermediate_ca_key",
  "kty": "EC",
  "crv": "P-256",
  "authority": {
    "provisioners": [
      {"type": "ACME", "name": "acme"},
      {"type": "OIDC", "name": "google"}
    ]
  }
}`
	m := &EnrollmentModule{}
	findings := m.parseStepCAConfig("/etc/step/config/ca.json", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["step-ca key type"])
}

func TestParseStepCA_NotCA(t *testing.T) {
	conf := `{"some": "config"}`
	m := &EnrollmentModule{}
	findings := m.parseStepCAConfig("/etc/step/config/ca.json", []byte(conf))
	assert.Empty(t, findings)
}

// --- EST parser tests ---

func TestParseESTConfig_ServerURL(t *testing.T) {
	conf := `# EST client config
server = https://est.example.com/.well-known/est
cert = /etc/est/client.crt
key = /etc/est/client.key
`
	m := &EnrollmentModule{}
	findings := m.parseESTConfig("/etc/est/est-client.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "EST enrollment endpoint", findings[0].CryptoAsset.Function)
	assert.Equal(t, "TLS", findings[0].CryptoAsset.Algorithm)
}

func TestParseESTConfig_NoURL(t *testing.T) {
	conf := `# minimal EST config
timeout = 30
`
	m := &EnrollmentModule{}
	findings := m.parseESTConfig("/etc/est/est-client.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "EST client config", findings[0].CryptoAsset.Function)
}

// --- SCEP parser tests ---

func TestParseSCEPConfig_ServerURL(t *testing.T) {
	conf := `# SCEP client config
url = http://scep.example.com/cgi-bin/scep/pkiclient.exe
challenge = secret123
`
	m := &EnrollmentModule{}
	findings := m.parseSCEPConfig("/etc/scep/scep.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "SCEP enrollment endpoint", findings[0].CryptoAsset.Function)
	assert.Equal(t, "RSA", findings[0].CryptoAsset.Algorithm)
	// Challenge must not leak
	assert.NotContains(t, findings[0].CryptoAsset.Purpose, "secret123")
}

func TestParseSCEPConfig_Minimal(t *testing.T) {
	conf := `# minimal
retry = 3
`
	m := &EnrollmentModule{}
	findings := m.parseSCEPConfig("/etc/scep/scep.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "SCEP client config", findings[0].CryptoAsset.Function)
}

// --- module interface ---

func TestEnrollmentModuleInterface(t *testing.T) {
	m := NewEnrollmentModule(nil)
	assert.Equal(t, "enrollment", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}
