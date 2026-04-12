package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- file matcher tests ---

func TestIsFIDO2File(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		// libfido2 / pam-u2f
		{"/etc/Yubico/u2f_keys", true},
		{"/home/user/.config/Yubico/u2f_keys", true},
		{"/etc/pam.d/u2f-auth", true},

		// WebAuthn RP configs
		{"/etc/webauthn/config.json", true},
		{"/opt/app/webauthn.json", true},

		// FIDO metadata
		{"/etc/fido/metadata.json", true},
		{"/opt/fido2/blob.jwt", true},

		// Not FIDO2
		{"/etc/nginx/nginx.conf", false},
		{"/home/user/keys.json", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isFIDO2File(tc.path), "path: %s", tc.path)
		})
	}
}

// --- pam-u2f key file tests ---

func TestParsePamU2FKeys(t *testing.T) {
	// pam-u2f format: username:KeyHandle,PublicKey,CoseType,Options
	keys := `user1:key1handle,key1pubkey,es256,+presence
user2:key2handle,key2pubkey,eddsa,+presence+verification
`
	m := &FIDO2Module{}
	findings := m.parsePamU2FKeys("/etc/Yubico/u2f_keys", []byte(keys))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["ECDSA-P256"], "es256 should map to ECDSA-P256")
	assert.True(t, algoSet["Ed25519"], "eddsa should map to Ed25519")
}

func TestParsePamU2FKeys_NoKeys(t *testing.T) {
	m := &FIDO2Module{}
	findings := m.parsePamU2FKeys("/etc/Yubico/u2f_keys", []byte(""))
	assert.Empty(t, findings)
}

// --- WebAuthn RP config tests ---

func TestParseWebAuthnConfig(t *testing.T) {
	conf := `{
  "rpId": "example.com",
  "rpName": "Example Corp",
  "attestation": "direct",
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -8},
    {"type": "public-key", "alg": -257}
  ]
}`
	m := &FIDO2Module{}
	findings := m.parseWebAuthnConfig("/etc/webauthn/config.json", []byte(conf))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["ECDSA-P256"], "alg -7 = ES256")
	assert.True(t, algoSet["Ed25519"], "alg -8 = EdDSA")
	assert.True(t, algoSet["RSA"], "alg -257 = RS256")
}

func TestParseWebAuthnConfig_NoPubKey(t *testing.T) {
	conf := `{"rpId": "example.com"}`
	m := &FIDO2Module{}
	findings := m.parseWebAuthnConfig("/etc/webauthn/config.json", []byte(conf))
	assert.Empty(t, findings)
}

// --- module interface ---

func TestFIDO2ModuleInterface(t *testing.T) {
	m := NewFIDO2Module(nil)
	assert.Equal(t, "fido2", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}
