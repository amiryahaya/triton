package scanner

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

var _ Module = (*AuthMaterialModule)(nil)

func TestAuthMaterialModule_Interface(t *testing.T) {
	m := NewAuthMaterialModule(&config.Config{})
	assert.Equal(t, "auth_material", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestIsAuthMaterialFile(t *testing.T) {
	cases := map[string]bool{
		"/etc/krb5.keytab":                                         true,
		"/etc/httpd/conf.d/http.keytab":                            true,
		"/var/lib/tor/hidden_service/hs_ed25519_secret_key":        true,
		"/var/lib/tor/hidden_service/hostname":                     true,
		"/etc/wpa_supplicant/wpa_supplicant.conf":                  true,
		"/etc/NetworkManager/system-connections/Work.nmconnection": true,
		"/var/lib/bind/Kexample.com.+008+12345.private":            true,
		"/etc/bind/keys/Kexample.com.+013+54321.private":           true,
		"/etc/systemd/system/myapp.service":                        true,
		"/etc/systemd/system.conf":                                 false, // not a unit
		"/etc/passwd":                                              false,
		"/home/user/.bashrc":                                       false,
	}
	for path, want := range cases {
		got := isAuthMaterialFile(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

// --- Kerberos keytab binary parser ---

// buildKeytabBlob constructs a minimal valid keytab v2 blob with
// one entry for a given enctype. Used to test the parser without
// needing a real krb5 install. Format reference:
// https://web.mit.edu/kerberos/krb5-1.12/doc/formats/keytab_file_format.html
func buildKeytabBlob(enctype uint16) []byte {
	// File header: 0x05 0x02 (version 2, big-endian for rest of file).
	blob := []byte{0x05, 0x02}

	// Entry (prefixed with a signed int32 length):
	//   uint16  num_components (excluding realm)
	//   counted_string realm
	//   counted_string component[0]
	//   uint32  name_type
	//   uint32  timestamp
	//   uint8   vno8
	//   uint16  enctype
	//   counted_string keyblock
	var entry []byte
	ap := func(b []byte) { entry = append(entry, b...) }

	// num_components = 1
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	ap(u16[:])

	// realm = "EXAMPLE.COM"
	realm := []byte("EXAMPLE.COM")
	binary.BigEndian.PutUint16(u16[:], uint16(len(realm)))
	ap(u16[:])
	ap(realm)

	// component[0] = "host/foo"
	comp := []byte("host/foo")
	binary.BigEndian.PutUint16(u16[:], uint16(len(comp)))
	ap(u16[:])
	ap(comp)

	// name_type = KRB5_NT_PRINCIPAL (1)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], 1)
	ap(u32[:])

	// timestamp = 0
	binary.BigEndian.PutUint32(u32[:], 0)
	ap(u32[:])

	// vno8 = 1
	ap([]byte{0x01})

	// enctype = <arg>
	binary.BigEndian.PutUint16(u16[:], enctype)
	ap(u16[:])

	// keyblock: 16 bytes of zero key material (not a real key!)
	binary.BigEndian.PutUint16(u16[:], 16)
	ap(u16[:])
	ap(make([]byte, 16))

	// Prepend the 32-bit length.
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(entry)))
	blob = append(blob, lenBytes[:]...)
	blob = append(blob, entry...)

	return blob
}

func TestParseKeytab_StrongAES(t *testing.T) {
	// enctype 18 = AES256-CTS-HMAC-SHA1-96 (safe)
	blob := buildKeytabBlob(18)
	m := NewAuthMaterialModule(&config.Config{})
	findings := m.parseKeytab("/etc/krb5.keytab", blob)
	require.NotEmpty(t, findings)

	var aes *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(f.CryptoAsset.Algorithm, "AES-256") {
			aes = f
		}
	}
	require.NotNil(t, aes, "AES-256 keytab enctype finding missing")
	assert.Contains(t, aes.CryptoAsset.Purpose, "host/foo")
	assert.Contains(t, aes.CryptoAsset.Purpose, "EXAMPLE.COM")
}

func TestParseKeytab_WeakArcfour(t *testing.T) {
	// enctype 23 = ARCFOUR-HMAC (RC4 — DEPRECATED)
	blob := buildKeytabBlob(23)
	m := NewAuthMaterialModule(&config.Config{})
	findings := m.parseKeytab("/etc/krb5.keytab", blob)
	require.NotEmpty(t, findings)

	var rc4 *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(strings.ToUpper(f.CryptoAsset.Algorithm), "RC4") {
			rc4 = f
		}
	}
	require.NotNil(t, rc4, "RC4 / arcfour enctype finding missing")
}

func TestParseKeytab_WeakDES(t *testing.T) {
	// enctype 1 = DES-CBC-CRC (fundamentally broken)
	blob := buildKeytabBlob(1)
	m := NewAuthMaterialModule(&config.Config{})
	findings := m.parseKeytab("/etc/krb5.keytab", blob)
	require.NotEmpty(t, findings)

	var des *model.Finding
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(strings.ToUpper(f.CryptoAsset.Algorithm), "DES") {
			des = f
		}
	}
	require.NotNil(t, des, "DES-CBC keytab enctype finding missing")
}

// --- GPG keyring parser ---

const gpgListOutput = `tru::1:1730000000:0:3:1:5
pub:-:4096:1:AABBCCDDEEFF0011:1700000000:::-:::scESC::::::23::0:
fpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678:
uid:-::::1700000000::ABCDEF1234567890ABCDEF1234567890ABCDEF12::Alice <alice@example.com>::::::::::0:
sub:-:2048:1:1122334455667788:1700000000:::::e::::::23:
pub:-:1024:17:1111111111111111:1600000000:::-:::scESC::::::17::0:
uid:-::::1600000000::::Bob Legacy <bob@example.com>::::::::::0:
pub:-:256:22:2222222222222222:1720000000:::-:::scESC::::::22::0:
uid:-::::1720000000::::Carol <carol@example.com>::::::::::0:
`

func TestParseGPG_KeyList(t *testing.T) {
	m := NewAuthMaterialModule(&config.Config{})
	findings := m.parseGPGList([]byte(gpgListOutput))
	// Expect three pub keys: RSA-4096, DSA-1024, Ed25519
	require.Len(t, findings, 3)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "RSA")
	assert.Contains(t, joined, "DSA")
	assert.Contains(t, strings.ToLower(joined), "ed25519")
}

// --- 802.1X supplicant ---

const wpaSupplicantConfig = `network={
    ssid="CorpNet"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="alice@corp.local"
    client_cert="/etc/cert/alice.crt"
    private_key="/etc/cert/alice.key"
    phase1="peaplabel=0"
}

network={
    ssid="LegacyNet"
    key_mgmt=WPA-PSK
    psk="insecurepassword"
}

network={
    ssid="GuestLine"
    key_mgmt=NONE
}
`

func TestParseWPASupplicant(t *testing.T) {
	m := NewAuthMaterialModule(&config.Config{})
	findings := m.parseWPASupplicant("/etc/wpa_supplicant/wpa_supplicant.conf", []byte(wpaSupplicantConfig))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "EAP-TLS")
	assert.Contains(t, joined, "WPA-PSK")
	assert.Contains(t, joined, "OPEN")
}

// --- Tor v3 hidden service ---

func TestTor_DetectsHiddenService(t *testing.T) {
	tmp := t.TempDir()
	hsDir := filepath.Join(tmp, "hidden_service")
	require.NoError(t, os.MkdirAll(hsDir, 0o700))
	// Write the marker files — value doesn't matter, presence does.
	require.NoError(t, os.WriteFile(filepath.Join(hsDir, "hs_ed25519_secret_key"), []byte("magic"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(hsDir, "hostname"), []byte("abcdef.onion\n"), 0o600))

	m := NewAuthMaterialModule(&config.Config{})
	findings := m.parseTorHiddenServiceKey(filepath.Join(hsDir, "hs_ed25519_secret_key"))
	require.NotEmpty(t, findings)

	for _, f := range findings {
		require.NotNil(t, f.CryptoAsset)
		assert.Contains(t, f.CryptoAsset.Algorithm, "Ed25519")
	}
}

// --- DNSSEC key detection ---

func TestDNSSEC_KeyFileName(t *testing.T) {
	m := NewAuthMaterialModule(&config.Config{})

	// K<name>+<algo>+<tag>.private — algo 8 = RSA-SHA256, 13 = ECDSA-P256, 15 = Ed25519
	cases := map[string]string{
		"Kexample.com.+008+12345.private": "RSA",   // 8 = RSASHA256
		"Kexample.com.+013+54321.private": "ECDSA", // 13 = ECDSAP256SHA256
		"Kexample.com.+015+98765.private": "Ed25519",
		"Kexample.com.+007+00001.private": "RSA", // 7 = RSASHA1 (DEPRECATED)
		"Kexample.com.+005+00002.private": "RSA", // 5 = RSASHA1
	}
	for name, expect := range cases {
		findings := m.parseDNSSECKey(name)
		require.NotEmpty(t, findings, "expected findings for %s", name)
		got := findings[0].CryptoAsset.Algorithm
		assert.Contains(t, got, expect, "file=%s got=%s", name, got)
	}
}

// --- systemd credential directives ---

const systemdUnit = `[Unit]
Description=My App

[Service]
ExecStart=/usr/bin/myapp
LoadCredentialEncrypted=dbpass:/etc/myapp/dbpass.cred
SetCredentialEncrypted=apikey:opaquebase64blobhere
Environment="SOME_OTHER=value"
`

func TestParseSystemdUnit(t *testing.T) {
	m := NewAuthMaterialModule(&config.Config{})
	findings := m.parseSystemdUnit("/etc/systemd/system/myapp.service", []byte(systemdUnit))
	require.NotEmpty(t, findings)

	// Both LoadCredentialEncrypted and SetCredentialEncrypted should
	// produce findings.
	purposes := make([]string, 0, len(findings))
	for _, f := range findings {
		purposes = append(purposes, f.CryptoAsset.Purpose)
	}
	joined := strings.Join(purposes, " | ")
	assert.Contains(t, joined, "LoadCredentialEncrypted")
	assert.Contains(t, joined, "SetCredentialEncrypted")
	assert.Contains(t, joined, "dbpass")
	assert.Contains(t, joined, "apikey")
}
