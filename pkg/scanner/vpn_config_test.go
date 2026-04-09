package scanner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

var _ Module = (*VPNModule)(nil)

func TestVPNModule_Interface(t *testing.T) {
	t.Parallel()
	m := NewVPNModule(&config.Config{})
	assert.Equal(t, "vpn", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

// --- Matcher ---

func TestIsVPNConfigFile(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"/etc/ipsec.conf":                       true,
		"/etc/strongswan/ipsec.conf":            true,
		"/etc/strongswan.conf":                  true,
		"/etc/swanctl/swanctl.conf":             true,
		"/etc/strongswan/swanctl/conf.d/a.conf": true,
		"/etc/wireguard/wg0.conf":               true,
		"/etc/wireguard/wg-corp.conf":           true,
		"/etc/openvpn/server.conf":              true,
		"/etc/openvpn/client.conf":              true,
		"/home/user/work.ovpn":                  true,
		"/etc/openvpn/easy-rsa/vars":            false, // not a vpn conf
		"/etc/nginx/nginx.conf":                 false,
		"/etc/wireguard/wg0.conf.bak":           false,
	}
	for path, want := range cases {
		got := isVPNConfigFile(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

// --- IPsec (strongSwan) ---

const ipsecStrong = `
config setup
    charondebug="ike 2"

conn rw
    keyexchange=ikev2
    ike=aes256-sha384-ecp384!
    esp=aes256gcm16-ecp384!
    pfs=yes
    left=%defaultroute
    right=vpn.example.com
    auto=start
`

const ipsecWeak = `
conn legacy
    keyexchange=ikev1
    ike=3des-md5-modp1024
    esp=3des-md5
    pfs=no
`

func TestParseIPsec_Strong(t *testing.T) {
	t.Parallel()
	m := NewVPNModule(&config.Config{})
	findings := m.parseIPsec("/etc/ipsec.conf", []byte(ipsecStrong))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	// Expect ike= and esp= proposals to be split into individual
	// algorithm findings (aes256, sha384, ecp384, etc.).
	hasAES := false
	hasSHA := false
	hasECP := false
	for _, a := range algos {
		up := strings.ToUpper(a)
		if strings.Contains(up, "AES") {
			hasAES = true
		}
		if strings.Contains(up, "SHA") {
			hasSHA = true
		}
		if strings.Contains(up, "ECP") || strings.Contains(up, "ECDH") || strings.Contains(up, "P384") || strings.Contains(up, "P-384") {
			hasECP = true
		}
	}
	assert.True(t, hasAES, "AES missing, got %v", algos)
	assert.True(t, hasSHA, "SHA missing, got %v", algos)
	assert.True(t, hasECP, "EC curve missing, got %v", algos)
}

func TestParseIPsec_Weak(t *testing.T) {
	t.Parallel()
	m := NewVPNModule(&config.Config{})
	findings := m.parseIPsec("/etc/ipsec.conf", []byte(ipsecWeak))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	// 3des and md5 must surface — they're the entire point of
	// scanning legacy VPN configs.
	has3DES := false
	hasMD5 := false
	for _, a := range algos {
		up := strings.ToUpper(a)
		if strings.Contains(up, "3DES") || strings.Contains(up, "DES") {
			has3DES = true
		}
		if strings.Contains(up, "MD5") {
			hasMD5 = true
		}
	}
	assert.True(t, has3DES, "3DES missing, got %v", algos)
	assert.True(t, hasMD5, "MD5 missing, got %v", algos)
}

// --- WireGuard ---

const wireguardConfig = `
[Interface]
PrivateKey = aGVsbG93b3JsZGV4YW1wbGVwbGFjZWhvbGRlcjEyMzQ1Njc4OQ==
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = cGVlcnB1YmtleWV4YW1wbGVwbGFjZWhvbGRlcjEyMzQ1Njc4OQ==
AllowedIPs = 10.0.0.2/32
Endpoint = peer.example.com:51820
PersistentKeepalive = 25
`

func TestParseWireGuard(t *testing.T) {
	t.Parallel()
	m := NewVPNModule(&config.Config{})
	findings := m.parseWireGuard("/etc/wireguard/wg0.conf", []byte(wireguardConfig))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	// WireGuard's crypto suite is fixed: X25519 + ChaCha20-Poly1305 + Blake2s.
	// Verify all three appear in the findings.
	hasX25519 := false
	hasChaCha := false
	hasBlake := false
	for _, a := range algos {
		up := strings.ToUpper(a)
		if strings.Contains(up, "X25519") || strings.Contains(up, "CURVE25519") {
			hasX25519 = true
		}
		if strings.Contains(up, "CHACHA20") {
			hasChaCha = true
		}
		if strings.Contains(up, "BLAKE2") {
			hasBlake = true
		}
	}
	assert.True(t, hasX25519, "X25519 missing, got %v", algos)
	assert.True(t, hasChaCha, "ChaCha20 missing, got %v", algos)
	assert.True(t, hasBlake, "Blake2s missing, got %v", algos)

	// Detection of PrivateKey presence (without leaking the value).
	hasPrivKey := false
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(f.CryptoAsset.Function, "Private key") {
			hasPrivKey = true
			// Make sure we don't leak the actual key material.
			assert.NotContains(t, f.CryptoAsset.Purpose, "aGVsbG93b3JsZA")
		}
	}
	assert.True(t, hasPrivKey, "WireGuard private key presence not flagged")
}

// --- OpenVPN ---

const openvpnStrong = `
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
data-ciphers AES-256-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
`

const openvpnWeak = `
client
remote vpn.example.com 1194
cipher BF-CBC
auth MD5
tls-version-min 1.0
`

func TestParseOpenVPN_Strong(t *testing.T) {
	t.Parallel()
	m := NewVPNModule(&config.Config{})
	findings := m.parseOpenVPN("/etc/openvpn/client.ovpn", []byte(openvpnStrong))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	hasAES := false
	hasChaCha := false
	for _, a := range algos {
		up := strings.ToUpper(a)
		if strings.Contains(up, "AES") {
			hasAES = true
		}
		if strings.Contains(up, "CHACHA") {
			hasChaCha = true
		}
	}
	assert.True(t, hasAES)
	assert.True(t, hasChaCha)
	assert.Contains(t, algos, "TLS 1.2")
}

// TestParseOpenVPN_TLSGroups is the S4 regression test: before
// the fix, `tls-groups` was not a case in parseOpenVPN's switch,
// so the vpnAlgoTokenMap entries for secp*/prime256v1 were dead
// code and OpenVPN ECDH curve names produced zero findings.
func TestParseOpenVPN_TLSGroups(t *testing.T) {
	t.Parallel()
	const cfg = `
client
remote vpn.example.com 1194
tls-groups secp384r1:X25519:prime256v1
`
	m := NewVPNModule(&config.Config{})
	findings := m.parseOpenVPN("/etc/openvpn/client.ovpn", []byte(cfg))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	// Expect all three curves (normalized by vpnAlgoTokenMap or
	// classified by the registry).
	hasP384 := false
	hasX25519 := false
	hasP256 := false
	for _, a := range algos {
		up := strings.ToUpper(a)
		if strings.Contains(up, "P384") || strings.Contains(up, "P-384") {
			hasP384 = true
		}
		if strings.Contains(up, "X25519") || strings.Contains(up, "CURVE25519") {
			hasX25519 = true
		}
		if strings.Contains(up, "P256") || strings.Contains(up, "P-256") {
			hasP256 = true
		}
	}
	assert.True(t, hasP384, "secp384r1 missing, got %v", algos)
	assert.True(t, hasX25519, "X25519 missing, got %v", algos)
	assert.True(t, hasP256, "prime256v1 missing, got %v", algos)
}

// TestParseIPsec_PFSDisabled verifies that `pfs = no` surfaces
// as a PFS-disabled finding (the B3 defensive refactor turned
// this path into an appendNonNil call; ensure it still fires).
func TestParseIPsec_PFSDisabled(t *testing.T) {
	t.Parallel()
	const cfg = `
conn weak
    keyexchange=ikev2
    ike=aes256-sha256-modp2048
    pfs=no
`
	m := NewVPNModule(&config.Config{})
	findings := m.parseIPsec("/etc/ipsec.conf", []byte(cfg))

	hasDisabled := false
	for _, f := range findings {
		if f.CryptoAsset != nil && strings.Contains(f.CryptoAsset.Algorithm, "PFS-disabled") {
			hasDisabled = true
		}
	}
	assert.True(t, hasDisabled, "PFS-disabled finding missing, algos=%v", collectAlgorithms(findings))
}

func TestParseOpenVPN_Weak(t *testing.T) {
	t.Parallel()
	m := NewVPNModule(&config.Config{})
	findings := m.parseOpenVPN("/etc/openvpn/client.ovpn", []byte(openvpnWeak))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	hasBF := false
	hasMD5 := false
	for _, a := range algos {
		up := strings.ToUpper(a)
		if strings.Contains(up, "BF") || strings.Contains(up, "BLOWFISH") {
			hasBF = true
		}
		if strings.Contains(up, "MD5") {
			hasMD5 = true
		}
	}
	assert.True(t, hasBF, "Blowfish missing, got %v", algos)
	assert.True(t, hasMD5, "MD5 missing, got %v", algos)
	assert.Contains(t, algos, "TLS 1.0")
}
