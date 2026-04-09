package scanner

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// VPNModule scans VPN configuration files for crypto posture.
// Covers:
//   - strongSwan / Libreswan IPsec (ipsec.conf, swanctl.conf, *.conf
//     under swanctl/conf.d/)
//   - WireGuard wg*.conf
//   - OpenVPN .conf and .ovpn
//
// We deliberately do NOT extract private key material from these
// files; for WireGuard we only flag presence of `PrivateKey =`
// without including the value, because storing key material in
// scan output would itself be a compliance failure.
type VPNModule struct {
	config      *config.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewVPNModule constructs a VPNModule wired to the engine config.
func NewVPNModule(cfg *config.Config) *VPNModule {
	return &VPNModule{config: cfg}
}

func (m *VPNModule) Name() string                         { return "vpn" }
func (m *VPNModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *VPNModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *VPNModule) SetStore(s store.Store)               { m.store = s }

func (m *VPNModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and parses every file matching
// isVPNConfigFile.
func (m *VPNModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isVPNConfigFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			results := m.parseConfig(path, data)
			for _, f := range results {
				// B1 — degenerate tokens (`!`, `-`, `+`) cause
				// the finding builder to return nil. The engine
				// collector would panic on dereference, so drop
				// them here.
				if f == nil {
					continue
				}
				select {
				case findings <- f:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	})
}

// isVPNConfigFile decides whether a path is in scope. Pure path
// match — no content sniff. Sufficient because the canonical
// install layouts are all we promise to cover.
func isVPNConfigFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)
	ext := strings.ToLower(filepath.Ext(base))

	// OpenVPN client profiles.
	if ext == ".ovpn" {
		return true
	}
	// strongSwan top-level files.
	if base == "ipsec.conf" || base == "ipsec.secrets" ||
		base == "strongswan.conf" || base == "swanctl.conf" {
		return true
	}
	// WireGuard interface configs: wg*.conf or files under
	// /etc/wireguard/. Belt and suspenders for both layouts.
	if strings.Contains(lower, "/wireguard/") && ext == ".conf" {
		return true
	}
	if strings.HasPrefix(base, "wg") && ext == ".conf" {
		return true
	}
	// OpenVPN server/client .conf files under /etc/openvpn/.
	if strings.Contains(lower, "/openvpn/") && ext == ".conf" {
		return true
	}
	// strongSwan swanctl drop-in configs.
	if strings.Contains(lower, "/swanctl/") && ext == ".conf" {
		return true
	}
	return false
}

// parseConfig dispatches to the right per-vendor parser.
func (m *VPNModule) parseConfig(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)
	ext := strings.ToLower(filepath.Ext(base))

	switch {
	case base == "ipsec.conf" || strings.Contains(lower, "/swanctl/") || base == "strongswan.conf" || base == "swanctl.conf":
		return m.parseIPsec(path, data)
	case strings.Contains(lower, "/wireguard/") || strings.HasPrefix(base, "wg"):
		return m.parseWireGuard(path, data)
	case ext == ".ovpn" || strings.Contains(lower, "/openvpn/"):
		return m.parseOpenVPN(path, data)
	}
	return nil
}

// --- IPsec / strongSwan ---

// strongswanProposalAlgos splits a proposal string like
// `aes256-sha384-ecp384!` into its component algorithm tokens.
// The trailing `!` (proposal-strict marker) is stripped.
func strongswanProposalAlgos(proposal string) []string {
	proposal = strings.TrimRight(proposal, "!")
	if proposal == "" {
		return nil
	}
	parts := strings.Split(proposal, "-")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// strongswanAlgoMap normalizes strongSwan's IKE/ESP algorithm
// mnemonics into the names the crypto registry recognizes. Maps
// only the cases where strongSwan uses a non-canonical spelling.
var strongswanAlgoMap = map[string]string{
	"aes128":      "AES-128",
	"aes192":      "AES-192",
	"aes256":      "AES-256",
	"aes128gcm16": "AES-128-GCM",
	"aes192gcm16": "AES-192-GCM",
	"aes256gcm16": "AES-256-GCM",
	"3des":        "3DES",
	"des":         "DES",
	"sha1":        "SHA-1",
	"sha256":      "SHA-256",
	"sha384":      "SHA-384",
	"sha512":      "SHA-512",
	"md5":         "MD5",
	"modp1024":    "DH",
	"modp2048":    "DH",
	"modp3072":    "DH",
	"modp4096":    "DH",
	"ecp256":      "ECDSA-P256",
	"ecp384":      "ECDSA-P384",
	"ecp521":      "ECDSA-P521",
	"curve25519":  "X25519",
	"x25519":      "X25519",
}

// parseIPsec walks an ipsec.conf-style file. We don't model the
// `conn` block hierarchy — every `ike=` / `esp=` / `ah=` line is
// turned into one finding per algorithm token. Cross-conn
// resolution is unnecessary because we only care about which
// algorithms appear anywhere in the operator's policy.
func (m *VPNModule) parseIPsec(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "ipsec", scanner.Err()) }()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strongSwan: directive=value, possibly with leading
		// whitespace already stripped.
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		if val == "" {
			continue
		}

		var function, purpose string
		switch key {
		case "ike", "ike-proposal", "proposals":
			function = "IKE proposal"
			purpose = "strongSwan IKE proposal"
		case "esp", "esp-proposal":
			function = "ESP proposal"
			purpose = "strongSwan ESP transform"
		case "ah":
			function = "AH proposal"
			purpose = "strongSwan AH transform"
		case "keyexchange":
			appendNonNil(&out, m.vpnAlgoFinding(path, "Key exchange version", val, "strongSwan keyexchange directive"))
			continue
		case "pfs":
			out = append(out, m.vpnPFSFinding(path, val))
			continue
		default:
			continue
		}

		// Multiple proposals on one line are comma-separated;
		// each proposal is dash-separated tokens.
		for _, prop := range strings.Split(val, ",") {
			for _, tok := range strongswanProposalAlgos(prop) {
				canonical := tok
				if mapped, ok := strongswanAlgoMap[strings.ToLower(tok)]; ok {
					canonical = mapped
				}
				appendNonNil(&out, m.vpnAlgoFinding(path, function, canonical, purpose))
			}
		}
	}
	return out
}

// vpnPFSFinding emits a finding for the pfs= directive. PFS=no is
// notable enough on its own to surface; PFS=yes is benign but
// still recorded so the report shows the operator's choice.
func (m *VPNModule) vpnPFSFinding(path, val string) *model.Finding {
	enabled := strings.EqualFold(val, "yes") || strings.EqualFold(val, "on") || strings.EqualFold(val, "true")
	algo := "PFS-enabled"
	pqcStatus := "TRANSITIONAL"
	if !enabled {
		algo = "PFS-disabled"
		pqcStatus = "DEPRECATED"
	}
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Perfect Forward Secrecy",
		Algorithm: algo,
		Purpose:   "strongSwan pfs directive",
		PQCStatus: pqcStatus,
	}
	return vpnFinding(path, asset)
}

// --- WireGuard ---

// parseWireGuard emits findings for WireGuard's fixed crypto suite
// plus a presence flag for any [Interface] block that has a
// PrivateKey directive (without leaking the value). WireGuard's
// suite is non-negotiable so the algorithms are always the same;
// the value is in marking that this host *operates* a WireGuard
// tunnel for the inventory.
func (m *VPNModule) parseWireGuard(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "wireguard", scanner.Err()) }()

	hasInterface := false
	hasPrivateKey := false
	for scanner.Scan() {
		stripped := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(stripped)
		if lower == "[interface]" {
			hasInterface = true
		}
		if strings.HasPrefix(lower, "privatekey") {
			hasPrivateKey = true
		}
	}
	if !hasInterface {
		return nil
	}

	// Fixed suite findings.
	for _, spec := range []struct{ fn, algo, purp string }{
		{"Key exchange", "X25519", "WireGuard noise handshake"},
		{"Symmetric encryption", "ChaCha20-Poly1305", "WireGuard AEAD"},
		{"Message authentication", "Poly1305", "WireGuard AEAD tag"},
		{"Hash", "Blake2s", "WireGuard hash"},
	} {
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  spec.fn,
			Algorithm: spec.algo,
			Purpose:   spec.purp,
		}
		crypto.ClassifyCryptoAsset(asset)
		out = append(out, vpnFinding(path, asset))
	}

	if hasPrivateKey {
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "Private key configured",
			Algorithm: "X25519",
			Purpose:   "WireGuard interface PrivateKey present (value redacted)",
		}
		crypto.ClassifyCryptoAsset(asset)
		out = append(out, vpnFinding(path, asset))
	}
	return out
}

// --- OpenVPN ---

// parseOpenVPN walks an OpenVPN client/server config and emits
// findings for the crypto-relevant directives. The cipher list
// (`data-ciphers`) is colon-separated; legacy `cipher` is a
// single value.
func (m *VPNModule) parseOpenVPN(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "openvpn", scanner.Err()) }()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		directive := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")

		switch directive {
		case "cipher":
			appendNonNil(&out, m.vpnAlgoFinding(path, "Symmetric encryption", value, "OpenVPN cipher directive (legacy)"))
		case "data-ciphers", "data-ciphers-fallback":
			for _, c := range strings.Split(value, ":") {
				c = strings.TrimSpace(c)
				if c == "" {
					continue
				}
				appendNonNil(&out, m.vpnAlgoFinding(path, "Symmetric encryption", c, "OpenVPN data-ciphers"))
			}
		case "auth":
			appendNonNil(&out, m.vpnAlgoFinding(path, "Message authentication", value, "OpenVPN auth (HMAC) directive"))
		case "tls-cipher", "tls-ciphersuites":
			for _, c := range strings.Split(value, ":") {
				c = strings.TrimSpace(c)
				if c == "" {
					continue
				}
				appendNonNil(&out, m.vpnAlgoFinding(path, "TLS cipher suite", c, "OpenVPN tls-cipher"))
			}
		case "tls-version-min":
			canonical, ok := tlsVersionMap[strings.ToLower(value)]
			if !ok {
				canonical = "TLS " + value
			}
			appendNonNil(&out, m.vpnAlgoFinding(path, "TLS protocol version", canonical, "OpenVPN tls-version-min"))
		}
	}
	return out
}

// --- shared finding builders ---

// vpnAlgoTokenMap pre-normalizes VPN-specific algorithm token
// spellings that the crypto registry does not recognize directly.
// Keyed by lowercased raw token; values are canonical names the
// registry DOES understand. This avoids changing the global
// registry for VPN-only idioms.
//
// S1 review — `BF-CBC` is the OpenVPN legacy Blowfish cipher; the
// registry never matches it because its normalizer strips the
// dash to "BFCBC" which has no substring of "BLOWFISH".
var vpnAlgoTokenMap = map[string]string{
	"bf-cbc":       "Blowfish",
	"bf-cfb":       "Blowfish",
	"bf":           "Blowfish",
	"blowfish-cbc": "Blowfish",
	"cast5-cbc":    "CAST5",
	"cast128":      "CAST5",
	"rc2-cbc":      "RC2",
	"rc2":          "RC2",
	// Normalize common ECDH curve names that OpenVPN emits on
	// `tls-groups` lines. We map them to the curve's canonical
	// ECDSA-P<n> registry name; this is technically a group-vs-
	// key-algorithm conflation but it at least classifies the
	// curve strength instead of leaving it as "unknown".
	"secp256r1":  "ECDSA-P256",
	"secp384r1":  "ECDSA-P384",
	"secp521r1":  "ECDSA-P521",
	"prime256v1": "ECDSA-P256",
}

// vpnAlgoFinding produces one VPN-tagged Finding for an algorithm
// token. Empty inputs are dropped. Strips OpenSSL list operators
// the same way the web_server cipher path does, so an entry like
// `!RC4` does not produce a `!RC4` algorithm name.
func (m *VPNModule) vpnAlgoFinding(path, function, raw, purpose string) *model.Finding {
	cleaned := strings.TrimLeft(raw, "!-+")
	if cleaned == "" {
		return nil
	}
	// VPN-specific token normalization runs BEFORE the general
	// registry classifier so that tokens like BF-CBC reach a
	// name the registry recognizes.
	if mapped, ok := vpnAlgoTokenMap[strings.ToLower(cleaned)]; ok {
		cleaned = mapped
	}
	info := crypto.ClassifyAlgorithm(cleaned, 0)
	algoName := info.Name
	if algoName == "" {
		algoName = cleaned
	}
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  function,
		Algorithm: algoName,
		KeySize:   info.KeySize,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	return vpnFinding(path, asset)
}

// vpnFinding wraps a CryptoAsset into the standard Finding shape
// expected by the engine collector. Centralized so each parser
// produces an identical envelope. The vendor name is encoded in
// asset.Purpose by the caller; no separate parameter needed here.
func vpnFinding(path string, asset *model.CryptoAsset) *model.Finding {
	if asset == nil {
		return nil
	}
	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryConfig,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceHigh,
		Module:      "vpn",
		Timestamp:   time.Now(),
	}
}
