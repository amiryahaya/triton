package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// VPNRuntimeModule enumerates live VPN tunnel state by running
// daemon status commands:
//
//   - `ipsec statusall`  — strongSwan / Libreswan negotiated SAs
//   - `wg show`          — WireGuard active interfaces and peers
//   - `openvpn --status` — OpenVPN status file (reads from
//     /var/run/openvpn-status.log if the daemon writes one)
//
// This captures **actually negotiated** algorithms, which may differ
// from configured values when a peer downgrades. The existing VPNModule
// handles static config files; this module handles runtime state.
type VPNRuntimeModule struct {
	config *scannerconfig.Config
}

// NewVPNRuntimeModule constructs a VPNRuntimeModule.
func NewVPNRuntimeModule(cfg *scannerconfig.Config) *VPNRuntimeModule {
	return &VPNRuntimeModule{config: cfg}
}

func (m *VPNRuntimeModule) Name() string                         { return "vpn_runtime" }
func (m *VPNRuntimeModule) Category() model.ModuleCategory       { return model.CategoryActiveRuntime }
func (m *VPNRuntimeModule) ScanTargetType() model.ScanTargetType { return model.TargetProcess }

// vpnRuntimeCmdRunner abstracts command execution for testability.
var vpnRuntimeCmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// vpnRuntimeReadFile abstracts file reads for testability (OpenVPN status log).
var vpnRuntimeReadFile func(string) ([]byte, error) = os.ReadFile

// Scan probes each supported VPN daemon for runtime crypto state.
// Missing tools or inactive daemons are silently skipped.
func (m *VPNRuntimeModule) Scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	// strongSwan / Libreswan
	if out, err := vpnRuntimeCmdRunner(ctx, "ipsec", "statusall"); err == nil {
		for _, f := range m.parseIPsecStatusAll(out) {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	} else {
		log.Printf("vpn_runtime: ipsec statusall unavailable: %v", err)
	}

	// WireGuard
	if out, err := vpnRuntimeCmdRunner(ctx, "wg", "show"); err == nil {
		for _, f := range m.parseWgShow(out) {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	} else {
		log.Printf("vpn_runtime: wg show unavailable: %v", err)
	}

	// OpenVPN status log (daemon writes this periodically).
	// Read the status file directly — no subprocess needed.
	// Note: the status file format does not expose the negotiated
	// cipher; that requires the management socket (deferred).
	if out, err := vpnRuntimeReadFile("/var/run/openvpn-status.log"); err == nil {
		for _, f := range m.parseOpenVPNStatus(out) {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	} else {
		log.Printf("vpn_runtime: openvpn status unavailable: %v", err)
	}

	return nil
}

// --- strongSwan / Libreswan `ipsec statusall` ---

// ipsecAlgoTokenMap normalizes strongSwan SA status algorithm names
// to the canonical forms the crypto registry recognizes.
var ipsecAlgoTokenMap = map[string]string{
	"AES_CBC_128":       "AES-128",
	"AES_CBC_192":       "AES-192",
	"AES_CBC_256":       "AES-256",
	"AES_CTR_128":       "AES-128",
	"AES_CTR_192":       "AES-192",
	"AES_CTR_256":       "AES-256",
	"AES_GCM_16_128":    "AES-128-GCM",
	"AES_GCM_16_192":    "AES-192-GCM",
	"AES_GCM_16_256":    "AES-256-GCM",
	"AES_GCM_12_128":    "AES-128-GCM",
	"AES_GCM_12_256":    "AES-256-GCM",
	"AES_GCM_8_128":     "AES-128-GCM",
	"AES_GCM_8_256":     "AES-256-GCM",
	"AES_CCM_16_128":    "AES-128",
	"AES_CCM_16_256":    "AES-256",
	"3DES_CBC":          "3DES",
	"DES_CBC":           "DES",
	"CAMELLIA_CBC_128":  "Camellia-128",
	"CAMELLIA_CBC_256":  "Camellia-256",
	"HMAC_SHA1_96":      "SHA-1",
	"HMAC_SHA2_256_128": "SHA-256",
	"HMAC_SHA2_384_192": "SHA-384",
	"HMAC_SHA2_512_256": "SHA-512",
	"HMAC_MD5_96":       "MD5",
	"PRF_HMAC_SHA1":     "SHA-1",
	"PRF_HMAC_SHA2_256": "SHA-256",
	"PRF_HMAC_SHA2_384": "SHA-384",
	"PRF_HMAC_SHA2_512": "SHA-512",
	"PRF_HMAC_MD5":      "MD5",
	"PRF_AES128_XCBC":   "AES-128",
	"MODP_1024":         "DH",
	"MODP_1536":         "DH",
	"MODP_2048":         "DH",
	"MODP_3072":         "DH",
	"MODP_4096":         "DH",
	"MODP_8192":         "DH",
	"ECP_256":           "ECDSA-P256",
	"ECP_384":           "ECDSA-P384",
	"ECP_521":           "ECDSA-P521",
	"CURVE_25519":       "X25519",
	"CURVE_448":         "X448",
	"NO_EXT_SEQ":        "", // not a crypto algorithm
}

// parseIPsecStatusAll extracts negotiated algorithms from `ipsec statusall`.
// Lines of interest:
//
//	conn[N]: IKE proposal: ALG/ALG/ALG/ALG
//	conn{N}:  ALG/ALG/NO_EXT_SEQ, <bytes>
func (m *VPNRuntimeModule) parseIPsecStatusAll(data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		// IKE proposal line
		if idx := strings.Index(line, "IKE proposal:"); idx >= 0 {
			proposal := strings.TrimSpace(line[idx+len("IKE proposal:"):])
			for _, tok := range strings.Split(proposal, "/") {
				tok = strings.TrimSpace(tok)
				f := m.ipsecRuntimeFinding(tok, "IKE negotiated proposal")
				if f != nil {
					out = append(out, f)
				}
			}
			continue
		}

		// ESP/AH child SA line: "conn{N}:  ALG/ALG/NO_EXT_SEQ, bytes_i..."
		// Identified by the {N} brace pattern followed by algorithm tokens.
		if lbrace := strings.Index(line, "{"); lbrace >= 0 {
			if rbrace := strings.Index(line[lbrace:], "}:"); rbrace >= 0 {
				rest := strings.TrimSpace(line[lbrace+rbrace+2:])
				// Skip lines that say INSTALLED, ROUTED, etc.
				if strings.HasPrefix(rest, "INSTALLED") || strings.HasPrefix(rest, "ROUTED") ||
					strings.HasPrefix(rest, "10.") || strings.HasPrefix(rest, "192.") ||
					strings.HasPrefix(rest, "172.") || strings.HasPrefix(rest, "fd") ||
					strings.HasPrefix(rest, "0.0.0.0") || strings.HasPrefix(rest, "::/") {
					continue
				}
				// Extract algorithm part (before comma)
				if comma := strings.Index(rest, ","); comma >= 0 {
					rest = rest[:comma]
				}
				for _, tok := range strings.Split(rest, "/") {
					tok = strings.TrimSpace(tok)
					f := m.ipsecRuntimeFinding(tok, "ESP/AH negotiated transform")
					if f != nil {
						out = append(out, f)
					}
				}
			}
		}
	}
	return out
}

// ipsecRuntimeFinding creates a finding from an ipsec SA algorithm token.
func (m *VPNRuntimeModule) ipsecRuntimeFinding(token, purpose string) *model.Finding {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	canonical, ok := ipsecAlgoTokenMap[token]
	if ok {
		if canonical == "" {
			return nil // NO_EXT_SEQ etc.
		}
	} else {
		// Try the crypto registry directly for unknown tokens.
		info := crypto.ClassifyAlgorithm(token, 0)
		if info.Name != "" {
			canonical = info.Name
		} else {
			canonical = token
		}
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "VPN negotiated algorithm",
		Algorithm: canonical,
		Purpose:   fmt.Sprintf("ipsec statusall: %s", purpose),
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = canonical

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryRuntime,
		Source: model.FindingSource{
			Type:            "process",
			DetectionMethod: "ipsec-statusall",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceDefinitive,
		Module:      "vpn_runtime",
		Timestamp:   time.Now(),
	}
}

// --- WireGuard `wg show` ---

// parseWgShow extracts active WireGuard interfaces from `wg show` output.
// WireGuard's crypto suite is fixed (X25519 + ChaCha20-Poly1305 + Blake2s),
// so the value is confirming which interfaces are running.
func (m *VPNRuntimeModule) parseWgShow(data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))

	var currentInterface string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "interface:") {
			currentInterface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			// Emit fixed suite for each interface
			for _, spec := range []struct{ fn, algo string }{
				{"Key exchange", "X25519"},
				{"Symmetric encryption", "ChaCha20-Poly1305"},
				{"Hash", "Blake2s"},
			} {
				out = append(out, m.wgRuntimeFinding(currentInterface, spec.fn, spec.algo))
			}
		}
	}
	return out
}

func (m *VPNRuntimeModule) wgRuntimeFinding(iface, function, algorithm string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  function,
		Algorithm: algorithm,
		Purpose:   fmt.Sprintf("wg show: active WireGuard interface %s", iface),
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = algorithm

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryRuntime,
		Source: model.FindingSource{
			Type:            "process",
			DetectionMethod: "wg-show",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceDefinitive,
		Module:      "vpn_runtime",
		Timestamp:   time.Now(),
	}
}

// --- OpenVPN status ---

// parseOpenVPNStatus parses the OpenVPN status file. The status
// format does not expose the negotiated cipher directly (that
// requires the management interface `state` command), so we emit
// a presence finding for each connected client — the existence of
// active tunnels is itself a crypto inventory signal.
func (m *VPNRuntimeModule) parseOpenVPNStatus(data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))

	inClientList := false
	clientCount := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		// Detect client list section
		if strings.HasPrefix(line, "Common Name,Real Address") {
			inClientList = true
			continue
		}
		// End of client list
		if inClientList && (strings.HasPrefix(line, "ROUTING TABLE") || line == "") {
			inClientList = false
			continue
		}
		if inClientList {
			// Each line is a connected client
			parts := strings.SplitN(line, ",", 2)
			if len(parts) >= 2 && parts[0] != "" {
				clientCount++
			}
		}
	}

	if clientCount > 0 {
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "OpenVPN active tunnel",
			Algorithm: "OpenVPN-negotiated",
			Purpose:   fmt.Sprintf("openvpn status: %d active client(s)", clientCount),
		}
		crypto.ClassifyCryptoAsset(asset)
		asset.Algorithm = "OpenVPN-negotiated"

		out = append(out, &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: CategoryRuntime,
			Source: model.FindingSource{
				Type:            "process",
				DetectionMethod: "openvpn-status",
			},
			CryptoAsset: asset,
			Confidence:  ConfidenceMedium,
			Module:      "vpn_runtime",
			Timestamp:   time.Now(),
		})
	}
	return out
}
