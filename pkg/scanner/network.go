package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// cryptoPorts maps well-known ports to their crypto protocol.
var cryptoPorts = map[int]struct {
	algorithm string
	function  string
}{
	22:    {"SSH", "SSH server"},
	443:   {"TLS", "HTTPS server"},
	993:   {"TLS", "IMAPS server"},
	995:   {"TLS", "POP3S server"},
	465:   {"TLS", "SMTPS server"},
	636:   {"TLS", "LDAPS server"},
	989:   {"TLS", "FTPS data"},
	990:   {"TLS", "FTPS control"},
	5061:  {"TLS", "SIPS server"},
	8443:  {"TLS", "HTTPS alt server"},
	1194:  {"TLS", "OpenVPN server"},
	500:   {"IPsec", "IKE/IPsec"},
	4500:  {"IPsec", "IPsec NAT-T"},
	4433:  {"TLS", "TLS server"},
	51820: {"ChaCha20-Poly1305", "WireGuard VPN"},
}

// lsofPortRegex extracts command, PID, protocol, and port from lsof output.
var lsofPortRegex = regexp.MustCompile(`^(\S+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(TCP|UDP)\s+\S+:(\d+)`)

// ssPortRegex extracts address:port from ss output.
var ssPortRegex = regexp.MustCompile(`^\S+\s+\d+\s+\d+\s+\S+:(\d+)\s+`)

// NetworkModule scans for listening network services that use cryptographic protocols.
type NetworkModule struct {
	config *config.Config
}

func NewNetworkModule(cfg *config.Config) *NetworkModule {
	return &NetworkModule{config: cfg}
}

func (m *NetworkModule) Name() string {
	return "network"
}

func (m *NetworkModule) Category() model.ModuleCategory {
	return model.CategoryActiveNetwork
}

func (m *NetworkModule) ScanTargetType() model.ScanTargetType {
	return model.TargetNetwork
}

func (m *NetworkModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	switch runtime.GOOS {
	case "darwin":
		return m.scanMacPorts(ctx, findings)
	case "linux":
		return m.scanLinuxPorts(ctx, findings)
	default:
		return nil
	}
}

func (m *NetworkModule) scanMacPorts(ctx context.Context, findings chan<- *model.Finding) error {
	cmd := exec.CommandContext(ctx, "lsof", "-i", "-P", "-n", "-sTCP:LISTEN")
	output, err := cmd.Output()
	if err != nil {
		return nil // Graceful degradation
	}
	return m.parseLsofOutput(ctx, string(output), findings)
}

func (m *NetworkModule) scanLinuxPorts(ctx context.Context, findings chan<- *model.Finding) error {
	// Try ss first (modern)
	cmd := exec.CommandContext(ctx, "ss", "-tlnp")
	output, err := cmd.Output()
	if err == nil {
		return m.parseSSOutput(ctx, string(output), findings)
	}

	// Fallback to lsof
	cmd = exec.CommandContext(ctx, "lsof", "-i", "-P", "-n", "-sTCP:LISTEN")
	output, err = cmd.Output()
	if err == nil {
		return m.parseLsofOutput(ctx, string(output), findings)
	}

	return nil
}

// parseLsofOutput parses lsof output to identify listening crypto services.
func (m *NetworkModule) parseLsofOutput(ctx context.Context, output string, findings chan<- *model.Finding) error {
	seen := make(map[int]bool)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}

		matches := lsofPortRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		command := matches[1]
		pidStr := matches[2]
		protocol := matches[3]
		portStr := matches[4]

		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		// Deduplicate by port
		if seen[port] {
			continue
		}

		algo, isCrypto := classifyPort(port, protocol, command)
		if !isCrypto {
			continue
		}
		seen[port] = true

		pid := parsePID(pidStr)
		endpoint := fmt.Sprintf(":%d/%s", port, strings.ToLower(protocol))

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  fmt.Sprintf("%s service on port %d", algo, port),
			Algorithm: algo,
			Purpose:   "Network service using cryptographic protocol",
		}
		crypto.ClassifyCryptoAsset(asset)

		select {
		case findings <- &model.Finding{
			ID:       uuid.New().String(),
			Category: 8,
			Source: model.FindingSource{
				Type:     "network",
				Path:     command,
				PID:      pid,
				Endpoint: endpoint,
			},
			CryptoAsset: asset,
			Confidence:  0.75,
			Module:      "network",
			Timestamp:   time.Now(),
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// parseSSOutput parses ss (socket statistics) output for listening ports.
func (m *NetworkModule) parseSSOutput(ctx context.Context, output string, findings chan<- *model.Finding) error {
	seen := make(map[int]bool)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") {
			continue
		}

		matches := ssPortRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		port, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}

		if seen[port] {
			continue
		}

		algo, isCrypto := classifyPort(port, "TCP", "")
		if !isCrypto {
			continue
		}
		seen[port] = true

		endpoint := fmt.Sprintf(":%d/tcp", port)

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  fmt.Sprintf("%s service on port %d", algo, port),
			Algorithm: algo,
			Purpose:   "Network service using cryptographic protocol",
		}
		crypto.ClassifyCryptoAsset(asset)

		select {
		case findings <- &model.Finding{
			ID:       uuid.New().String(),
			Category: 8,
			Source: model.FindingSource{
				Type:     "network",
				Endpoint: endpoint,
			},
			CryptoAsset: asset,
			Confidence:  0.75,
			Module:      "network",
			Timestamp:   time.Now(),
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// networkCommandKeywords maps process/command names to crypto algorithms for network services.
// Only includes processes that always use crypto; web servers are excluded since they
// may serve plain HTTP — their crypto ports are handled by the cryptoPorts map.
var networkCommandKeywords = []struct {
	keyword   string
	algorithm string
}{
	{"sshd", "SSH"},
	{"ssh-agent", "SSH"},
	{"openssl", "TLS"},
	{"stunnel", "TLS"},
	{"openvpn", "TLS"},
	{"wireguard", "ChaCha20-Poly1305"},
	{"strongswan", "IPsec"},
	{"ipsec", "IPsec"},
}

// classifyPort determines if a port/protocol/command combination uses crypto.
func classifyPort(port int, _, command string) (algorithm string, isCrypto bool) {
	// Check well-known crypto ports
	if info, ok := cryptoPorts[port]; ok {
		return info.algorithm, true
	}

	// Check command name for known crypto network services
	if command != "" {
		lower := strings.ToLower(command)
		for _, kw := range networkCommandKeywords {
			if strings.Contains(lower, kw.keyword) {
				return kw.algorithm, true
			}
		}
	}

	return "", false
}
