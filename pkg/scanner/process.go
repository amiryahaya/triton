package scanner

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// cryptoProcessKeywords maps process names to their crypto function and algorithm.
var cryptoProcessKeywords = []struct {
	keyword   string
	name      string
	algorithm string
	function  string
}{
	{"sshd", "OpenSSH server", "SSH", "SSH server authentication"},
	{"ssh-agent", "SSH agent", "SSH", "SSH key agent"},
	{"ssh", "SSH client", "SSH", "SSH client connection"},
	{"openssl", "OpenSSL CLI", "TLS", "Cryptographic operations"},
	{"stunnel", "stunnel", "TLS", "TLS tunneling proxy"},
	{"openvpn", "OpenVPN", "TLS", "VPN tunnel encryption"},
	{"wireguard", "WireGuard", "ChaCha20-Poly1305", "VPN tunnel encryption"},
	{"strongswan", "strongSwan", "IPsec", "IPsec VPN"},
	{"ipsec", "IPsec", "IPsec", "IPsec VPN"},
	{"gpg-agent", "GnuPG agent", "RSA", "PGP key management"},
	{"gpg", "GnuPG", "RSA", "PGP encryption/signing"},
	{"certbot", "Certbot", "RSA", "ACME certificate management"},
	{"vault", "HashiCorp Vault", "AES-256-GCM", "Secrets management"},
	{"step-ca", "Smallstep CA", "RSA", "Certificate authority"},
}

// ProcessModule scans running processes for crypto-related binaries and library linkage.
type ProcessModule struct {
	config *scannerconfig.Config
}

func NewProcessModule(cfg *scannerconfig.Config) *ProcessModule {
	return &ProcessModule{config: cfg}
}

func (m *ProcessModule) Name() string {
	return "processes"
}

func (m *ProcessModule) Category() model.ModuleCategory {
	return model.CategoryActiveRuntime
}

func (m *ProcessModule) ScanTargetType() model.ScanTargetType {
	return model.TargetProcess
}

func (m *ProcessModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	// Get process list
	cmd := exec.CommandContext(ctx, "ps", "-eo", "pid,command")
	output, err := cmd.Output()
	if err != nil {
		return nil // Graceful degradation if ps is not available
	}

	return m.parseProcessOutput(ctx, string(output), findings)
}

// parseProcessOutput parses ps output and identifies crypto-related processes.
func (m *ProcessModule) parseProcessOutput(ctx context.Context, output string, findings chan<- *model.Finding) error {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pid := parsePID(fields[0])
		command := strings.Join(fields[1:], " ")

		name, algo, ok := identifyCryptoProcess(command)
		if !ok {
			continue
		}

		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  name,
			Algorithm: algo,
			Purpose:   "Running crypto process",
		}
		crypto.ClassifyCryptoAsset(asset)

		select {
		case findings <- &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 1,
			Source: model.FindingSource{
				Type: "process",
				PID:  pid,
				Path: command,
			},
			CryptoAsset: asset,
			Confidence:  0.70,
			Module:      "processes",
			Timestamp:   time.Now(),
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// identifyCryptoProcess checks if a command line matches a known crypto process.
// Matching is done against the command basename to reduce false positives.
// Order matters: more specific patterns (e.g. "ssh-agent") must appear before broader ones (e.g. "ssh").
func identifyCryptoProcess(command string) (name, algorithm string, ok bool) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "", "", false
	}
	cmdBase := strings.ToLower(filepath.Base(fields[0]))

	for _, kw := range cryptoProcessKeywords {
		if strings.Contains(cmdBase, kw.keyword) {
			return kw.function, kw.algorithm, true
		}
	}
	return "", "", false
}

// parsePID converts a string PID to int, returning 0 on failure.
func parsePID(s string) int {
	pid, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return pid
}
