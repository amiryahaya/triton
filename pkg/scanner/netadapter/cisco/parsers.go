package cisco

import (
	"regexp"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// parseShowIPSSH extracts SSH algorithm configurations from 'show ip ssh' output.
func parseShowIPSSH(hostname, output string) []*model.Finding {
	var findings []*model.Finding

	sections := []struct {
		pattern string
		purpose string
		module  string
	}{
		{`Encryption Algorithms:\s*(.+)`, "ssh-server-cipher", "cisco-ssh-cipher"},
		{`MAC Algorithms:\s*(.+)`, "ssh-server-mac", "cisco-ssh-mac"},
		{`KEX Algorithms:\s*(.+)`, "ssh-server-kex", "cisco-ssh-kex"},
		{`Hostkey Algorithms:\s*(.+)`, "ssh-server-hostkey", "cisco-ssh-hostkey"},
	}

	for _, s := range sections {
		for _, algo := range extractList(output, s.pattern) {
			findings = append(findings, buildSSHFinding(hostname, s.module, s.purpose, algo))
		}
	}

	return findings
}

// buildSSHFinding creates a Finding for a single SSH algorithm.
func buildSSHFinding(hostname, module, purpose, algorithm string) *model.Finding {
	return &model.Finding{
		Source: model.FindingSource{
			Type:            "network-device",
			Path:            hostname,
			DetectionMethod: "configuration",
		},
		Module:     module,
		Confidence: 1.0,
		CryptoAsset: &model.CryptoAsset{
			Algorithm: algorithm,
			Purpose:   purpose,
		},
	}
}

// parseShowCryptoPKI extracts certificate trustpoints. Stub for MVP.
func parseShowCryptoPKI(hostname, output string) []*model.Finding {
	return nil
}

// parseShowIsakmpPolicy extracts IKE proposals. Stub for MVP.
func parseShowIsakmpPolicy(hostname, output string) []*model.Finding {
	return nil
}

// parseShowCryptoIPsec extracts IPsec SA parameters. Stub for MVP.
func parseShowCryptoIPsec(hostname, output string) []*model.Finding {
	return nil
}

// parseShowSNMP extracts SNMP user auth/priv algorithms. Stub for MVP.
func parseShowSNMP(hostname, output string) []*model.Finding {
	return nil
}

// extractList parses "Label: item1,item2,item3" lines using the provided pattern.
func extractList(output, pattern string) []string {
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(output)
	if len(m) < 2 {
		return nil
	}
	var out []string
	for _, s := range strings.Split(m[1], ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
