// Package juniper implements the Juniper Junos agentless scanner adapter.
package juniper

import (
	"encoding/xml"
	"fmt"

	"github.com/amiryahaya/triton/pkg/model"
)

// sshConfigDoc mirrors <data><configuration><system><services><ssh>.
type sshConfigDoc struct {
	XMLName       xml.Name `xml:"data"`
	Configuration struct {
		System struct {
			Services struct {
				SSH struct {
					Ciphers     []string `xml:"ciphers"`
					MACs        []string `xml:"macs"`
					KeyExchange []string `xml:"key-exchange"`
				} `xml:"ssh"`
			} `xml:"services"`
		} `xml:"system"`
	} `xml:"configuration"`
}

// parseSSHConfig extracts SSH algorithm configs from NETCONF get-config output.
func parseSSHConfig(hostname string, data []byte) ([]*model.Finding, error) {
	var doc sshConfigDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse ssh config: %w", err)
	}

	var findings []*model.Finding
	ssh := doc.Configuration.System.Services.SSH

	for _, c := range ssh.Ciphers {
		findings = append(findings, buildFinding(hostname, "juniper-ssh-cipher", "ssh-server-cipher", c))
	}
	for _, m := range ssh.MACs {
		findings = append(findings, buildFinding(hostname, "juniper-ssh-mac", "ssh-server-mac", m))
	}
	for _, k := range ssh.KeyExchange {
		findings = append(findings, buildFinding(hostname, "juniper-ssh-kex", "ssh-server-kex", k))
	}
	return findings, nil
}

// buildFinding creates a Finding with the standard Juniper shape.
// Uses the same field layout as Cisco parsers — see
// pkg/scanner/netadapter/cisco/parsers.go buildSSHFinding for reference.
func buildFinding(hostname, module, purpose, algorithm string) *model.Finding {
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

// parseIKEConfig extracts IKE proposals. Stub for MVP.
func parseIKEConfig(hostname string, data []byte) ([]*model.Finding, error) {
	return nil, nil
}

// parseIPsecConfig extracts IPsec proposals. Stub for MVP.
func parseIPsecConfig(hostname string, data []byte) ([]*model.Finding, error) {
	return nil, nil
}

// parsePKIConfig extracts PKI certificate trustpoints. Stub for MVP.
func parsePKIConfig(hostname string, data []byte) ([]*model.Finding, error) {
	return nil, nil
}

// parseSNMPConfig extracts SNMP auth/priv settings. Stub for MVP.
func parseSNMPConfig(hostname string, data []byte) ([]*model.Finding, error) {
	return nil, nil
}
