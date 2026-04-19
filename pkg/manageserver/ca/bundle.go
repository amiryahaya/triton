package ca

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BundleInputs is the set of values required to build an agent
// onboarding bundle. AgentID, AgentKeyPEM, AgentCertPEM and
// ManageCACertPEM come from the enrol handler (right after SignAgentCert);
// ManageGatewayURL + PhoneHomeInterval come from the server config. The
// bundle is opaque to the agent at build time — the agent reads its
// config.yaml to discover where + how often to phone home.
type BundleInputs struct {
	AgentID           uuid.UUID
	ManageGatewayURL  string
	AgentKeyPEM       []byte
	AgentCertPEM      []byte
	ManageCACertPEM   []byte
	PhoneHomeInterval time.Duration
}

// BuildBundle produces a gzip-compressed tar archive containing:
//
//	client.crt     the agent's leaf certificate PEM (mode 0644)
//	client.key     the agent's private key PEM (mode 0400 — secret)
//	ca.crt         Manage's CA certificate PEM (mode 0644 — trust anchor)
//	config.yaml    phone-home URL + agent_id + cadence (mode 0644)
//
// Forked from pkg/server/engine/bundle.go. The engine variant includes
// an engine.json BundleManifest for the Report Server's first-seen
// guard; the agent bundle deliberately omits that because the Manage
// gateway's mTLS handshake already identifies the agent by cert CN.
func BuildBundle(in BundleInputs) ([]byte, error) {
	if in.PhoneHomeInterval <= 0 {
		return nil, fmt.Errorf("phone_home_interval must be positive, got %v", in.PhoneHomeInterval)
	}
	if in.ManageGatewayURL == "" {
		return nil, fmt.Errorf("manage_gateway_url is required")
	}

	// Plain-text YAML assembled by string concat rather than via
	// gopkg.in/yaml.v3 so we keep the bundle parser-agnostic on the
	// agent side (the agent can read this with a line-based YAML scanner
	// or a full parser).
	config := fmt.Sprintf(
		"manage_gateway_url: %s\nagent_id: %s\nphone_home_interval: %s\n",
		in.ManageGatewayURL, in.AgentID.String(), in.PhoneHomeInterval.String(),
	)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	add := func(name string, data []byte, mode int64) error {
		if err := tw.WriteHeader(&tar.Header{
			Name:    name,
			Size:    int64(len(data)),
			Mode:    mode,
			ModTime: time.Now().UTC(),
		}); err != nil {
			return fmt.Errorf("write tar header %s: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("write tar body %s: %w", name, err)
		}
		return nil
	}

	if err := add("client.crt", in.AgentCertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := add("client.key", in.AgentKeyPEM, 0o400); err != nil {
		return nil, err
	}
	if err := add("ca.crt", in.ManageCACertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := add("config.yaml", []byte(config), 0o644); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}
	return buf.Bytes(), nil
}
