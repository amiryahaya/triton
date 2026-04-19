package manage_enrol

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BundleInputs is the set of values needed to build a Manage enrolment
// bundle. Crucially, the private key is NOT part of the bundle — Manage
// generated its keypair locally and only sent the public key over the
// wire for signing. The Report server never holds Manage's private key.
type BundleInputs struct {
	ManageInstanceID uuid.UUID
	ReportURL        string // the public URL Manage/agents POST scans to
	TenantID         string // tenant attribution stamp (empty in single-tenant)
	ClientCertPEM    []byte // leaf just minted by engine CA
	CACertPEM        []byte // Report's engine CA cert (trust anchor for Manage)
}

// BuildBundle produces a gzip-compressed tar archive containing:
//
//	client.crt    the signed manage: leaf (mode 0644)
//	ca.crt        Report's engine CA cert (mode 0644)
//	config.yaml   manage_instance_id, report_url, tenant_id (mode 0644)
//
// Manage unpacks this alongside the private key it generated locally, and
// the drain goroutine uses the tuple (client.crt + local key + ca.crt) as
// its mTLS bundle when POSTing scan results to report_url.
func BuildBundle(in BundleInputs) ([]byte, error) {
	if in.ManageInstanceID == uuid.Nil {
		return nil, fmt.Errorf("manage_instance_id required")
	}
	if in.ReportURL == "" {
		return nil, fmt.Errorf("report_url required")
	}
	if len(in.ClientCertPEM) == 0 {
		return nil, fmt.Errorf("client_cert_pem required")
	}
	if len(in.CACertPEM) == 0 {
		return nil, fmt.Errorf("ca_cert_pem required")
	}

	// Minimal hand-rolled YAML so we don't pull in gopkg.in/yaml.v3 just
	// for three fields. Keys match the Manage-side reader in
	// handlers_setup.go's auto-enrol flow.
	configYAML := fmt.Sprintf("manage_instance_id: %s\nreport_url: %s\ntenant_id: %s\n",
		in.ManageInstanceID.String(), in.ReportURL, in.TenantID)

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

	if err := add("client.crt", in.ClientCertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := add("ca.crt", in.CACertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := add("config.yaml", []byte(configYAML), 0o644); err != nil {
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
