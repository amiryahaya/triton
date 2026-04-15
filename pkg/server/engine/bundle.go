package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BundleInputs is the set of values required to build an engine
// onboarding bundle. EngineID and OrgID must be valid UUIDs; PortalURL
// is the report-server base URL the engine will phone home to; the
// three PEM-encoded byte slices are the engine's private key, its
// signed leaf certificate, and the issuing org-CA certificate.
type BundleInputs struct {
	EngineID      uuid.UUID
	OrgID         uuid.UUID
	Label         string
	PortalURL     string
	EngineKeyPEM  []byte
	EngineCertPEM []byte
	CACertPEM     []byte
}

// bundleVersion is the schema version embedded in engine.json. Bump
// when BundleManifest fields change in a way the engine binary must
// detect.
const bundleVersion = 1

// BuildBundle produces a gzip-compressed tar archive containing:
//
//	engine.json      BundleManifest (pretty-printed JSON, mode 0644)
//	engine.key       engine Ed25519 private key PEM (mode 0400)
//	engine.crt       leaf certificate signed by the org engine-CA (0644)
//	portal-ca.crt    org engine-CA certificate (0644)
//
// NOTE: manifest.sig is intentionally omitted in the MVP. Bundle
// integrity in transit is assumed from out-of-band delivery. Bundle
// leakage is mitigated by the single-use first-seen guard in the store
// (see Store.RecordFirstSeen).
func BuildBundle(in BundleInputs) ([]byte, error) {
	manifest, err := json.MarshalIndent(BundleManifest{
		EngineID:        in.EngineID,
		OrgID:           in.OrgID,
		Label:           in.Label,
		ReportServerURL: in.PortalURL,
		IssuedAt:        time.Now().UTC(),
		BundleVersion:   bundleVersion,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

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

	if err := add("engine.json", manifest, 0o644); err != nil {
		return nil, err
	}
	if err := add("engine.key", in.EngineKeyPEM, 0o400); err != nil {
		return nil, err
	}
	if err := add("engine.crt", in.EngineCertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := add("portal-ca.crt", in.CACertPEM, 0o644); err != nil {
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
