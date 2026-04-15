package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/uuid"
)

func readBundleEntries(t *testing.T, gzData []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		buf, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = buf
	}
	return out
}

func TestBuildBundle_ContainsExpectedFiles(t *testing.T) {
	gzData, err := BuildBundle(BundleInputs{
		EngineID:      uuid.New(),
		OrgID:         uuid.New(),
		Label:         "test-engine",
		PortalURL:     "https://portal.example.com",
		EngineKeyPEM:  []byte("KEY"),
		EngineCertPEM: []byte("CRT"),
		CACertPEM:     []byte("CA"),
	})
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	entries := readBundleEntries(t, gzData)
	for _, name := range []string{"engine.json", "engine.key", "engine.crt", "portal-ca.crt"} {
		if _, ok := entries[name]; !ok {
			t.Errorf("bundle missing %s; got %v", name, keys(entries))
		}
	}
	if string(entries["engine.key"]) != "KEY" {
		t.Errorf("engine.key mismatch: %q", entries["engine.key"])
	}
	if string(entries["engine.crt"]) != "CRT" {
		t.Errorf("engine.crt mismatch: %q", entries["engine.crt"])
	}
	if string(entries["portal-ca.crt"]) != "CA" {
		t.Errorf("portal-ca.crt mismatch: %q", entries["portal-ca.crt"])
	}
}

func TestBuildBundle_EngineJSONHasExpectedFields(t *testing.T) {
	engineID := uuid.New()
	orgID := uuid.New()
	gzData, err := BuildBundle(BundleInputs{
		EngineID:      engineID,
		OrgID:         orgID,
		Label:         "alpha",
		PortalURL:     "https://portal.example.com",
		EngineKeyPEM:  []byte("K"),
		EngineCertPEM: []byte("C"),
		CACertPEM:     []byte("A"),
	})
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	entries := readBundleEntries(t, gzData)
	var m BundleManifest
	if err := json.Unmarshal(entries["engine.json"], &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if m.EngineID != engineID {
		t.Errorf("EngineID: got %s want %s", m.EngineID, engineID)
	}
	if m.OrgID != orgID {
		t.Errorf("OrgID: got %s want %s", m.OrgID, orgID)
	}
	if m.Label != "alpha" {
		t.Errorf("Label: got %q want alpha", m.Label)
	}
	if m.ReportServerURL != "https://portal.example.com" {
		t.Errorf("ReportServerURL: got %q", m.ReportServerURL)
	}
	if m.BundleVersion != bundleVersion {
		t.Errorf("BundleVersion: got %d want %d", m.BundleVersion, bundleVersion)
	}
	if m.IssuedAt.IsZero() {
		t.Errorf("IssuedAt is zero")
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
