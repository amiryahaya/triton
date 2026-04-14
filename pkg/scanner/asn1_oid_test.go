package scanner

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestASN1OIDModule_BasicInterface(t *testing.T) {
	cfg := &scannerconfig.Config{}
	m := NewASN1OIDModule(cfg)

	if m.Name() != "asn1_oid" {
		t.Errorf("Name: got %q, want asn1_oid", m.Name())
	}
	if m.Category() != model.CategoryPassiveFile {
		t.Errorf("Category: got %v, want CategoryPassiveFile", m.Category())
	}
}

func TestASN1OIDModule_ScansSelfExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("self-exec scan requires POSIX")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &scannerconfig.Config{}
	m := NewASN1OIDModule(cfg)

	target := model.ScanTarget{
		Type:  model.TargetFilesystem,
		Value: exe,
	}
	findings := make(chan *model.Finding, 100)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()

	err = m.Scan(context.Background(), target, findings)
	close(findings)
	<-done

	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// The Go toolchain embeds Ed25519 and TLS-related OIDs in the binary.
	// We don't assert specific findings (brittle) — just that the scan
	// completes and may or may not produce findings without panicking.
	t.Logf("self-scan produced %d findings", len(collected))
}

// Note: system-dir skip (/proc, /sys, .git) is now enforced by the shared
// walkTarget helper via the default exclude patterns in
// internal/scannerconfig. Covered by walker tests and by
// TestDefaultExcludePatterns in the config test suite.

func TestBuildFinding_CompositeOIDSetsHybrid(t *testing.T) {
	// ML-DSA-65-ECDSA-P384 is a composite signature OID
	entry, ok := crypto.LookupOID("2.16.840.1.114027.80.8.1.9")
	if !ok {
		t.Fatal("expected ML-DSA-65-ECDSA-P384 in registry")
	}
	c := crypto.ClassifiedOID{
		FoundOID: crypto.FoundOID{OID: "2.16.840.1.114027.80.8.1.9"},
		Entry:    entry,
	}
	f := buildFinding("/some/binary", ".rodata", c)
	if f.CryptoAsset == nil {
		t.Fatal("nil CryptoAsset")
	}
	if !f.CryptoAsset.IsHybrid {
		t.Error("expected IsHybrid=true for composite OID")
	}
	if len(f.CryptoAsset.ComponentAlgorithms) != 2 {
		t.Errorf("expected 2 ComponentAlgorithms, got %v", f.CryptoAsset.ComponentAlgorithms)
	}
}

func TestBuildFinding_NonCompositeNoHybrid(t *testing.T) {
	entry, ok := crypto.LookupOID("1.2.840.113549.1.1.11") // SHA256-RSA
	if !ok {
		t.Fatal("expected SHA256-RSA in registry")
	}
	c := crypto.ClassifiedOID{
		FoundOID: crypto.FoundOID{OID: "1.2.840.113549.1.1.11"},
		Entry:    entry,
	}
	f := buildFinding("/some/binary", ".rodata", c)
	if f.CryptoAsset.IsHybrid {
		t.Error("non-composite OID should not be marked hybrid")
	}
}
