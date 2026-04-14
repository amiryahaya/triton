package scanner

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
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
