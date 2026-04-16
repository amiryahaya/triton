//go:build linux

package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestUEFIModule_Linux_EmitsFindings(t *testing.T) {
	varRoot, _ := filepath.Abs("internal/uefivars/testdata/efivars")
	cfg := &scannerconfig.Config{UEFIVarRoot: varRoot}
	m := NewUEFIModule(cfg)
	ch := make(chan *model.Finding, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem}, ch)
		close(ch)
	}()

	var got []*model.Finding
	for f := range ch {
		got = append(got, f)
	}
	if len(got) < 4 {
		t.Fatalf("expected >= 4 findings (2 state + >= 1 cert + 1 dbx), got %d", len(got))
	}
	for _, f := range got {
		if f.Module != "uefi" {
			t.Errorf("Module = %q, want uefi", f.Module)
		}
	}

	// Assert SecureBoot state finding present.
	foundSB := false
	for _, f := range got {
		if f.Source.DetectionMethod == "efivars-state" && strings.Contains(f.Source.Evidence, "SecureBoot=") {
			foundSB = true
		}
	}
	if !foundSB {
		t.Error("no SecureBoot state finding emitted")
	}

	// Assert dbx finding with missing CVE (fixture has BlackLotus hash but missing BootHole + Baton Drop).
	foundDbx := false
	for _, f := range got {
		if f.Source.DetectionMethod == "efivars-dbx" {
			foundDbx = true
			if len(f.CryptoAsset.QualityWarnings) == 0 {
				t.Error("dbx finding has no quality warnings (expected missing CVE revocations)")
			}
		}
	}
	if !foundDbx {
		t.Error("no dbx finding emitted")
	}
}

func TestUEFIModule_Linux_NoEFISilent(t *testing.T) {
	cfg := &scannerconfig.Config{UEFIVarRoot: t.TempDir()}
	m := NewUEFIModule(cfg)
	ch := make(chan *model.Finding, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Scan(ctx, model.ScanTarget{}, ch); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	close(ch)
	for f := range ch {
		t.Errorf("unexpected finding: %+v", f)
	}
}
