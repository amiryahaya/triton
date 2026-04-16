//go:build !linux

package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestUEFIModule_NonLinuxSkippedFinding(t *testing.T) {
	m := NewUEFIModule(&scannerconfig.Config{})
	ch := make(chan *model.Finding, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem}, ch); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	close(ch)
	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
		return
	}
	if got[0].Module != "uefi" {
		t.Errorf("Module = %q, want uefi", got[0].Module)
	}
	if got[0].Source.DetectionMethod != "uefi-skipped" {
		t.Errorf("DetectionMethod = %q, want uefi-skipped", got[0].Source.DetectionMethod)
	}
}
