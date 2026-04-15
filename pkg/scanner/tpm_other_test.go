//go:build !linux

package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestTPMModule_NonLinuxSkippedFinding(t *testing.T) {
	m := NewTPMModule(&scannerconfig.Config{})
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
	f := got[0]
	if f.Module != "tpm" {
		t.Errorf("Module = %q, want tpm", f.Module)
	}
	if f.Source.DetectionMethod != "tpm-skipped" {
		t.Errorf("DetectionMethod = %q, want tpm-skipped", f.Source.DetectionMethod)
	}
	if f.Confidence != 0.0 {
		t.Errorf("Confidence = %v, want 0.0", f.Confidence)
	}
}
