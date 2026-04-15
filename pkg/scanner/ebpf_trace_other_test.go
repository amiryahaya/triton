//go:build !linux

package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestEBPFTraceModule_NonLinuxSkippedFinding(t *testing.T) {
	m := NewEBPFTraceModule(&scannerconfig.Config{})
	ch := make(chan *model.Finding, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Scan(ctx, model.ScanTarget{Type: model.TargetProcess}, ch); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	close(ch)
	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	f := got[0]
	if f.Module != "ebpf_trace" {
		t.Errorf("Module = %q, want ebpf_trace", f.Module)
	}
	if f.Source.DetectionMethod != "ebpf-skipped" {
		t.Errorf("DetectionMethod = %q, want ebpf-skipped", f.Source.DetectionMethod)
	}
	if f.Confidence != 0.0 {
		t.Errorf("Confidence = %v, want 0.0", f.Confidence)
	}
}
