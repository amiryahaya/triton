package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestEBPFTraceModule_Identity(t *testing.T) {
	m := NewEBPFTraceModule(&scannerconfig.Config{})
	if m.Name() != "ebpf_trace" {
		t.Errorf("Name = %q, want ebpf_trace", m.Name())
	}
	if m.Category() != model.CategoryActiveRuntime {
		t.Errorf("Category = %v, want CategoryActiveRuntime", m.Category())
	}
	if m.ScanTargetType() != model.TargetProcess {
		t.Errorf("ScanTargetType = %v, want TargetProcess", m.ScanTargetType())
	}
}
