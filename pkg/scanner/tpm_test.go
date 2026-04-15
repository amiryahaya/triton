package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestTPMModule_Identity(t *testing.T) {
	m := NewTPMModule(&scannerconfig.Config{})
	if m.Name() != "tpm" {
		t.Errorf("Name = %q, want tpm", m.Name())
	}
	if m.Category() != model.CategoryPassiveFile {
		t.Errorf("Category = %v, want CategoryPassiveFile", m.Category())
	}
	if m.ScanTargetType() != model.TargetFilesystem {
		t.Errorf("ScanTargetType = %v, want TargetFilesystem", m.ScanTargetType())
	}
}
