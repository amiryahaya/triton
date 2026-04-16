package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestUEFIModule_Identity(t *testing.T) {
	m := NewUEFIModule(&scannerconfig.Config{})
	if m.Name() != "uefi" {
		t.Errorf("Name = %q, want uefi", m.Name())
	}
	if m.Category() != model.CategoryPassiveFile {
		t.Errorf("Category = %v, want CategoryPassiveFile", m.Category())
	}
	if m.ScanTargetType() != model.TargetFilesystem {
		t.Errorf("ScanTargetType = %v, want TargetFilesystem", m.ScanTargetType())
	}
}
