package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestDotNetILModule_NameAndCategory(t *testing.T) {
	m := NewDotNetILModule(&scannerconfig.Config{})
	if m.Name() != "dotnet_il" {
		t.Errorf("Name = %q, want dotnet_il", m.Name())
	}
	if m.Category() != model.CategoryPassiveFile {
		t.Errorf("Category = %v, want CategoryPassiveFile", m.Category())
	}
	if m.ScanTargetType() != model.TargetFilesystem {
		t.Errorf("ScanTargetType = %v, want TargetFilesystem", m.ScanTargetType())
	}
}

func TestDotNetILModule_SkipsNonPEFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fake.dll"), []byte("not a PE"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewDotNetILModule(&scannerconfig.Config{MaxFileSize: 1 << 20})
	ch := make(chan *model.Finding, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 2}, ch); err != nil {
		t.Errorf("Scan: %v", err)
	}
	close(ch)
	for f := range ch {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestDotNetILModule_DedupAcrossHostAndBundle(t *testing.T) {
	// Verify that classifyAndEmit shares the seen map across host + bundle paths.
	// Synthesise an Assembly with the same algorithm in both lists; expect
	// only ONE finding emitted via the shared seen map.
	t.Skip("covered by integration test once bundle-mode integration lands")
}
