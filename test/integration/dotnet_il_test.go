//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// TestDotNetIL_EndToEnd builds a minimal valid .NET assembly in a temp dir,
// runs the dotnet_il module against it, and asserts at least one classified
// crypto finding is emitted with the .NET language tag.
func TestDotNetIL_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	asm := scanner.BuildDotNetTestAssembly(t)
	if err := os.WriteFile(filepath.Join(dir, "Crypto.dll"), asm, 0o644); err != nil {
		t.Fatal(err)
	}

	mod := scanner.NewDotNetILModule(&scannerconfig.Config{MaxFileSize: 16 << 20})
	ch := make(chan *model.Finding, 64)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		_ = mod.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 2}, ch)
		close(ch)
	}()

	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one finding from dotnet_il scan")
	}
	for _, f := range got {
		if f.Module != "dotnet_il" {
			t.Errorf("Module = %q, want dotnet_il", f.Module)
		}
		if f.CryptoAsset == nil || f.CryptoAsset.Language != ".NET" {
			t.Errorf("Language = %q, want .NET", f.CryptoAsset.Language)
		}
	}
}
