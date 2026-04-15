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
	algos := map[string]string{} // algorithm → status
	for _, f := range got {
		if f.Module != "dotnet_il" {
			t.Errorf("Module = %q, want dotnet_il", f.Module)
		}
		if f.CryptoAsset == nil {
			t.Error("nil CryptoAsset")
			continue
		}
		if f.CryptoAsset.Language != ".NET" {
			t.Errorf("Language = %q, want .NET", f.CryptoAsset.Language)
		}
		if f.Confidence != 0.90 {
			t.Errorf("Confidence = %v, want 0.90", f.Confidence)
		}
		if f.Source.DetectionMethod != "dotnet-il" {
			t.Errorf("DetectionMethod = %q, want dotnet-il", f.Source.DetectionMethod)
		}
		algos[f.CryptoAsset.Algorithm] = f.CryptoAsset.PQCStatus
	}
	// Fixture has AesManaged, MD5CryptoServiceProvider, BCRYPT_RSA_ALGORITHM.
	wantAlgos := map[string]string{
		"AES": "TRANSITIONAL",
		"MD5": "UNSAFE",
		"RSA": "TRANSITIONAL",
	}
	for algo, wantStatus := range wantAlgos {
		if got, ok := algos[algo]; !ok {
			t.Errorf("missing %s finding", algo)
		} else if got != wantStatus {
			t.Errorf("%s status = %q, want %q", algo, got, wantStatus)
		}
	}
}
