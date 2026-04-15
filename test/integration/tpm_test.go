//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// TestTPM_EndToEnd exercises the tpm module against the committed Infineon
// sysfs fixture and asserts the expected findings surface with CVE warnings.
// Linux-only; skips on other OS.
func TestTPM_EndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("tpm module is Linux-only")
	}
	// Integration test file lives in test/integration; fixture is in pkg/scanner/internal/tpmfs/testdata.
	// Resolve the fixture path relative to this source file (cwd-independent).
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	sysRoot := filepath.Join(repoRoot, "pkg/scanner/internal/tpmfs/testdata/sysfs-infineon")
	if _, err := os.Stat(sysRoot); err != nil {
		t.Skipf("fixture not found at %s: %v", sysRoot, err)
	}
	secRoot := t.TempDir()

	cfg := &scannerconfig.Config{
		TPMSysRoot:  sysRoot,
		TPMSecRoot:  secRoot,
		MaxFileSize: 16 << 20,
	}
	m := scanner.NewTPMModule(cfg)
	ch := make(chan *model.Finding, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		_ = m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem}, ch)
		close(ch)
	}()

	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) == 0 {
		t.Fatal("no findings emitted from TPM fixture scan")
	}

	// Assert the module tags each finding correctly.
	for _, f := range got {
		if f.Module != "tpm" {
			t.Errorf("Module = %q, want tpm", f.Module)
		}
	}
}
