//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	byMethod := map[string][]*model.Finding{}
	for _, f := range got {
		byMethod[f.Source.DetectionMethod] = append(byMethod[f.Source.DetectionMethod], f)
	}

	// 1. Device finding via "sysfs" with Function="Hardware root of trust"
	var device *model.Finding
	for _, f := range byMethod["sysfs"] {
		if f.CryptoAsset != nil && f.CryptoAsset.Function == "Hardware root of trust" {
			device = f
			break
		}
	}
	if device == nil {
		t.Fatal("no device finding emitted")
	}
	// Assert Infineon + ROCA.
	if !strings.Contains(device.CryptoAsset.Library, "Infineon") {
		t.Errorf("Library = %q, want contains Infineon", device.CryptoAsset.Library)
	}
	foundROCA := false
	for _, qw := range device.CryptoAsset.QualityWarnings {
		if qw.CVE == "CVE-2017-15361" {
			foundROCA = true
		}
	}
	if !foundROCA {
		t.Error("expected CVE-2017-15361 on Infineon firmware 4.32.1.2")
	}
	// Assert TPM 2.0 spec advisory CVEs fire.
	foundSpec := 0
	for _, qw := range device.CryptoAsset.QualityWarnings {
		if qw.CVE == "CVE-2023-1017" || qw.CVE == "CVE-2023-1018" {
			foundSpec++
		}
	}
	if foundSpec != 2 {
		t.Errorf("expected 2 TPM 2.0 spec CVEs (CVE-2023-1017/1018); got %d", foundSpec)
	}
	// EK cert assertion intentionally omitted: the sysfs-infineon fixture
	// doesn't ship an endorsement_key_cert file (ROCA-era TPMs commonly
	// store the cert in NVRAM, not exposed via sysfs).
}
