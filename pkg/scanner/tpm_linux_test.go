//go:build linux

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestTPMModule_Linux_CorruptEventLogEmitsSkipped(t *testing.T) {
	sysRoot, _ := filepath.Abs("internal/tpmfs/testdata/sysfs-infineon")
	if _, err := os.Stat(sysRoot); err != nil {
		t.Skipf("fixture not found: %v", err)
	}
	secRoot := t.TempDir()
	// Write garbage to the event log path.
	tpmLogDir := filepath.Join(secRoot, "tpm0")
	if err := os.MkdirAll(tpmLogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tpmLogDir, "binary_bios_measurements"),
		[]byte("this is not a valid TCG event log"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &scannerconfig.Config{TPMSysRoot: sysRoot, TPMSecRoot: secRoot}
	m := NewTPMModule(cfg)
	ch := make(chan *model.Finding, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		_ = m.Scan(ctx, model.ScanTarget{}, ch)
		close(ch)
	}()

	sawSkipped := false
	for f := range ch {
		if f.Source.DetectionMethod == "tpm-skipped" && strings.Contains(f.Source.Evidence, "corrupt event log") {
			sawSkipped = true
		}
	}
	if !sawSkipped {
		t.Error("expected tpm-skipped finding for corrupt event log")
	}
}

// TestTPMModule_Linux_EmitsDeviceFinding exercises the full scan pipeline
// against the committed sysfs-infineon fixture. Runs on Linux only.
func TestTPMModule_Linux_EmitsDeviceFinding(t *testing.T) {
	sysRoot, _ := filepath.Abs("internal/tpmfs/testdata/sysfs-infineon")
	if _, err := os.Stat(sysRoot); err != nil {
		t.Skipf("fixture not found: %v", err)
	}
	secRoot := t.TempDir()

	cfg := &scannerconfig.Config{
		TPMSysRoot: sysRoot,
		TPMSecRoot: secRoot,
	}
	m := NewTPMModule(cfg)
	ch := make(chan *model.Finding, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem}, ch)
		close(ch)
	}()

	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) < 1 {
		t.Fatalf("len(got) = %d, want >= 1 (device finding)", len(got))
		return
	}

	var deviceFinding *model.Finding
	for _, f := range got {
		if f.Source.DetectionMethod == "sysfs" && f.CryptoAsset != nil && f.CryptoAsset.Function == "Hardware root of trust" {
			deviceFinding = f
			break
		}
	}
	if deviceFinding == nil {
		t.Fatal("no device finding emitted")
		return
	}
	if deviceFinding.CryptoAsset.Library != "Infineon TPM firmware" {
		t.Errorf("Library = %q, want 'Infineon TPM firmware'", deviceFinding.CryptoAsset.Library)
	}
	// Firmware 4.32.1.2 <= 4.33.4 → ROCA CVE should fire.
	foundROCA := false
	for _, qw := range deviceFinding.CryptoAsset.QualityWarnings {
		if qw.CVE == "CVE-2017-15361" {
			foundROCA = true
		}
	}
	if !foundROCA {
		t.Errorf("expected CVE-2017-15361 (ROCA) warning on Infineon firmware 4.32.1.2; got %+v", deviceFinding.CryptoAsset.QualityWarnings)
	}
}

// TestTPMModule_Linux_NoTPMSilent exercises the empty-directory path: no
// /sys/class/tpm entries → no findings.
func TestTPMModule_Linux_NoTPMSilent(t *testing.T) {
	sysRoot := t.TempDir() // empty directory — no tpm* subdirs
	secRoot := t.TempDir()
	cfg := &scannerconfig.Config{TPMSysRoot: sysRoot, TPMSecRoot: secRoot}
	m := NewTPMModule(cfg)
	ch := make(chan *model.Finding, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Scan(ctx, model.ScanTarget{}, ch); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	close(ch)
	for f := range ch {
		t.Errorf("unexpected finding: %+v", f)
	}
}
