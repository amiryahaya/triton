//go:build integration && linux

package integration

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// TestEBPFTrace_ObservesOpenSSLDigest runs the full ebpf_trace scanner module
// end-to-end: it spawns an `openssl dgst -sha256` subprocess during the trace
// window and asserts the module emits at least one SHA-256 (or SHA-family)
// finding tagged as an eBPF uprobe detection. Skipped on non-root hosts,
// hosts without BTF, or hosts without an openssl binary.
func TestEBPFTrace_ObservesOpenSSLDigest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (or CAP_BPF)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("BTF not available at /sys/kernel/btf/vmlinux")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl binary not found")
	}

	cfg := &scannerconfig.Config{
		EBPFWindow:      8 * time.Second,
		EBPFSkipUprobes: false,
		EBPFSkipKprobes: false,
	}
	mod := scanner.NewEBPFTraceModule(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ch := make(chan *model.Finding, 128)
	done := make(chan error, 1)
	go func() {
		done <- mod.Scan(ctx, model.ScanTarget{Type: model.TargetProcess}, ch)
		close(ch)
	}()

	// Give probes time to attach before spawning the target.
	time.Sleep(2 * time.Second)
	cmd := exec.Command("openssl", "dgst", "-sha256", "/etc/hostname")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Run(); err != nil {
		t.Fatalf("openssl run: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("ebpf_trace Scan returned error: %v", err)
	}

	var findings []*model.Finding
	for f := range ch {
		findings = append(findings, f)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from ebpf_trace")
	}

	foundSHA := false
	for _, f := range findings {
		if f.Module != "ebpf_trace" {
			t.Errorf("Module = %q, want ebpf_trace", f.Module)
		}
		if f.CryptoAsset == nil {
			continue
		}
		algo := f.CryptoAsset.Algorithm
		if algo == "SHA-256" || algo == "SHA256" || algo == "SHA-2" {
			if f.Source.DetectionMethod != "ebpf-uprobe" && f.Source.DetectionMethod != "ebpf-kprobe" {
				t.Errorf("DetectionMethod = %q, want ebpf-uprobe or ebpf-kprobe", f.Source.DetectionMethod)
			}
			foundSHA = true
		}
	}
	if !foundSHA {
		t.Errorf("no SHA-256 finding observed in %d findings from ebpf_trace", len(findings))
	}
}
