//go:build linux && integration

package ebpftrace

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestRun_ObservesOpenSSLDigest spawns an openssl subprocess computing sha256
// and asserts the trace captures at least one AES or SHA-256 aggregate.
// Skipped when not root or when BTF is unavailable.
func TestRun_ObservesOpenSSLDigest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (or CAP_BPF)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("BTF not available")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl binary not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start trace in goroutine; run openssl in the middle.
	result := make(chan *Outcome, 1)
	errCh := make(chan error, 1)
	go func() {
		out, err := Run(ctx, Options{Window: 10 * time.Second})
		if err != nil {
			errCh <- err
			return
		}
		result <- out
	}()

	time.Sleep(2 * time.Second) // give probes time to attach
	cmd := exec.Command("openssl", "dgst", "-sha256", "/etc/hostname")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Run(); err != nil {
		t.Fatalf("openssl run: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("Run: %v", err)
	case out := <-result:
		found := false
		for _, agg := range out.Aggregates {
			if agg.Algorithm == "SHA-256" || agg.Family == "SHA" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no SHA-256 finding in %d aggregates", len(out.Aggregates))
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for trace result")
	}
}
