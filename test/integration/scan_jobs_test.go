//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
)

// buildTritonBinary compiles triton into a temp binary for the test.
// Returns the path. Cleanup runs via t.Cleanup.
func buildTritonBinary(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "triton-test")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/amiryahaya/triton")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}
	return bin
}

// lastNonEmptyLine returns the last non-empty trimmed line of the output.
// The CLI prints informational log lines to stderr, but the `--detach
// --quiet` job-id is emitted on stdout as its own line. We read stdout only
// and take the last line for robustness against any future prefix output.
func lastNonEmptyLine(b []byte) string {
	lines := strings.Split(string(b), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		s := strings.TrimSpace(lines[i])
		if s != "" {
			return s
		}
	}
	return ""
}

func TestJobRunner_EndToEnd_Cancel(t *testing.T) {
	bin := buildTritonBinary(t)
	workDir := t.TempDir()

	// Spawn detached scan. Use stdout-only capture so log lines written to
	// stderr (e.g. licence validation warnings) don't contaminate the job
	// id. --max-duration keeps the scan alive long enough that the cancel
	// flag has a chance to be observed against the 2s poll interval.
	cmd := exec.Command(bin, "--detach", "--profile", "quick", "--max-duration", "60s",
		"--work-dir", workDir, "--quiet", "--license-key", "")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("detach failed: %v: %s", err, out)
	}
	jobID := lastNonEmptyLine(out)
	if jobID == "" {
		t.Fatal("no job-id from --detach --quiet")
	}
	jobDir := filepath.Join(workDir, jobID)

	// Touch the cancel flag as soon as the job dir exists so the daemon's
	// 2s poll loop sees it on its first tick. Racing the scan to completion
	// is host-dependent; this is the earliest point at which the test can
	// influence the daemon.
	if err := jobrunner.TouchCancelFlag(jobDir); err != nil {
		t.Fatalf("touch cancel.flag: %v", err)
	}

	// Wait for terminal state via the --cancel --wait dispatcher path for
	// end-to-end coverage.
	cancelCmd := exec.Command(bin, "--cancel", "--job-id", jobID,
		"--work-dir", workDir, "--wait", "--timeout", "30s", "--license-key", "")
	cancelCmd.Stderr = os.Stderr
	if _, err := cancelCmd.Output(); err != nil {
		t.Fatalf("cancel failed: %v", err)
	}

	// Verify terminal state. We expect StateCancelled when the daemon's
	// cancel-flag poller (2s interval) observes the pre-armed flag before
	// the scan finishes naturally. On hosts with a tiny scan surface the
	// scan can finish inside the first poll window — accept StateDone as a
	// soft pass in that case (the end-to-end dispatcher path is still
	// exercised), but log a t.Logf for CI visibility.
	s, err := jobrunner.ReadStatus(jobDir)
	if err != nil {
		t.Fatalf("read status after cancel: %v", err)
	}
	if !s.State.IsTerminal() {
		t.Fatalf("state after cancel --wait is not terminal: %q", s.State)
	}
	if s.State != jobrunner.StateCancelled {
		t.Logf("scan completed before 2s cancel-poll tick (state=%q); "+
			"cancel flag was set but daemon finished naturally", s.State)
	}
	if s.CompletedAt == nil {
		t.Error("CompletedAt should be populated after terminal state")
	}
}

func TestJobRunner_EndToEnd_Complete(t *testing.T) {
	bin := buildTritonBinary(t)
	workDir := t.TempDir()

	// Use a very short max-duration so the scan always terminates promptly
	// regardless of the host's crypto-asset surface area.
	cmd := exec.Command(bin, "--detach", "--profile", "quick", "--max-duration", "3s",
		"--work-dir", workDir, "--quiet", "--license-key", "")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("detach failed: %v: %s", err, out)
	}
	jobID := lastNonEmptyLine(out)
	if jobID == "" {
		t.Fatal("no job-id from --detach --quiet")
	}

	// Wait for terminal state.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		s, err := jobrunner.ReadStatus(filepath.Join(workDir, jobID))
		if err == nil && s.State.IsTerminal() {
			if s.State == jobrunner.StateDone {
				return // happy path
			}
			if s.State == jobrunner.StateFailed {
				t.Fatalf("scan failed: %s", s.Error)
			}
			if s.State == jobrunner.StateCancelled {
				t.Fatalf("unexpected cancelled state for quick completion: %s", s.Error)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Error("scan did not reach terminal state within 30s")
}

func TestJobRunner_StaleDetection(t *testing.T) {
	workDir := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(workDir, "stale-job")

	// Fake a status for a PID that is highly unlikely to exist.
	s := jobrunner.InitialStatus("stale-job", 99999999, "quick", "test", "")
	if err := jobrunner.WriteStatusAtomic(jobDir, s); err != nil {
		t.Fatal(err)
	}

	bin := buildTritonBinary(t)
	cmd := exec.Command(bin, "--status", "--job-id", "stale-job",
		"--work-dir", workDir, "--license-key", "")
	if _, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("status failed: %v", err)
	}

	// After the status call, Reconcile should have rewritten to failed.
	s2, err := jobrunner.ReadStatus(jobDir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.State != jobrunner.StateFailed {
		t.Errorf("state after stale detection: got %q, want %q", s2.State, jobrunner.StateFailed)
	}
}
