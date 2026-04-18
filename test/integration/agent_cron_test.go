//go:build integration

package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgent_CronValidatesUnderCheckConfig runs the agent with a 1-minute
// cron expression under --check-config and verifies the scheduler
// validates, describes itself in the banner, and the process exits 0
// without ever sleeping or scanning.
func TestAgent_CronValidatesUnderCheckConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "triton")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../")
	buildCmd.Env = append(buildCmd.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	yamlPath := filepath.Join(tmpDir, "agent.yaml")
	yamlContent := []byte("schedule: \"* * * * *\"\nprofile: quick\n")
	if err := os.WriteFile(yamlPath, yamlContent, 0o644); err != nil {
		t.Fatal(err)
	}

	runCmd := exec.Command(binPath, "agent", "--check-config")
	runCmd.Dir = tmpDir
	var stdout, stderr bytes.Buffer
	runCmd.Stdout = &stdout
	runCmd.Stderr = &stderr
	if err := runCmd.Run(); err != nil {
		t.Fatalf("agent --check-config failed: %v\nstdout: %s\nstderr: %s",
			err, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "schedule:") {
		t.Errorf("stdout missing 'schedule:' line:\n%s", out)
	}
	if !strings.Contains(out, "* * * * *") {
		t.Errorf("stdout missing cron expression:\n%s", out)
	}
}

// TestAgent_InvalidCronFailsFast proves the agent exits non-zero
// when agent.yaml carries an invalid cron expression, regardless of
// whether --check-config is passed. The scheduler is resolved before
// --check-config exits and before any scan or server-reachability work.
func TestAgent_InvalidCronFailsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "triton")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../")
	buildCmd.Env = append(buildCmd.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	yamlPath := filepath.Join(tmpDir, "agent.yaml")
	if err := os.WriteFile(yamlPath, []byte("schedule: \"this is not cron\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	runCmd := exec.Command(binPath, "agent")
	runCmd.Dir = tmpDir
	var stderr bytes.Buffer
	runCmd.Stderr = &stderr
	err := runCmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid cron, got success")
	}
	msg := stderr.String()
	if !strings.Contains(msg, "cron") && !strings.Contains(msg, "schedule") {
		t.Errorf("stderr does not mention cron/schedule:\n%s", msg)
	}
}
