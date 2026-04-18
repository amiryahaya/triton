package jobrunner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestHelperProcess is not a real test — it's the subprocess entry point
// used by TestSpawn_ChildRuns. Triggered via the GO_HELPER_MODE env var.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_HELPER_MODE") != "sleep-and-exit" {
		return
	}
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

func TestSpawn_ChildRuns(t *testing.T) {
	tmp := t.TempDir()
	jobDir, err := EnsureJobDir(tmp, "test-job")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "GO_HELPER_MODE=sleep-and-exit")
	cmd.SysProcAttr = detachSysProcAttr()
	logPath := filepath.Join(jobDir, "scan.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Process.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	_ = logFile.Close()

	if !realPIDAlive(pid) {
		t.Errorf("child pid %d should be alive immediately after Start", pid)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// Reap the child if it has exited but is waiting in zombie state.
		// realPIDAlive would otherwise report zombies as alive (kill(pid,0)
		// succeeds on them on unix); in production the parent triton CLI
		// exits right after Spawn so init reaps — in-test we must.
		reapIfZombie(pid)
		if !realPIDAlive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("child pid %d did not exit within 2s", pid)
}

func TestSpawn_CreatesPidFile(t *testing.T) {
	tmp := t.TempDir()
	jobDir, err := EnsureJobDir(tmp, "pid-test")
	if err != nil {
		t.Fatal(err)
	}

	cfg := SpawnConfig{
		Executable: os.Args[0],
		Args:       []string{"-test.run=TestHelperProcess"},
		Env:        []string{"GO_HELPER_MODE=sleep-and-exit"},
		JobDir:     jobDir,
	}
	pid, err := Spawn(cfg)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if pid <= 0 {
		t.Errorf("pid should be positive, got %d", pid)
	}
	// Clean up: reap the child on exit so the test binary does not
	// leave zombies behind (see spawn_reap_*_test.go for rationale).
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if reapIfZombie(pid) && !realPIDAlive(pid) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	})

	pidPath := filepath.Join(jobDir, "pid")
	data, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	if len(data) == 0 {
		t.Error("pid file is empty")
	}
}
