package jobrunner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// SpawnConfig describes how to fork-exec a detached child process.
type SpawnConfig struct {
	// Executable is the path to the binary to run (typically os.Args[0]
	// to re-exec self). Required.
	Executable string

	// Args are the CLI arguments to pass to the child (excluding the
	// executable name itself — Go prepends that).
	Args []string

	// Env are additional environment variables to append. The parent
	// process's environment is inherited; callers should add the
	// TRITON_DETACHED=1 sentinel here along with TRITON_JOB_ID and
	// TRITON_WORK_DIR so the child can find its state.
	Env []string

	// JobDir is the absolute path of the work-dir for this job. Spawn
	// writes the pid file and redirects child stdout/stderr to
	// scan.log inside this directory.
	JobDir string
}

// Spawn fork-execs a detached child per cfg and returns its PID.
// Writes JobDir/pid (numeric PID, one line) before returning so that
// --status invocations see a consistent snapshot.
// Child stdout/stderr are redirected to JobDir/scan.log.
func Spawn(cfg SpawnConfig) (int, error) {
	if cfg.Executable == "" {
		return 0, fmt.Errorf("SpawnConfig.Executable is required")
	}
	if cfg.JobDir == "" {
		return 0, fmt.Errorf("SpawnConfig.JobDir is required")
	}

	logPath := filepath.Join(cfg.JobDir, "scan.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return 0, fmt.Errorf("create scan.log: %w", err)
	}
	cmd := exec.Command(cfg.Executable, cfg.Args...)
	cmd.Env = append(os.Environ(), cfg.Env...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.SysProcAttr = detachSysProcAttr()

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return 0, fmt.Errorf("start daemon: %w", err)
	}
	_ = logFile.Close()

	pid := cmd.Process.Pid
	if err := cmd.Process.Release(); err != nil {
		_ = writePIDFile(cfg.JobDir, pid)
		return pid, fmt.Errorf("release daemon process: %w", err)
	}
	if err := writePIDFile(cfg.JobDir, pid); err != nil {
		return pid, fmt.Errorf("write pid file: %w", err)
	}
	return pid, nil
}

// writePIDFile writes the daemon PID to <jobDir>/pid as one decimal line.
// Atomic via write-tmp-rename for reader safety.
func writePIDFile(jobDir string, pid int) error {
	path := filepath.Join(jobDir, "pid")
	return writeStringAtomic(path, strconv.Itoa(pid)+"\n")
}

// writeStringAtomic writes s to path via the same write-tmp-rename pattern
// used in io.go. Kept local because writeJSON takes an interface{} and we
// want plaintext here.
func writeStringAtomic(path, s string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(s); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
