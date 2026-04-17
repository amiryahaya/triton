# Job Runner (Detached Scans) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a detached lifecycle to `triton scan` (`--detach`, `--status`, `--collect`, `--cancel`, `--list-jobs`, `--cleanup`) so SSH can disconnect mid-scan, by introducing a new `internal/runtime/jobrunner` package and a `cmd/scan_jobs.go` dispatcher that wraps the existing scan engine.

**Architecture:** Fork-exec with env sentinel. Parent `runScanDetached()` spawns a detached child via `exec.Command` with `SysProcAttr{Setsid:true}` (unix) / `DETACHED_PROCESS` (windows) and writes pid/status to a work-dir. Child detects `TRITON_DETACHED=1` and runs `runScanDaemon()` which installs the same `Limits.Apply()` as foreground, then starts three goroutines: `eng.Scan()`, a status-writer consuming `progressCh` with atomic write-tmp-rename, and a cancel.flag poller. No scanner engine changes.

**Tech Stack:** Go 1.25 stdlib (`os/exec`, `syscall`, `archive/tar`, `compress/gzip`), `github.com/google/uuid` (already a dep), existing `internal/runtime/limits` from PR #71, existing `pkg/scanner` engine (unchanged).

**Spec:** `docs/plans/2026-04-18-job-runner-design.md` (committed at `71491cd` in this worktree).

---

## File Structure

**Create (new `internal/runtime/jobrunner/` package):**
- `internal/runtime/jobrunner/doc.go` — package doc (caveats, platform notes)
- `internal/runtime/jobrunner/status.go` — Status struct, StateEnum, initial/update/terminal helpers
- `internal/runtime/jobrunner/status_test.go`
- `internal/runtime/jobrunner/io.go` — WriteStatusAtomic, ReadStatus, WriteJSON helpers (write-tmp-rename)
- `internal/runtime/jobrunner/io_test.go`
- `internal/runtime/jobrunner/lock_unix.go` — `//go:build unix` flock-based file lock
- `internal/runtime/jobrunner/lock_windows.go` — `//go:build windows` LockFileEx
- `internal/runtime/jobrunner/lock_test.go`
- `internal/runtime/jobrunner/workdir.go` — DefaultWorkDir, ResolveWorkDir, JobDir, EnsureJobDir
- `internal/runtime/jobrunner/workdir_test.go`
- `internal/runtime/jobrunner/cancelflag.go` — TouchCancelFlag, IsCancelled
- `internal/runtime/jobrunner/cancelflag_test.go`
- `internal/runtime/jobrunner/detach_unix.go` — `//go:build unix` SysProcAttr with Setsid
- `internal/runtime/jobrunner/detach_windows.go` — `//go:build windows` SysProcAttr with DETACHED_PROCESS
- `internal/runtime/jobrunner/spawn.go` — Spawn() wrapping exec.Command
- `internal/runtime/jobrunner/spawn_test.go`
- `internal/runtime/jobrunner/stale.go` — Reconcile() with injectable PID-alive hook
- `internal/runtime/jobrunner/stale_test.go`
- `internal/runtime/jobrunner/list.go` — List() → []JobSummary, Remove(), RemoveAll()
- `internal/runtime/jobrunner/list_test.go`

**Create (new CLI dispatchers):**
- `cmd/scan_jobs.go` — runScanDetached, runScanDaemon, runJobStatus, runJobCollect, runJobCancel, runJobList, runJobCleanup, writeStatusLoop, cancelFlagPoller
- `cmd/scan_jobs_test.go`

**Modify:**
- `cmd/root.go` — add 15 lifecycle/control flags in `init()`; add daemon-sentinel check + lifecycle dispatch at top of `runScan`

**Create (integration):**
- `test/integration/scan_jobs_test.go` — `//go:build integration` end-to-end detach→status→collect→cancel flow

**Modify (docs):**
- `README.md` — add "Detached scans" section under Usage
- `CLAUDE.md` — add `### Job runner (detached scans)` reference under the new resource-limits subsection

---

## Scope Check

Single feature, single PR. All new code lives in one new package + one new CLI file + ~50 lines added to `cmd/root.go`. Comparable to PR #71 in shape (new package + CLI wiring + integration test). No need to decompose further.

---

## Testing Notes for the Implementer

**You'll see test seams in the `jobrunner` package.** The stale detector takes an injectable `pidAlive func(int) bool` for the same reason PR #71's watchdog takes an injectable sampler + kill: the real implementation calls `os.FindProcess(pid).Signal(syscall.Signal(0))` which is stateful against the live process table; tests can't reliably produce a specific ESRCH without forking a process. The seam is package-private.

**The Spawn test uses a real subprocess.** We don't mock `exec.Command` — we exec a tiny helper binary that the test builds via `go test -c`, sleeps for a fixed interval, then exits. This gives genuine coverage of the detach flow without mocking OS primitives. See `cmd/scan_jobs_test.go` existing patterns in the project for the technique — actually this project doesn't use that pattern yet, so expect to define the test helper inline using `exec.Command(os.Args[0], "-test.run=TestHelperProcess", ...)`.

**Windows vs unix tests.** Files ending in `_unix.go` / `_windows.go` have build tags. Tests for them live in `*_test.go` files that are NOT build-tagged but call the cross-platform public API — the build tag on the implementation file determines which compiles. Don't write `detach_unix_test.go` with `//go:build unix` unless the test directly exercises unix-only syscalls; prefer testing the public API so the same test exercises both platforms.

**Integration tests use `//go:build integration`.** Do not run them in the unit test phase of CI.

**Race detector must pass.** Status writes + reads + cancel flag polling all happen concurrently. Use `sync/atomic` or context cancellation; avoid bare bool flags shared between goroutines.

---

## Task 1: Status struct + state transitions

**Files:**
- Create: `internal/runtime/jobrunner/status.go`
- Create: `internal/runtime/jobrunner/status_test.go`
- Create: `internal/runtime/jobrunner/doc.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/jobrunner/status_test.go`:

```go
package jobrunner

import (
	"testing"
	"time"
)

func TestInitialStatus(t *testing.T) {
	before := time.Now()
	s := InitialStatus("job-123", 4567, "quick", "v1.0.0", "limits=none")
	after := time.Now()

	if s.JobID != "job-123" {
		t.Errorf("JobID = %q, want job-123", s.JobID)
	}
	if s.PID != 4567 {
		t.Errorf("PID = %d, want 4567", s.PID)
	}
	if s.State != StateRunning {
		t.Errorf("State = %q, want %q", s.State, StateRunning)
	}
	if s.StartedAt.Before(before) || s.StartedAt.After(after) {
		t.Errorf("StartedAt %v not in [%v, %v]", s.StartedAt, before, after)
	}
	if s.TritonVersion != "v1.0.0" {
		t.Errorf("TritonVersion = %q, want v1.0.0", s.TritonVersion)
	}
	if s.Limits != "limits=none" {
		t.Errorf("Limits = %q, want limits=none", s.Limits)
	}
	if s.CompletedAt != nil {
		t.Errorf("CompletedAt should be nil on init, got %v", *s.CompletedAt)
	}
}

func TestStateIsTerminal(t *testing.T) {
	cases := []struct {
		s    State
		term bool
	}{
		{StatePending, false},
		{StateRunning, false},
		{StateDone, true},
		{StateFailed, true},
		{StateCancelled, true},
	}
	for _, tc := range cases {
		t.Run(string(tc.s), func(t *testing.T) {
			if got := tc.s.IsTerminal(); got != tc.term {
				t.Errorf("%q.IsTerminal() = %v, want %v", tc.s, got, tc.term)
			}
		})
	}
}

func TestStatusMarkTerminal(t *testing.T) {
	s := InitialStatus("j", 1, "q", "v", "")
	s.MarkTerminal(StateDone, nil)

	if s.State != StateDone {
		t.Errorf("State = %q, want done", s.State)
	}
	if s.CompletedAt == nil {
		t.Fatal("CompletedAt should be set after MarkTerminal")
	}
	if s.Error != "" {
		t.Errorf("Error = %q, want empty on done", s.Error)
	}
}

func TestStatusMarkTerminalWithError(t *testing.T) {
	s := InitialStatus("j", 1, "q", "v", "")
	s.MarkTerminal(StateFailed, errAtomicFailure)

	if s.State != StateFailed {
		t.Errorf("State = %q, want failed", s.State)
	}
	if s.Error == "" {
		t.Errorf("Error should be populated on failed state")
	}
}

// sentinel for the test above
var errAtomicFailure = &sentinelError{msg: "boom"}

type sentinelError struct{ msg string }

func (e *sentinelError) Error() string { return e.msg }
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/runtime/jobrunner/... -v`
Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Implement**

Create `internal/runtime/jobrunner/doc.go`:

```go
// Package jobrunner implements the work-dir state machine for detached triton scans.
//
// A detached scan writes lifecycle state to ~/.triton/jobs/<job-id>/ — pid,
// status.json, cancel.flag, scan.log, reports/, result.json. This package owns
// the filesystem contract; consumers read/write status via atomic WriteFile +
// Rename and check daemon liveness via the stale detector.
//
// Platform notes:
//
//   - Detach mechanism is fork-exec with env sentinel (TRITON_DETACHED=1).
//     SysProcAttr differs between unix (Setsid: true) and windows
//     (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP).
//
//   - Cancellation is cooperative: callers touch cancel.flag; the daemon
//     polls every 2s and cancels its scan context. This avoids platform
//     signal differences (SIGTERM on unix vs GenerateConsoleCtrlEvent on
//     windows).
//
//   - File locks use flock on unix and LockFileEx on windows. The lock is
//     held by the daemon for its lifetime; observing an unheld lock is how
//     stale-job detection works.
package jobrunner
```

Create `internal/runtime/jobrunner/status.go`:

```go
package jobrunner

import "time"

// State enumerates the observable states of a detached scan.
type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateDone      State = "done"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
)

// IsTerminal reports whether the state is final (won't transition further).
func (s State) IsTerminal() bool {
	switch s {
	case StateDone, StateFailed, StateCancelled:
		return true
	}
	return false
}

// Status is the on-disk contract for ~/.triton/jobs/<job-id>/status.json.
// Stable fields — adding new ones is safe; removing/renaming is breaking.
type Status struct {
	JobID          string     `json:"job_id"`
	PID            int        `json:"pid"`
	State          State      `json:"state"`
	StartedAt      time.Time  `json:"started_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CompletedAt    *time.Time `json:"completed_at"`
	ProgressPct    float64    `json:"progress_pct"`
	CurrentModule  string     `json:"current_module"`
	FindingsCount  int        `json:"findings_count"`
	RSSMB          int        `json:"rss_mb"`
	Limits         string     `json:"limits"`
	Error          string     `json:"error"`
	Host           string     `json:"host"`
	TritonVersion  string     `json:"triton_version"`
	Profile        string     `json:"profile"`
}

// InitialStatus returns a fresh Status with state=running, StartedAt=now.
// Host is populated from os.Hostname() by the caller (not here to avoid a
// syscall in test paths).
func InitialStatus(jobID string, pid int, profile, version, limits string) *Status {
	now := time.Now().UTC()
	return &Status{
		JobID:         jobID,
		PID:           pid,
		State:         StateRunning,
		StartedAt:     now,
		UpdatedAt:     now,
		TritonVersion: version,
		Limits:        limits,
		Profile:       profile,
	}
}

// MarkTerminal transitions the status to a terminal state and records the
// completion time and error message (if err is non-nil). Does nothing if
// the state is already terminal (sticky terminal states).
func (s *Status) MarkTerminal(next State, err error) {
	if s.State.IsTerminal() {
		return
	}
	s.State = next
	now := time.Now().UTC()
	s.UpdatedAt = now
	s.CompletedAt = &now
	if err != nil {
		s.Error = err.Error()
	}
}

// Touch updates UpdatedAt to now. Called by the status writer loop.
func (s *Status) Touch() {
	s.UpdatedAt = time.Now().UTC()
}
```

- [ ] **Step 4: Verify green**

Run: `go test ./internal/runtime/jobrunner/... -v`
Expected: PASS — 4 tests (TestInitialStatus, TestStateIsTerminal with 5 subtests, TestStatusMarkTerminal, TestStatusMarkTerminalWithError).

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/jobrunner/status.go internal/runtime/jobrunner/status_test.go internal/runtime/jobrunner/doc.go
git commit -m "feat(jobrunner): bootstrap Status struct with state transitions"
```

---

## Task 2: Atomic status I/O

**Files:**
- Create: `internal/runtime/jobrunner/io.go`
- Create: `internal/runtime/jobrunner/io_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/jobrunner/io_test.go`:

```go
package jobrunner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteStatusAtomic_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := InitialStatus("abc", 42, "quick", "v1.2.3", "limits=none")
	orig.ProgressPct = 33.3
	orig.FindingsCount = 7

	if err := WriteStatusAtomic(dir, orig); err != nil {
		t.Fatalf("WriteStatusAtomic: %v", err)
	}

	got, err := ReadStatus(dir)
	if err != nil {
		t.Fatalf("ReadStatus: %v", err)
	}

	if got.JobID != orig.JobID {
		t.Errorf("JobID: got %q want %q", got.JobID, orig.JobID)
	}
	if got.ProgressPct != orig.ProgressPct {
		t.Errorf("ProgressPct: got %v want %v", got.ProgressPct, orig.ProgressPct)
	}
	// Times round-trip with UTC truncation — compare with tolerance.
	if !got.StartedAt.Equal(orig.StartedAt) {
		t.Errorf("StartedAt: got %v want %v", got.StartedAt, orig.StartedAt)
	}
}

func TestWriteStatusAtomic_NoPartialReads(t *testing.T) {
	// The write-tmp-rename pattern means a reader opening status.json
	// either sees the old content or the new content, never a partial
	// write. We verify by ensuring the target file never appears in a
	// corrupt state: after WriteStatusAtomic, the file exists and parses.
	dir := t.TempDir()
	s1 := InitialStatus("j", 1, "q", "v", "")
	s2 := InitialStatus("j", 1, "q", "v", "")
	s2.FindingsCount = 999

	if err := WriteStatusAtomic(dir, s1); err != nil {
		t.Fatal(err)
	}
	// Overwrite — rename should succeed atomically.
	if err := WriteStatusAtomic(dir, s2); err != nil {
		t.Fatal(err)
	}
	got, err := ReadStatus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.FindingsCount != 999 {
		t.Errorf("FindingsCount: got %d want 999 (expected second write to win)", got.FindingsCount)
	}
}

func TestReadStatus_Missing(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadStatus(dir)
	if err == nil {
		t.Error("expected error for missing status.json, got nil")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist error, got %v", err)
	}
}

func TestReadStatus_CorruptJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadStatus(dir)
	if err == nil {
		t.Error("expected parse error for corrupt JSON, got nil")
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	type cfg struct {
		Profile string    `json:"profile"`
		At      time.Time `json:"at"`
	}
	want := cfg{Profile: "standard", At: time.Now().UTC()}
	if err := WriteJSON(path, want); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/runtime/jobrunner/... -v -run 'Status|WriteJSON'`
Expected: FAIL — undefined WriteStatusAtomic / ReadStatus / WriteJSON.

- [ ] **Step 3: Implement**

Create `internal/runtime/jobrunner/io.go`:

```go
package jobrunner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// statusFileName is the canonical file for job status on disk.
const statusFileName = "status.json"

// WriteStatusAtomic writes the status to <jobDir>/status.json atomically via
// write-tmp-rename. Callers: status-writer goroutine, terminal-state writer.
func WriteStatusAtomic(jobDir string, s *Status) error {
	s.Touch()
	return WriteJSON(filepath.Join(jobDir, statusFileName), s)
}

// ReadStatus reads <jobDir>/status.json and returns the parsed Status.
// Returns os.IsNotExist-wrapped error if the file is missing.
func ReadStatus(jobDir string) (*Status, error) {
	data, err := os.ReadFile(filepath.Join(jobDir, statusFileName))
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse status.json: %w", err)
	}
	return &s, nil
}

// WriteJSON marshals v as indented JSON and writes it atomically (write-tmp-
// rename). The temp file lives in the same directory so rename is same-FS.
// Mode 0600 — status files can contain host/process metadata.
func WriteJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Verify green + race**

Run: `go test ./internal/runtime/jobrunner/... -race -v -run 'Status|WriteJSON'`
Expected: PASS — 5 tests.

- [ ] **Step 5: Verify gofmt + vet**

Run: `gofmt -l internal/runtime/jobrunner/ && go vet ./internal/runtime/jobrunner/...`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/runtime/jobrunner/io.go internal/runtime/jobrunner/io_test.go
git commit -m "feat(jobrunner): atomic status.json I/O via write-tmp-rename"
```

---

## Task 3: File lock (cross-platform)

**Files:**
- Create: `internal/runtime/jobrunner/lock_unix.go` — `//go:build unix`
- Create: `internal/runtime/jobrunner/lock_windows.go` — `//go:build windows`
- Create: `internal/runtime/jobrunner/lock_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/jobrunner/lock_test.go`:

```go
package jobrunner

import (
	"path/filepath"
	"testing"
)

func TestAcquireFileLock_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	lock, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("AcquireFileLock: %v", err)
	}
	defer lock.Release()

	if lock == nil {
		t.Fatal("lock is nil")
	}
}

func TestAcquireFileLock_SecondAcquireFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	first, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer first.Release()

	// Second acquire on same path must fail.
	second, err := AcquireFileLock(path)
	if err == nil {
		second.Release()
		t.Fatal("second AcquireFileLock should have failed (lock already held)")
	}
}

func TestAcquireFileLock_AcquireAfterRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	first, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// After release, a new acquire should succeed.
	second, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("second acquire after release: %v", err)
	}
	second.Release()
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/runtime/jobrunner/... -v -run FileLock`
Expected: FAIL — undefined AcquireFileLock.

- [ ] **Step 3: Implement unix**

Create `internal/runtime/jobrunner/lock_unix.go`:

```go
//go:build unix

package jobrunner

import (
	"fmt"
	"os"
	"syscall"
)

// FileLock holds an exclusive file-level lock using flock(2). Zero-value is
// not usable; always use AcquireFileLock.
type FileLock struct {
	f *os.File
}

// AcquireFileLock opens path and tries to acquire an exclusive non-blocking
// flock lock. Returns an error if the lock is held by another process.
// The lock is released when Release is called or when the process exits.
func AcquireFileLock(path string) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flock: %w", err)
	}
	return &FileLock{f: f}, nil
}

// Release drops the lock and closes the underlying file. Safe to call more
// than once (subsequent calls are no-ops).
func (l *FileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	err := l.f.Close()
	l.f = nil
	return err
}
```

Create `internal/runtime/jobrunner/lock_windows.go`:

```go
//go:build windows

package jobrunner

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// FileLock holds an exclusive file-level lock using LockFileEx. Zero-value
// is not usable; always use AcquireFileLock.
type FileLock struct {
	f *os.File
}

// AcquireFileLock opens path and tries to acquire an exclusive non-blocking
// LockFileEx lock. Returns an error if the lock is held.
func AcquireFileLock(path string) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol,
	); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("LockFileEx: %w", err)
	}
	return &FileLock{f: f}, nil
}

// Release unlocks the file and closes it.
func (l *FileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	ol := new(windows.Overlapped)
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, ol)
	err := l.f.Close()
	l.f = nil
	return err
}
```

- [ ] **Step 4: Verify golang.org/x/sys is already a dependency**

Run: `go list -m golang.org/x/sys 2>&1`
Expected: prints a version line (it's a transitive dep of many Go modules). If it's missing, run `go get golang.org/x/sys@latest` and add to go.mod.

- [ ] **Step 5: Verify green on darwin**

Run: `go test ./internal/runtime/jobrunner/... -race -v -run FileLock`
Expected: PASS — 3 tests.

- [ ] **Step 6: Verify windows build**

Run: `GOOS=windows GOARCH=amd64 go build ./...`
Expected: succeeds.

- [ ] **Step 7: Commit**

```bash
git add internal/runtime/jobrunner/lock_unix.go internal/runtime/jobrunner/lock_windows.go internal/runtime/jobrunner/lock_test.go go.mod go.sum
git commit -m "feat(jobrunner): cross-platform FileLock (flock on unix, LockFileEx on windows)"
```

---

## Task 4: Work-dir path helpers

**Files:**
- Create: `internal/runtime/jobrunner/workdir.go`
- Create: `internal/runtime/jobrunner/workdir_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/jobrunner/workdir_test.go`:

```go
package jobrunner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveWorkDir_Override(t *testing.T) {
	got := ResolveWorkDir("/custom/path")
	if got != "/custom/path" {
		t.Errorf("ResolveWorkDir override: got %q want /custom/path", got)
	}
}

func TestResolveWorkDir_Default(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	want := filepath.Join(home, ".triton", "jobs")
	got := ResolveWorkDir("")
	if got != want {
		t.Errorf("ResolveWorkDir default: got %q want %q", got, want)
	}
}

func TestJobDir(t *testing.T) {
	got := JobDir("/base", "abc-123")
	want := filepath.Join("/base", "abc-123")
	if got != want {
		t.Errorf("JobDir: got %q want %q", got, want)
	}
}

func TestEnsureJobDir(t *testing.T) {
	tmp := t.TempDir()
	jobDir, err := EnsureJobDir(tmp, "job-xyz")
	if err != nil {
		t.Fatalf("EnsureJobDir: %v", err)
	}
	expected := filepath.Join(tmp, "job-xyz")
	if jobDir != expected {
		t.Errorf("returned path: got %q want %q", jobDir, expected)
	}
	// reports/ subdir should exist
	if _, err := os.Stat(filepath.Join(jobDir, "reports")); err != nil {
		t.Errorf("reports/ not created: %v", err)
	}
}

func TestEnsureJobDir_IdempotentOnExisting(t *testing.T) {
	tmp := t.TempDir()
	_, err := EnsureJobDir(tmp, "already")
	if err != nil {
		t.Fatal(err)
	}
	// Second call on the same dir must not fail.
	_, err = EnsureJobDir(tmp, "already")
	if err != nil {
		t.Errorf("second EnsureJobDir should be idempotent, got %v", err)
	}
}

func TestResolveWorkDir_ExpandsTilde(t *testing.T) {
	// ~/foo should become ${HOME}/foo
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home: %v", err)
	}
	got := ResolveWorkDir("~/custom-jobs")
	want := filepath.Join(home, "custom-jobs")
	if got != want {
		t.Errorf("ResolveWorkDir(~/custom-jobs): got %q want %q", got, want)
	}
	// Also verify the default path is absolute.
	if !strings.HasPrefix(ResolveWorkDir(""), "/") && !strings.Contains(ResolveWorkDir(""), ":\\") {
		t.Errorf("default workdir should be absolute")
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/runtime/jobrunner/... -v -run 'WorkDir|JobDir'`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement**

Create `internal/runtime/jobrunner/workdir.go`:

```go
package jobrunner

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultWorkDirName is the subdirectory under $HOME where work-dirs live.
const DefaultWorkDirName = ".triton/jobs"

// ResolveWorkDir returns the absolute path to use as the jobs root. If
// override is empty, returns $HOME/.triton/jobs. A leading ~/ is expanded.
func ResolveWorkDir(override string) string {
	if override != "" {
		return expandHome(override)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "triton-jobs")
	}
	return filepath.Join(home, DefaultWorkDirName)
}

// JobDir returns workDir/jobID — the filesystem path for a specific job.
// Does not create the directory.
func JobDir(workDir, jobID string) string {
	return filepath.Join(workDir, jobID)
}

// EnsureJobDir creates workDir/jobID and workDir/jobID/reports if they do
// not exist. Idempotent. Returns the job directory path.
func EnsureJobDir(workDir, jobID string) (string, error) {
	jobDir := JobDir(workDir, jobID)
	if err := os.MkdirAll(filepath.Join(jobDir, "reports"), 0o700); err != nil {
		return "", err
	}
	return jobDir, nil
}

// expandHome expands a leading ~/ to the user's home directory. If home
// lookup fails, returns the path unchanged.
func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}
```

- [ ] **Step 4: Verify green**

Run: `go test ./internal/runtime/jobrunner/... -race -v -run 'WorkDir|JobDir'`
Expected: PASS — 6 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/jobrunner/workdir.go internal/runtime/jobrunner/workdir_test.go
git commit -m "feat(jobrunner): work-dir path resolution and layout helpers"
```

---

## Task 5: Cancel flag

**Files:**
- Create: `internal/runtime/jobrunner/cancelflag.go`
- Create: `internal/runtime/jobrunner/cancelflag_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/jobrunner/cancelflag_test.go`:

```go
package jobrunner

import "testing"

func TestTouchCancelFlag(t *testing.T) {
	dir := t.TempDir()

	if IsCancelled(dir) {
		t.Error("fresh work-dir should not be cancelled")
	}

	if err := TouchCancelFlag(dir); err != nil {
		t.Fatalf("TouchCancelFlag: %v", err)
	}

	if !IsCancelled(dir) {
		t.Error("after TouchCancelFlag, IsCancelled should be true")
	}
}

func TestTouchCancelFlag_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if err := TouchCancelFlag(dir); err != nil {
		t.Fatalf("first touch: %v", err)
	}
	// Second touch on same file must not fail.
	if err := TouchCancelFlag(dir); err != nil {
		t.Fatalf("second touch (idempotent): %v", err)
	}
	if !IsCancelled(dir) {
		t.Error("still cancelled after second touch")
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/runtime/jobrunner/... -v -run CancelFlag`
Expected: FAIL.

- [ ] **Step 3: Implement**

Create `internal/runtime/jobrunner/cancelflag.go`:

```go
package jobrunner

import (
	"os"
	"path/filepath"
)

// cancelFlagName is the sentinel file inside a job-dir that signals
// "please cancel" to the daemon.
const cancelFlagName = "cancel.flag"

// TouchCancelFlag creates <jobDir>/cancel.flag if it does not exist.
// Idempotent — touching an already-touched flag is a no-op.
func TouchCancelFlag(jobDir string) error {
	path := filepath.Join(jobDir, cancelFlagName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// IsCancelled reports whether <jobDir>/cancel.flag exists.
func IsCancelled(jobDir string) bool {
	_, err := os.Stat(filepath.Join(jobDir, cancelFlagName))
	return err == nil
}
```

- [ ] **Step 4: Verify green**

Run: `go test ./internal/runtime/jobrunner/... -race -v -run CancelFlag`
Expected: PASS — 2 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/jobrunner/cancelflag.go internal/runtime/jobrunner/cancelflag_test.go
git commit -m "feat(jobrunner): cancel.flag touch + detection"
```

---

## Task 6: Stale detection

**Files:**
- Create: `internal/runtime/jobrunner/stale.go`
- Create: `internal/runtime/jobrunner/stale_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/jobrunner/stale_test.go`:

```go
package jobrunner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReconcile_NonTerminalPidGone_MarksFailed(t *testing.T) {
	dir := t.TempDir()
	s := InitialStatus("j", 999999, "quick", "v1.0.0", "")
	s.State = StateRunning
	if err := WriteStatusAtomic(dir, s); err != nil {
		t.Fatal(err)
	}

	// pidAlive returns false — daemon is dead.
	rec := &reconciler{pidAlive: func(int) bool { return false }}
	out, changed, err := rec.Reconcile(dir)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !changed {
		t.Error("expected state to change (running → failed)")
	}
	if out.State != StateFailed {
		t.Errorf("State = %q, want failed", out.State)
	}
	if out.Error == "" {
		t.Error("Error should be populated with 'daemon vanished'")
	}
}

func TestReconcile_NonTerminalPidAlive_NoChange(t *testing.T) {
	dir := t.TempDir()
	s := InitialStatus("j", os.Getpid(), "quick", "v1.0.0", "")
	s.State = StateRunning
	if err := WriteStatusAtomic(dir, s); err != nil {
		t.Fatal(err)
	}

	// pidAlive returns true — daemon is alive.
	rec := &reconciler{pidAlive: func(int) bool { return true }}
	out, changed, err := rec.Reconcile(dir)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if changed {
		t.Error("expected no change when daemon alive")
	}
	if out.State != StateRunning {
		t.Errorf("State = %q, want running", out.State)
	}
}

func TestReconcile_TerminalStateNeverChanges(t *testing.T) {
	dir := t.TempDir()
	s := InitialStatus("j", 1, "quick", "v1.0.0", "")
	s.State = StateDone
	ct := time.Now().UTC()
	s.CompletedAt = &ct
	if err := WriteStatusAtomic(dir, s); err != nil {
		t.Fatal(err)
	}

	// Even with pidAlive=false, terminal state must not be rewritten.
	rec := &reconciler{pidAlive: func(int) bool { return false }}
	out, changed, err := rec.Reconcile(dir)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if changed {
		t.Error("terminal state should not be reconciled")
	}
	if out.State != StateDone {
		t.Errorf("State = %q, want done (sticky)", out.State)
	}
}

func TestReconcile_MissingStatus(t *testing.T) {
	dir := t.TempDir()
	rec := &reconciler{pidAlive: func(int) bool { return false }}
	_, _, err := rec.Reconcile(dir)
	if err == nil {
		t.Error("expected error for missing status.json")
	}
}

// Ensure the public Reconcile uses real pidAlive (smoke test).
func TestReconcilePublic_DoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	s := InitialStatus("j", os.Getpid(), "quick", "v1.0.0", "")
	if err := WriteStatusAtomic(dir, s); err != nil {
		t.Fatal(err)
	}
	// Add an empty lock path — Reconcile should complete without panicking.
	_ = os.WriteFile(filepath.Join(dir, "state.lock"), nil, 0o600)
	_, _, err := Reconcile(dir)
	if err != nil {
		t.Errorf("Reconcile public: %v", err)
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/runtime/jobrunner/... -v -run Reconcile`
Expected: FAIL.

- [ ] **Step 3: Implement**

Create `internal/runtime/jobrunner/stale.go`:

```go
package jobrunner

import (
	"errors"
	"os"
)

// Reconcile reads status.json from jobDir and, if the state is non-
// terminal and the daemon PID is not alive, rewrites status as failed
// with error "daemon vanished". Returns the (possibly updated) status,
// whether it was changed, and any I/O error.
//
// This is the self-healing path for --status / --list-jobs.
func Reconcile(jobDir string) (*Status, bool, error) {
	return defaultReconciler.Reconcile(jobDir)
}

// reconciler carries the pidAlive injection seam. Production uses
// defaultReconciler; tests construct their own with a fake pidAlive.
type reconciler struct {
	pidAlive func(int) bool
}

var defaultReconciler = &reconciler{pidAlive: realPIDAlive}

// Reconcile is the method form used by tests.
func (r *reconciler) Reconcile(jobDir string) (*Status, bool, error) {
	s, err := ReadStatus(jobDir)
	if err != nil {
		return nil, false, err
	}
	if s.State.IsTerminal() {
		return s, false, nil
	}
	if s.PID > 0 && r.pidAlive(s.PID) {
		return s, false, nil
	}
	// Non-terminal + PID gone → declare failed.
	s.MarkTerminal(StateFailed, errDaemonVanished)
	if err := WriteStatusAtomic(jobDir, s); err != nil {
		return s, false, err
	}
	return s, true, nil
}

// errDaemonVanished is the sentinel error recorded on stale jobs.
var errDaemonVanished = errors.New("daemon vanished (crash or kill)")

// realPIDAlive reports whether a process with the given PID is reachable
// via signal-0. Negative, zero, or absent processes return false. Used
// only in production; tests inject a fake.
func realPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// os.FindProcess always succeeds on unix; Signal(0) is the liveness
	// check. On windows, FindProcess fails for dead PIDs.
	if err := p.Signal(signalZero); err != nil {
		return false
	}
	return true
}
```

**Why signalZero is a package variable:** `syscall.Signal(0)` is unix-specific. On Windows, `os.Process.Signal(os.Kill)` works but is harmful; instead Windows FindProcess itself fails for dead PIDs, so Signal isn't needed. We'll plumb this via a build-tagged constant in the next step.

- [ ] **Step 4: Add platform-specific signal-zero**

Create `internal/runtime/jobrunner/stale_unix.go`:

```go
//go:build unix

package jobrunner

import "syscall"

// signalZero is the no-op signal used for liveness probing on unix.
var signalZero = syscall.Signal(0)
```

Create `internal/runtime/jobrunner/stale_windows.go`:

```go
//go:build windows

package jobrunner

import "os"

// signalZero on windows. We use os.Interrupt here but realPIDAlive
// short-circuits on FindProcess error before the Signal call, so this
// value is effectively unused on windows builds.
var signalZero = os.Interrupt
```

- [ ] **Step 5: Verify green**

Run: `go test ./internal/runtime/jobrunner/... -race -v -run Reconcile`
Expected: PASS — 5 tests.

- [ ] **Step 6: Verify windows build**

Run: `GOOS=windows GOARCH=amd64 go build ./...`
Expected: succeeds.

- [ ] **Step 7: Commit**

```bash
git add internal/runtime/jobrunner/stale.go internal/runtime/jobrunner/stale_unix.go internal/runtime/jobrunner/stale_windows.go internal/runtime/jobrunner/stale_test.go
git commit -m "feat(jobrunner): stale-job reconciler (self-healing for dead daemons)"
```

---

## Task 7: Platform-specific detach SysProcAttr

**Files:**
- Create: `internal/runtime/jobrunner/detach_unix.go` — `//go:build unix`
- Create: `internal/runtime/jobrunner/detach_windows.go` — `//go:build windows`

No test file — these are trivial one-line returns consumed by Spawn (Task 8), whose test exercises them implicitly via subprocess execution.

- [ ] **Step 1: Create the unix file**

Create `internal/runtime/jobrunner/detach_unix.go`:

```go
//go:build unix

package jobrunner

import "syscall"

// detachSysProcAttr returns the SysProcAttr that detaches a child from the
// parent's controlling terminal and session. Setsid ensures the child
// becomes its own session leader, so closing the parent's SSH session
// does not deliver SIGHUP to the child.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
```

- [ ] **Step 2: Create the windows file**

Create `internal/runtime/jobrunner/detach_windows.go`:

```go
//go:build windows

package jobrunner

import "syscall"

// Win32 process-creation flags. DETACHED_PROCESS is not in the stdlib's
// syscall package as a named constant, so we define it locally.
const (
	createNewProcessGroup uint32 = 0x00000200 // CREATE_NEW_PROCESS_GROUP
	detachedProcess       uint32 = 0x00000008 // DETACHED_PROCESS
)

// detachSysProcAttr returns the SysProcAttr for a fully detached child on
// windows: no console attached, its own process group, no visible window.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup | detachedProcess,
		HideWindow:    true,
	}
}
```

- [ ] **Step 3: Verify both build**

Run: `go build ./... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: both succeed.

- [ ] **Step 4: Commit**

```bash
git add internal/runtime/jobrunner/detach_unix.go internal/runtime/jobrunner/detach_windows.go
git commit -m "feat(jobrunner): platform-specific detach SysProcAttr (setsid/DETACHED_PROCESS)"
```

---

## Task 8: Spawn — fork-exec with env sentinel

**Files:**
- Create: `internal/runtime/jobrunner/spawn.go`
- Create: `internal/runtime/jobrunner/spawn_test.go`

- [ ] **Step 1: Write the failing test**

The test exec's itself with a special `-test.run=TestHelperProcess` invocation — standard Go stdlib technique (see `os/exec_test.go` in Go source). The helper runs a short sleep and exits, proving the parent-side detach flow works without depending on triton's full scan logic.

Create `internal/runtime/jobrunner/spawn_test.go`:

```go
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

	// Use 'go test' binary itself as the child, routing to TestHelperProcess
	// via env var. This is the documented pattern in Go's os/exec tests.
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

	// PID must be alive now.
	if !realPIDAlive(pid) {
		t.Errorf("child pid %d should be alive immediately after Start", pid)
	}

	// Wait for it to exit.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !realPIDAlive(pid) {
			return // success
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

	// pid file should be written.
	pidPath := filepath.Join(jobDir, "pid")
	data, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	if len(data) == 0 {
		t.Error("pid file is empty")
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/runtime/jobrunner/... -v -run Spawn`
Expected: FAIL — undefined Spawn / SpawnConfig.

- [ ] **Step 3: Implement**

Create `internal/runtime/jobrunner/spawn.go`:

```go
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
	// Transfer ownership of logFile to the child via Cmd. We close it
	// in the parent after Start so the kernel file-table reference
	// count drops to 1 (the child's only). Child keeps it open until
	// daemon exits.
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
		// Release failure is non-fatal; child is running. Log in
		// status instead of failing spawn.
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
```

- [ ] **Step 4: Verify green + race**

Run: `go test ./internal/runtime/jobrunner/... -race -v -run Spawn`
Expected: PASS — 2 tests.

- [ ] **Step 5: Verify windows build**

Run: `GOOS=windows GOARCH=amd64 go build ./...`
Expected: succeeds.

- [ ] **Step 6: Commit**

```bash
git add internal/runtime/jobrunner/spawn.go internal/runtime/jobrunner/spawn_test.go
git commit -m "feat(jobrunner): Spawn — fork-exec detached child with pid file"
```

---

## Task 9: List + Remove

**Files:**
- Create: `internal/runtime/jobrunner/list.go`
- Create: `internal/runtime/jobrunner/list_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/jobrunner/list_test.go`:

```go
package jobrunner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestList_Empty(t *testing.T) {
	tmp := t.TempDir()
	jobs, err := List(tmp)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("List on empty dir: got %d jobs, want 0", len(jobs))
	}
}

func TestList_MultipleJobs(t *testing.T) {
	tmp := t.TempDir()
	for _, id := range []string{"job-a", "job-b", "job-c"} {
		jobDir, err := EnsureJobDir(tmp, id)
		if err != nil {
			t.Fatal(err)
		}
		s := InitialStatus(id, 100, "quick", "v1", "")
		if err := WriteStatusAtomic(jobDir, s); err != nil {
			t.Fatal(err)
		}
	}

	jobs, err := List(tmp)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(jobs) != 3 {
		t.Errorf("got %d jobs, want 3", len(jobs))
	}
	seen := map[string]bool{}
	for _, j := range jobs {
		seen[j.JobID] = true
	}
	for _, want := range []string{"job-a", "job-b", "job-c"} {
		if !seen[want] {
			t.Errorf("missing job %q in list", want)
		}
	}
}

func TestList_SkipsNonJobDirs(t *testing.T) {
	tmp := t.TempDir()
	// Create a stray file and a dir without status.json.
	if err := os.WriteFile(filepath.Join(tmp, "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "empty-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Create one real job.
	jobDir, _ := EnsureJobDir(tmp, "real-job")
	if err := WriteStatusAtomic(jobDir, InitialStatus("real-job", 1, "q", "v", "")); err != nil {
		t.Fatal(err)
	}

	jobs, err := List(tmp)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(jobs) != 1 || jobs[0].JobID != "real-job" {
		t.Errorf("got %+v, want 1 job (real-job)", jobs)
	}
}

func TestRemove_RefusesRunning(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := EnsureJobDir(tmp, "running")
	s := InitialStatus("running", os.Getpid(), "q", "v", "")
	s.State = StateRunning
	if err := WriteStatusAtomic(jobDir, s); err != nil {
		t.Fatal(err)
	}

	// pidAlive returns true, so running state is real.
	err := removeWithLiveness(tmp, "running", func(int) bool { return true })
	if err == nil {
		t.Fatal("Remove on running job should fail")
	}
	if _, e := os.Stat(jobDir); e != nil {
		t.Error("job dir should still exist after refused remove")
	}
}

func TestRemove_FinishedJob(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := EnsureJobDir(tmp, "done")
	s := InitialStatus("done", 1, "q", "v", "")
	s.State = StateDone
	if err := WriteStatusAtomic(jobDir, s); err != nil {
		t.Fatal(err)
	}

	if err := Remove(tmp, "done"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, e := os.Stat(jobDir); !os.IsNotExist(e) {
		t.Error("job dir should be gone after Remove")
	}
}

func TestRemoveAll_OnlyFinished(t *testing.T) {
	tmp := t.TempDir()

	jobA, _ := EnsureJobDir(tmp, "a")
	sA := InitialStatus("a", 1, "q", "v", "")
	sA.State = StateDone
	WriteStatusAtomic(jobA, sA)

	jobB, _ := EnsureJobDir(tmp, "b")
	sB := InitialStatus("b", 1, "q", "v", "")
	sB.State = StateFailed
	WriteStatusAtomic(jobB, sB)

	jobC, _ := EnsureJobDir(tmp, "c")
	sC := InitialStatus("c", os.Getpid(), "q", "v", "")
	sC.State = StateRunning
	WriteStatusAtomic(jobC, sC)

	removed, err := removeAllWithLiveness(tmp, func(int) bool { return true })
	if err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2 (done + failed; running skipped)", removed)
	}

	// c should still exist.
	if _, e := os.Stat(jobC); e != nil {
		t.Error("running job c should not have been removed")
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/runtime/jobrunner/... -v -run 'List|Remove'`
Expected: FAIL.

- [ ] **Step 3: Implement**

Create `internal/runtime/jobrunner/list.go`:

```go
package jobrunner

import (
	"fmt"
	"os"
	"path/filepath"
)

// JobSummary is the compact per-job view returned by List.
type JobSummary struct {
	JobID  string
	Status *Status
}

// List enumerates all job directories under workDir that contain a
// status.json file. Unrecognised entries (stray files, empty dirs) are
// skipped. Results are in filesystem order (not sorted).
func List(workDir string) ([]JobSummary, error) {
	entries, err := os.ReadDir(workDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read workdir: %w", err)
	}
	var out []JobSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		jobDir := filepath.Join(workDir, e.Name())
		s, err := ReadStatus(jobDir)
		if err != nil {
			continue // no status.json → not a job dir
		}
		out = append(out, JobSummary{JobID: e.Name(), Status: s})
	}
	return out, nil
}

// Remove deletes a single job directory. Refuses if the status is
// non-terminal AND the daemon PID is alive — in that case the caller
// should --cancel first. Callers using the public Remove get the real
// pidAlive check.
func Remove(workDir, jobID string) error {
	return removeWithLiveness(workDir, jobID, realPIDAlive)
}

// removeWithLiveness is the testable form, parameterised on a pidAlive
// predicate so unit tests can inject deterministic behaviour without
// depending on the process table.
func removeWithLiveness(workDir, jobID string, pidAlive func(int) bool) error {
	jobDir := filepath.Join(workDir, jobID)
	s, err := ReadStatus(jobDir)
	if err != nil {
		// If status.json is missing but the dir exists, assume it's
		// safe to remove (already stale or malformed).
		if os.IsNotExist(err) {
			return os.RemoveAll(jobDir)
		}
		return err
	}
	if !s.State.IsTerminal() && s.PID > 0 && pidAlive(s.PID) {
		return fmt.Errorf("job %s is running (pid %d); cancel it first", jobID, s.PID)
	}
	return os.RemoveAll(jobDir)
}

// RemoveAll removes all finished (terminal-state) jobs under workDir.
// Running jobs are skipped silently. Returns the count removed.
func RemoveAll(workDir string) (int, error) {
	return removeAllWithLiveness(workDir, realPIDAlive)
}

// removeAllWithLiveness is the testable form.
func removeAllWithLiveness(workDir string, pidAlive func(int) bool) (int, error) {
	jobs, err := List(workDir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, j := range jobs {
		if !j.Status.State.IsTerminal() && j.Status.PID > 0 && pidAlive(j.Status.PID) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(workDir, j.JobID)); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
```

- [ ] **Step 4: Verify green + race**

Run: `go test ./internal/runtime/jobrunner/... -race -v -run 'List|Remove'`
Expected: PASS — 6 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/jobrunner/list.go internal/runtime/jobrunner/list_test.go
git commit -m "feat(jobrunner): List + Remove with running-job protection"
```

---

## Task 10: Status writer goroutine + cancel poller in cmd/scan_jobs.go

**Files:**
- Create: `cmd/scan_jobs.go`
- Create: `cmd/scan_jobs_test.go`

Task 10 adds the two goroutines that bind `jobrunner` to the running scan engine. They are defined in `cmd/` (not `jobrunner/`) because they import `pkg/scanner` for the Progress type, and `jobrunner/` must stay importable from anywhere.

- [ ] **Step 1: Write the failing test**

Create `cmd/scan_jobs_test.go`:

```go
package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/pkg/scanner"
)

func TestWriteStatusLoop_UpdatesOnProgress(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "job")
	if err := jobrunner.WriteStatusAtomic(jobDir, jobrunner.InitialStatus("job", 1, "q", "v", "")); err != nil {
		t.Fatal(err)
	}

	progressCh := make(chan scanner.Progress, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		writeStatusLoop(ctx, jobDir, progressCh)
		close(done)
	}()

	progressCh <- scanner.Progress{Percent: 0.25, Status: "certificate", Module: "certificate"}
	progressCh <- scanner.Progress{Percent: 0.50, Status: "library", Module: "library"}
	time.Sleep(50 * time.Millisecond) // let the loop run
	close(progressCh)
	<-done

	s, err := jobrunner.ReadStatus(jobDir)
	if err != nil {
		t.Fatal(err)
	}
	if s.ProgressPct != 50.0 {
		t.Errorf("ProgressPct = %v, want 50.0", s.ProgressPct)
	}
	if s.CurrentModule != "library" {
		t.Errorf("CurrentModule = %q, want library", s.CurrentModule)
	}
}

func TestWriteStatusLoop_OnCompleteWritesResult(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "job")
	jobrunner.WriteStatusAtomic(jobDir, jobrunner.InitialStatus("job", 1, "q", "v", ""))

	progressCh := make(chan scanner.Progress, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		writeStatusLoop(ctx, jobDir, progressCh)
		close(done)
	}()

	progressCh <- scanner.Progress{Percent: 1.0, Status: "done", Complete: true}
	close(progressCh)
	<-done

	s, _ := jobrunner.ReadStatus(jobDir)
	if s.ProgressPct != 100.0 {
		t.Errorf("ProgressPct = %v, want 100.0 on complete", s.ProgressPct)
	}
}

func TestCancelFlagPoller_CancelsOnFlagTouch(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "job")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cancelled bool
	fakeCancel := func() { cancelled = true }

	done := make(chan struct{})
	go func() {
		// Use a very short interval for fast test feedback.
		cancelFlagPollerWithInterval(ctx, jobDir, fakeCancel, 10*time.Millisecond)
		close(done)
	}()

	// Touch the flag; expect fakeCancel() called within ~100ms.
	if err := jobrunner.TouchCancelFlag(jobDir); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cancelled {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if !cancelled {
		t.Error("fakeCancel was not called after cancel.flag touch")
	}
}

func TestCancelFlagPoller_StopsOnContextDone(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "job")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		cancelFlagPollerWithInterval(ctx, jobDir, func() {}, 10*time.Millisecond)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		// Ensure no orphan goroutine.
		t.Error("cancelFlagPoller did not exit within 200ms of context cancel")
	}
	_ = filepath.Join // silence unused import from earlier template
	_ = os.Getpid
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./cmd/... -v -run 'WriteStatusLoop|CancelFlagPoller'`
Expected: FAIL — undefined writeStatusLoop / cancelFlagPollerWithInterval.

- [ ] **Step 3: Implement**

Create `cmd/scan_jobs.go` with ONLY the two loop helpers for now. The dispatcher functions (runScanDetached, runJobStatus, etc.) come in later tasks — keep this task focused.

```go
package cmd

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// statusWriteInterval is the periodic tick for rewriting status.json when
// no progress event has arrived. 2 seconds balances freshness and I/O.
const statusWriteInterval = 2 * time.Second

// writeStatusLoop drains progressCh, updating status.json atomically on
// every progress event (bounded to statusWriteInterval by ticker if
// progress events are absent). Returns when progressCh closes or ctx ends.
func writeStatusLoop(ctx context.Context, jobDir string, progressCh <-chan scanner.Progress) {
	ticker := time.NewTicker(statusWriteInterval)
	defer ticker.Stop()

	current, err := jobrunner.ReadStatus(jobDir)
	if err != nil {
		// If status doesn't exist yet, create a minimal one.
		current = jobrunner.InitialStatus("unknown", 0, "", "", "")
	}

	flush := func() {
		current.RSSMB = currentRSSMB()
		_ = jobrunner.WriteStatusAtomic(jobDir, current)
	}

	for {
		select {
		case p, ok := <-progressCh:
			if !ok {
				flush()
				return
			}
			applyProgress(current, p)
			// Mirror progress to the daemon's stdout (redirected to scan.log).
			fmt.Printf("[%3.0f%%] %s\n", p.Percent*100, p.Status)
			if p.Complete {
				flush()
				return
			}
			flush()
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}

// applyProgress merges a Progress event into the Status in place.
func applyProgress(s *jobrunner.Status, p scanner.Progress) {
	s.ProgressPct = p.Percent * 100
	if p.Module != "" {
		s.CurrentModule = p.Module
	}
	if p.Result != nil {
		s.FindingsCount = len(p.Result.Findings)
	}
}

// currentRSSMB returns the Go runtime's memory footprint in MB as a proxy
// for RSS. This matches the metric used by PR #71's memory watchdog.
func currentRSSMB() int {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int(m.Sys / (1 << 20))
}

// cancelPollInterval is the default poll rate for the cancel-flag watcher.
const cancelPollInterval = 2 * time.Second

// cancelFlagPoller watches jobDir/cancel.flag and invokes cancel() once
// the flag appears, then returns. Exits on ctx.Done without calling cancel.
func cancelFlagPoller(ctx context.Context, jobDir string, cancel context.CancelFunc) {
	cancelFlagPollerWithInterval(ctx, jobDir, cancel, cancelPollInterval)
}

// cancelFlagPollerWithInterval is the testable form with an explicit interval.
func cancelFlagPollerWithInterval(ctx context.Context, jobDir string, cancel func(), interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if jobrunner.IsCancelled(jobDir) {
				cancel()
				return
			}
		}
	}
}
```

- [ ] **Step 4: Verify green + race**

Run: `go test ./cmd/... -race -v -run 'WriteStatusLoop|CancelFlagPoller'`
Expected: PASS — 4 tests.

- [ ] **Step 5: Verify gofmt + vet + windows build**

Run: `gofmt -l cmd/scan_jobs.go cmd/scan_jobs_test.go && go vet ./cmd/... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add cmd/scan_jobs.go cmd/scan_jobs_test.go
git commit -m "feat(cmd): status-writer and cancel-flag-poller goroutines for detached scans"
```

---

## Task 11: Daemon entry — runScanDaemon

**Files:**
- Modify: `cmd/scan_jobs.go` — append `runScanDaemon` function

- [ ] **Step 1: Write the failing test**

Append to `cmd/scan_jobs_test.go`:

```go
func TestIsDaemonMode(t *testing.T) {
	t.Setenv("TRITON_DETACHED", "1")
	if !isDaemonMode() {
		t.Error("isDaemonMode should return true when TRITON_DETACHED=1")
	}
	t.Setenv("TRITON_DETACHED", "")
	if isDaemonMode() {
		t.Error("isDaemonMode should return false with empty TRITON_DETACHED")
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./cmd/... -v -run IsDaemonMode`
Expected: FAIL.

- [ ] **Step 3: Implement the daemon entry + isDaemonMode**

In `cmd/scan_jobs.go`, append these functions (after the existing loop helpers):

```go
import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/internal/runtime/limits"
	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/store"
	"github.com/spf13/cobra"
)

// isDaemonMode reports whether the current process is a detached daemon
// (i.e. started by runScanDetached with TRITON_DETACHED=1 in its env).
func isDaemonMode() bool {
	return os.Getenv("TRITON_DETACHED") == "1"
}

// runScanDaemon is the entry point for a detached child process. It
// activates only when TRITON_DETACHED=1; otherwise the normal runScan
// path runs. Reads TRITON_JOB_ID and TRITON_WORK_DIR from env, acquires
// state.lock (fails fast if another daemon holds it), builds the scan
// engine, and launches three goroutines: eng.Scan, writeStatusLoop,
// cancelFlagPoller.
func runScanDaemon(cmd *cobra.Command, args []string) error {
	jobID := os.Getenv("TRITON_JOB_ID")
	workDir := os.Getenv("TRITON_WORK_DIR")
	if jobID == "" || workDir == "" {
		return errors.New("daemon mode requires TRITON_JOB_ID and TRITON_WORK_DIR")
	}
	jobDir := filepath.Join(workDir, jobID)

	lock, err := jobrunner.AcquireFileLock(filepath.Join(jobDir, "state.lock"))
	if err != nil {
		return fmt.Errorf("acquire state.lock: %w", err)
	}
	defer lock.Release()

	// Build scan config + limits identically to foreground scan.
	cfg, err := buildScanConfigForCmd(cmd)
	if err != nil {
		writeTerminalFailure(jobDir, err)
		return err
	}
	lim, err := buildLimitsForCmd(cmd)
	if err != nil {
		writeTerminalFailure(jobDir, err)
		return err
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()
	ctx, cleanup := lim.Apply(baseCtx)
	defer cleanup()

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()
	if cfg.DBUrl != "" {
		if db, err := store.NewPostgresStore(ctx, cfg.DBUrl); err == nil {
			eng.SetStore(db)
			defer func() { _ = db.Close() }()
		}
	}

	progressCh := make(chan scanner.Progress, progressBufferSize)

	var firstResult atomic.Pointer[model.ScanResult]
	go eng.Scan(ctx, progressCh)
	go cancelFlagPoller(ctx, jobDir, baseCancel)

	// Status-writer runs inline so we can capture the final Result.
	// (writeStatusLoop only mirrors findings count; we need the full
	// result for report generation + result.json below.)
	runStatusAndCollect(ctx, jobDir, progressCh, &firstResult)

	// Determine terminal state.
	result := firstResult.Load()
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		writeTerminalStatus(jobDir, jobrunner.StateCancelled, result, nil)
	case result != nil:
		if err := saveResultAndReports(jobDir, result, cfg); err != nil {
			writeTerminalStatus(jobDir, jobrunner.StateFailed, result, err)
			return err
		}
		writeTerminalStatus(jobDir, jobrunner.StateDone, result, nil)
	default:
		writeTerminalStatus(jobDir, jobrunner.StateFailed, nil, errors.New("scan ended without result"))
	}
	return nil
}

// runStatusAndCollect drains progressCh, mirrors progress to status.json,
// and stores the first Result into dst for later report generation.
// Combines writeStatusLoop's responsibilities with result capture so
// the daemon entry has one source of truth.
func runStatusAndCollect(ctx context.Context, jobDir string, progressCh <-chan scanner.Progress, dst *atomic.Pointer[model.ScanResult]) {
	ticker := time.NewTicker(statusWriteInterval)
	defer ticker.Stop()
	current, err := jobrunner.ReadStatus(jobDir)
	if err != nil {
		current = jobrunner.InitialStatus("unknown", 0, "", "", "")
	}
	flush := func() {
		current.RSSMB = currentRSSMB()
		_ = jobrunner.WriteStatusAtomic(jobDir, current)
	}
	for {
		select {
		case p, ok := <-progressCh:
			if !ok {
				flush()
				return
			}
			applyProgress(current, p)
			if p.Result != nil && dst.Load() == nil {
				dst.Store(p.Result)
			}
			fmt.Printf("[%3.0f%%] %s\n", p.Percent*100, p.Status)
			if p.Complete {
				flush()
				return
			}
			flush()
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}

// writeTerminalStatus is a convenience that reads current status, marks
// it terminal, and writes it back.
func writeTerminalStatus(jobDir string, state jobrunner.State, result *model.ScanResult, err error) {
	s, readErr := jobrunner.ReadStatus(jobDir)
	if readErr != nil {
		s = jobrunner.InitialStatus("unknown", 0, "", "", "")
	}
	if result != nil {
		s.FindingsCount = len(result.Findings)
	}
	s.MarkTerminal(state, err)
	_ = jobrunner.WriteStatusAtomic(jobDir, s)
}

// writeTerminalFailure is a shortcut for early-path errors.
func writeTerminalFailure(jobDir string, err error) {
	writeTerminalStatus(jobDir, jobrunner.StateFailed, nil, err)
}

// The following helpers are STUBBED here and implemented in later tasks:
// they will be factored out of cmd/root.go into shared helpers so both
// runScan and runScanDaemon can reuse them.

// buildScanConfigForCmd extracts scanner config from cobra flags.
// Currently calls the same scannerconfig.BuildConfig() used by runScan.
func buildScanConfigForCmd(cmd *cobra.Command) (*scannerconfig.Config, error) {
	return scannerconfig.BuildConfig(scannerconfig.BuildOptions{
		Profile: scanProfile,
		Modules: modules,
	})
}

// buildLimitsForCmd wraps cmd/root.go's existing buildLimits to extract
// flag values. In the final implementation, buildLimits will be exported
// or moved to cmd/ — for now we call through via a helper defined in
// Task 13.
func buildLimitsForCmd(cmd *cobra.Command) (limits.Limits, error) {
	maxMem, _ := cmd.Flags().GetString("max-memory")
	maxCPU, _ := cmd.Flags().GetString("max-cpu-percent")
	maxDur, _ := cmd.Flags().GetDuration("max-duration")
	stopAt, _ := cmd.Flags().GetString("stop-at")
	niceVal, _ := cmd.Flags().GetInt("nice")
	return buildLimits(maxMem, maxCPU, maxDur, stopAt, niceVal)
}

// saveResultAndReports writes the JSON result to result.json and
// generates all configured report formats into jobDir/reports/. Uses
// existing report.Generator — same code path as foreground runScan.
// Stubbed here; full implementation in Task 12.
func saveResultAndReports(jobDir string, result *model.ScanResult, cfg *scannerconfig.Config) error {
	// TEMPORARY: write only result.json; Task 12 adds report formats.
	return jobrunner.WriteJSON(filepath.Join(jobDir, "result.json"), result)
}
```

**Note to implementer:** the `progressBufferSize`, `scanProfile`, `modules`, and `buildLimits` identifiers come from `cmd/root.go` (same package, so they're visible here). No import cycle.

- [ ] **Step 4: Verify isDaemonMode test passes and package compiles**

Run: `go build ./... && go test ./cmd/... -v -run IsDaemonMode`
Expected: compile succeeds; IsDaemonMode test passes.

End-to-end daemon behavior is verified in Task 15 (integration test).

- [ ] **Step 5: Verify gofmt + vet + windows**

Run: `gofmt -l cmd/ && go vet ./cmd/... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add cmd/scan_jobs.go cmd/scan_jobs_test.go
git commit -m "feat(cmd): runScanDaemon entry point (TRITON_DETACHED=1 mode)"
```

---

## Task 12: Report generation for detached scans

**Files:**
- Modify: `cmd/scan_jobs.go` — replace stub `saveResultAndReports` with real implementation

- [ ] **Step 1: Write the failing test**

Append to `cmd/scan_jobs_test.go`:

```go
func TestSaveResultAndReports_WritesResultJSON(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "j")

	result := &model.ScanResult{
		ScanID:    "test-scan",
		Timestamp: time.Now(),
		Findings:  []*model.Finding{},
	}
	// format=json only → only result.json should appear, no report files.
	if err := saveResultAndReports(jobDir, result, &scannerconfig.Config{}); err != nil {
		t.Fatalf("saveResultAndReports: %v", err)
	}
	if _, err := os.Stat(filepath.Join(jobDir, "result.json")); err != nil {
		t.Errorf("result.json not written: %v", err)
	}
}

func TestSaveResultAndReports_AllFormats(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "j")

	result := &model.ScanResult{
		ScanID:    "test-scan",
		Timestamp: time.Now(),
		Findings:  []*model.Finding{},
	}
	// Inject format=all through package-level format var (set by root.go flags).
	origFormat := format
	format = "all"
	defer func() { format = origFormat }()

	if err := saveResultAndReports(jobDir, result, &scannerconfig.Config{}); err != nil {
		t.Fatalf("saveResultAndReports: %v", err)
	}
	// At least result.json + some files in reports/ should exist.
	if _, err := os.Stat(filepath.Join(jobDir, "result.json")); err != nil {
		t.Errorf("result.json missing: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(jobDir, "reports"))
	if err != nil {
		t.Fatalf("read reports dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("reports/ should contain at least one file when format=all")
	}
}
```

Note: the test relies on the package-level `format` variable declared in `cmd/root.go`. That variable is already set by the `--format` flag in foreground flow; we reuse it in detached flow.

- [ ] **Step 2: Verify red**

Run: `go test ./cmd/... -v -run SaveResultAndReports`
Expected: FAIL — current stub writes only result.json; the "AllFormats" test expects files in reports/.

- [ ] **Step 3: Replace the stub with real implementation**

In `cmd/scan_jobs.go`, replace the `saveResultAndReports` stub with:

```go
import (
	"github.com/amiryahaya/triton/pkg/report"
	// keep existing imports
)

// saveResultAndReports writes result.json and generates configured
// report formats into jobDir/reports/ using the existing report.Generator.
// Honours the package-level `format` variable (set by --format flag):
//   - "json": only result.json (no reports/)
//   - "cdx"/"html"/"sarif"/"xlsx": only that one format
//   - "all": all five formats
func saveResultAndReports(jobDir string, result *model.ScanResult, cfg *scannerconfig.Config) error {
	// Canonical JSON result (always written; required by --collect --format json).
	if err := jobrunner.WriteJSON(filepath.Join(jobDir, "result.json"), result); err != nil {
		return fmt.Errorf("write result.json: %w", err)
	}

	reportsDir := filepath.Join(jobDir, "reports")
	if err := os.MkdirAll(reportsDir, 0o700); err != nil {
		return fmt.Errorf("create reports dir: %w", err)
	}

	ts := result.Timestamp.Format("2006-01-02T15-04-05")
	gen := report.NewGenerator()

	writers := map[string]func() error{
		"json": func() error {
			return gen.GenerateTritonJSON(result, filepath.Join(reportsDir, "triton-report-"+ts+".json"))
		},
		"cdx": func() error {
			return gen.GenerateCycloneDXBOM(result, filepath.Join(reportsDir, "triton-report-"+ts+".cdx.json"))
		},
		"html": func() error {
			return gen.GenerateHTML(result, filepath.Join(reportsDir, "triton-report-"+ts+".html"))
		},
		"sarif": func() error {
			return gen.GenerateSARIF(result, filepath.Join(reportsDir, "triton-report-"+ts+".sarif"))
		},
		"xlsx": func() error {
			return gen.GenerateXLSX(result, filepath.Join(reportsDir, "triton-report-"+ts+".xlsx"))
		},
	}

	var formats []string
	switch format {
	case "all":
		formats = []string{"json", "cdx", "html", "sarif", "xlsx"}
	case "":
		// no-op: result.json only
	default:
		formats = []string{format}
	}

	for _, f := range formats {
		if w, ok := writers[f]; ok {
			if err := w(); err != nil {
				return fmt.Errorf("generate %s: %w", f, err)
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Verify green**

Run: `go test ./cmd/... -race -v -run SaveResultAndReports`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/scan_jobs.go cmd/scan_jobs_test.go
git commit -m "feat(cmd): generate result.json and reports/ in detached daemon"
```

---

## Task 13: Parent-side spawn — runScanDetached

**Files:**
- Modify: `cmd/scan_jobs.go` — append `runScanDetached`

- [ ] **Step 1: Write the failing test**

Skip automated test — runScanDetached spawns a real subprocess and is best exercised by the Task 15 integration test. The logic inside is straightforward: build a job-id, mkdir, snapshot config, delegate to jobrunner.Spawn, print the id.

- [ ] **Step 2: Implement**

Append to `cmd/scan_jobs.go`:

```go
import (
	// keep existing imports
	"github.com/google/uuid"
)

// runScanDetached is the parent-side entry point for `triton scan --detach`.
// Generates a job-id, creates the work-dir, snapshots the scan config,
// spawns a detached child via jobrunner.Spawn, writes the initial status,
// and prints the job-id to stdout. Returns immediately after fork.
func runScanDetached(cmd *cobra.Command, args []string) error {
	jobID := detachJobID
	if jobID == "" {
		jobID = uuid.NewString()
	}
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)

	// Refuse if a job-dir for this id already exists (prevents accidental
	// overwrite of a running or recently-finished job).
	existing := jobrunner.JobDir(workDir, jobID)
	if _, err := os.Stat(existing); err == nil {
		return fmt.Errorf("job %s already exists at %s; use --cleanup first", jobID, existing)
	}

	jobDir, err := jobrunner.EnsureJobDir(workDir, jobID)
	if err != nil {
		return fmt.Errorf("create job dir: %w", err)
	}

	// Snapshot the scan config for debugability.
	cfg, err := buildScanConfigForCmd(cmd)
	if err != nil {
		_ = os.RemoveAll(jobDir)
		return fmt.Errorf("build scan config: %w", err)
	}
	_ = jobrunner.WriteJSON(filepath.Join(jobDir, "config.json"), cfg)

	// Build limits (parent-side only: used for the startup log line).
	lim, err := buildLimitsForCmd(cmd)
	if err != nil {
		_ = os.RemoveAll(jobDir)
		return err
	}

	host, _ := os.Hostname()
	initial := jobrunner.InitialStatus(jobID, 0, scanProfile, versionString(), lim.String())
	initial.Host = host
	_ = jobrunner.WriteStatusAtomic(jobDir, initial)

	// Spawn the detached child, passing the CLI args minus --detach
	// (so the child doesn't recurse).
	childArgs := rebuildArgsWithoutDetach(os.Args[1:])
	pid, err := jobrunner.Spawn(jobrunner.SpawnConfig{
		Executable: os.Args[0],
		Args:       childArgs,
		Env: []string{
			"TRITON_DETACHED=1",
			"TRITON_JOB_ID=" + jobID,
			"TRITON_WORK_DIR=" + workDir,
		},
		JobDir: jobDir,
	})
	if err != nil {
		_ = os.RemoveAll(jobDir)
		return fmt.Errorf("spawn daemon: %w", err)
	}

	// Update status with the real pid.
	if s, rerr := jobrunner.ReadStatus(jobDir); rerr == nil {
		s.PID = pid
		_ = jobrunner.WriteStatusAtomic(jobDir, s)
	}

	if detachQuiet {
		fmt.Println(jobID)
	} else {
		fmt.Printf("Detached as job %s\npid %d, work-dir %s\n", jobID, pid, jobDir)
	}
	return nil
}

// rebuildArgsWithoutDetach returns os.Args[1:] with `--detach` removed so
// the child process does not recursively detach.
func rebuildArgsWithoutDetach(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--detach" {
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// versionString returns the build-time version (from cmd/root.go's
// version.Version) as a string. Stubbed here; referenced from existing
// cmd package state.
func versionString() string {
	return versionPackage
}
```

**Note to implementer:** `versionPackage` is a placeholder for whatever the existing package uses. Look in `cmd/root.go` for how `rootCmd.Version` is populated — likely via an import like `github.com/amiryahaya/triton/internal/version`. Reuse that same import/identifier here.

Also, `detachJobID`, `detachWorkDir`, `detachQuiet` are package-level flag variables to be declared alongside the existing ones in `cmd/root.go` — that's Task 14. For now, define temporary stubs in scan_jobs.go so this compiles:

```go
// Flag-backed vars. Wired to cobra in Task 14.
var (
	detachJobID   string
	detachWorkDir string
	detachQuiet   bool
)
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: succeeds.

- [ ] **Step 4: Commit**

```bash
git add cmd/scan_jobs.go
git commit -m "feat(cmd): runScanDetached — parent-side fork-exec"
```

---

## Task 14: CLI dispatchers for --status/--collect/--cancel/--list-jobs/--cleanup

**Files:**
- Modify: `cmd/scan_jobs.go` — append 5 dispatcher functions
- Modify: `cmd/scan_jobs_test.go` — append unit tests

- [ ] **Step 1: Write the failing tests**

Append to `cmd/scan_jobs_test.go`:

```go
func TestRunJobStatus_NotFound(t *testing.T) {
	tmp := t.TempDir()
	err := runJobStatusCore(tmp, "nope", false)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got %v", err)
	}
}

func TestRunJobStatus_JSON(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "j")
	s := jobrunner.InitialStatus("j", 1, "q", "v", "")
	s.State = jobrunner.StateDone
	jobrunner.WriteStatusAtomic(jobDir, s)

	// Redirect stdout to capture JSON output.
	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	err := runJobStatusCore(tmp, "j", true)
	w.Close()
	os.Stdout = orig
	if err != nil {
		t.Fatal(err)
	}
	buf, _ := io.ReadAll(r)
	if !strings.Contains(string(buf), `"state": "done"`) {
		t.Errorf("expected state=done in JSON output, got %s", buf)
	}
}

func TestRunJobCollect_RefusesRunning(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "j")
	s := jobrunner.InitialStatus("j", os.Getpid(), "q", "v", "")
	s.State = jobrunner.StateRunning
	jobrunner.WriteStatusAtomic(jobDir, s)

	err := runJobCollectCore(tmp, "j", "", "json", false, func(int) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "running") {
		t.Errorf("expected 'running' error, got %v", err)
	}
}

func TestRunJobCollect_JSONToStdout(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "j")
	s := jobrunner.InitialStatus("j", 1, "q", "v", "")
	s.State = jobrunner.StateDone
	jobrunner.WriteStatusAtomic(jobDir, s)
	os.WriteFile(filepath.Join(jobDir, "result.json"), []byte(`{"findings":[]}`), 0o600)

	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	err := runJobCollectCore(tmp, "j", "-", "json", true, func(int) bool { return false })
	w.Close()
	os.Stdout = orig
	if err != nil {
		t.Fatal(err)
	}
	buf, _ := io.ReadAll(r)
	if !strings.Contains(string(buf), "findings") {
		t.Errorf("expected result JSON on stdout, got %s", buf)
	}
}

func TestRunJobCancel_AsyncTouchesFlag(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "j")
	s := jobrunner.InitialStatus("j", os.Getpid(), "q", "v", "")
	s.State = jobrunner.StateRunning
	jobrunner.WriteStatusAtomic(jobDir, s)

	if err := runJobCancelCore(tmp, "j", false, 0); err != nil {
		t.Fatalf("runJobCancelCore: %v", err)
	}
	if !jobrunner.IsCancelled(jobDir) {
		t.Error("cancel.flag should be touched after runJobCancelCore")
	}
}

func TestRunJobList_FormatsOutput(t *testing.T) {
	tmp := t.TempDir()
	for _, id := range []string{"a", "b"} {
		jobDir, _ := jobrunner.EnsureJobDir(tmp, id)
		s := jobrunner.InitialStatus(id, 1, "q", "v", "")
		s.State = jobrunner.StateDone
		jobrunner.WriteStatusAtomic(jobDir, s)
	}
	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	err := runJobListCore(tmp, false)
	w.Close()
	os.Stdout = orig
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "a") || !strings.Contains(string(out), "b") {
		t.Errorf("expected both job ids in output, got %s", out)
	}
}

func TestRunJobCleanup_FinishedOnly(t *testing.T) {
	tmp := t.TempDir()
	jobDirDone, _ := jobrunner.EnsureJobDir(tmp, "done")
	s := jobrunner.InitialStatus("done", 1, "q", "v", "")
	s.State = jobrunner.StateDone
	jobrunner.WriteStatusAtomic(jobDirDone, s)

	if err := runJobCleanupCore(tmp, "done", false); err != nil {
		t.Fatalf("runJobCleanupCore: %v", err)
	}
	if _, err := os.Stat(jobDirDone); !os.IsNotExist(err) {
		t.Error("job dir should be removed after cleanup")
	}
}
```

Add to `cmd/scan_jobs_test.go` imports: `"io"`, `"strings"`.

- [ ] **Step 2: Verify red**

Run: `go test ./cmd/... -v -run 'JobStatus|JobCollect|JobCancel|JobList|JobCleanup'`
Expected: FAIL — undefined runJob*Core functions.

- [ ] **Step 3: Implement the five dispatchers**

Append to `cmd/scan_jobs.go`:

```go
import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
	"text/tabwriter"
	// keep existing imports
)

// --- runJobStatus ---

func runJobStatus(cmd *cobra.Command, args []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	jsonOut, _ := cmd.Flags().GetBool("json")
	return runJobStatusCore(workDir, detachJobID, jsonOut)
}

// runJobStatusCore is the testable form.
func runJobStatusCore(workDir, jobID string, jsonOut bool) error {
	if jobID == "" {
		return errors.New("--job-id required")
	}
	jobDir := jobrunner.JobDir(workDir, jobID)
	s, changed, err := jobrunner.Reconcile(jobDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("job %s not found at %s", jobID, jobDir)
		}
		return err
	}
	_ = changed
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	fmt.Printf("job_id:         %s\n", s.JobID)
	fmt.Printf("state:          %s\n", s.State)
	fmt.Printf("pid:            %d\n", s.PID)
	fmt.Printf("started_at:     %s\n", s.StartedAt.Format(time.RFC3339))
	fmt.Printf("updated_at:     %s\n", s.UpdatedAt.Format(time.RFC3339))
	fmt.Printf("progress:       %.1f%%\n", s.ProgressPct)
	fmt.Printf("current_module: %s\n", s.CurrentModule)
	fmt.Printf("findings:       %d\n", s.FindingsCount)
	fmt.Printf("rss_mb:         %d\n", s.RSSMB)
	fmt.Printf("limits:         %s\n", s.Limits)
	if s.Error != "" {
		fmt.Printf("error:          %s\n", s.Error)
	}
	return nil
}

// --- runJobCollect ---

func runJobCollect(cmd *cobra.Command, args []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	out, _ := cmd.Flags().GetString("output")
	keep, _ := cmd.Flags().GetBool("keep")
	return runJobCollectCore(workDir, detachJobID, out, format, keep, realPIDAliveCmd)
}

// runJobCollectCore is the testable form. pidAlive is a seam for tests.
func runJobCollectCore(workDir, jobID, outputPath, fmtName string, keep bool, pidAlive func(int) bool) error {
	if jobID == "" {
		return errors.New("--job-id required")
	}
	jobDir := jobrunner.JobDir(workDir, jobID)
	s, err := jobrunner.ReadStatus(jobDir)
	if err != nil {
		return fmt.Errorf("read status: %w", err)
	}
	if !s.State.IsTerminal() && s.PID > 0 && pidAlive(s.PID) {
		return fmt.Errorf("job %s is running (pid %d); cancel first or wait", jobID, s.PID)
	}

	switch fmtName {
	case "json":
		return writeCollectedFile(filepath.Join(jobDir, "result.json"), outputPath, keep, jobDir)
	case "", "tar", "all":
		return writeCollectedTar(filepath.Join(jobDir, "reports"), outputPath, keep, jobDir)
	default:
		// Single-format pick: look for a file with that extension.
		matches, _ := filepath.Glob(filepath.Join(jobDir, "reports", "*."+fmtName))
		if len(matches) == 0 {
			return fmt.Errorf("no %s report found in %s/reports", fmtName, jobDir)
		}
		return writeCollectedFile(matches[0], outputPath, keep, jobDir)
	}
}

// writeCollectedFile copies src to out (or stdout if out == "-"), then
// deletes jobDir unless keep.
func writeCollectedFile(src, out string, keep bool, jobDir string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	var w io.Writer
	if out == "" || out == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if _, err := io.Copy(w, in); err != nil {
		return err
	}
	if !keep {
		return os.RemoveAll(jobDir)
	}
	return nil
}

// writeCollectedTar creates a .tar.gz of the reports/ directory.
func writeCollectedTar(reportsDir, out string, keep bool, jobDir string) error {
	var w io.Writer
	if out == "" || out == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	err := filepath.Walk(reportsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(reportsDir, path)
		hdr, _ := tar.FileInfoHeader(info, "")
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return err
	}
	if !keep {
		return os.RemoveAll(jobDir)
	}
	return nil
}

// --- runJobCancel ---

func runJobCancel(cmd *cobra.Command, args []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	wait, _ := cmd.Flags().GetBool("wait")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	return runJobCancelCore(workDir, detachJobID, wait, timeout)
}

// runJobCancelCore is the testable form.
func runJobCancelCore(workDir, jobID string, wait bool, timeout time.Duration) error {
	if jobID == "" {
		return errors.New("--job-id required")
	}
	jobDir := jobrunner.JobDir(workDir, jobID)
	if _, err := os.Stat(jobDir); os.IsNotExist(err) {
		return fmt.Errorf("job %s not found", jobID)
	}
	if err := jobrunner.TouchCancelFlag(jobDir); err != nil {
		return fmt.Errorf("touch cancel.flag: %w", err)
	}
	fmt.Printf("cancel requested for %s\n", jobID)

	if !wait {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s, err := jobrunner.ReadStatus(jobDir)
		if err == nil && s.State.IsTerminal() {
			fmt.Printf("job %s reached terminal state: %s\n", jobID, s.State)
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("job %s did not terminate within %s (cancel still pending)", jobID, timeout)
}

// --- runJobList ---

func runJobList(cmd *cobra.Command, args []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	jsonOut, _ := cmd.Flags().GetBool("json")
	return runJobListCore(workDir, jsonOut)
}

// runJobListCore is the testable form.
func runJobListCore(workDir string, jsonOut bool) error {
	jobs, err := jobrunner.List(workDir)
	if err != nil {
		return err
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(jobs)
	}
	if len(jobs) == 0 {
		fmt.Println("no jobs found")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "JOB ID\tSTATE\tSTARTED\tPROGRESS\tFINDINGS")
	for _, j := range jobs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.1f%%\t%d\n",
			j.JobID, j.Status.State,
			j.Status.StartedAt.Format("2006-01-02 15:04:05"),
			j.Status.ProgressPct, j.Status.FindingsCount)
	}
	return tw.Flush()
}

// --- runJobCleanup ---

func runJobCleanup(cmd *cobra.Command, args []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	all, _ := cmd.Flags().GetBool("all")
	return runJobCleanupCore(workDir, detachJobID, all)
}

// runJobCleanupCore is the testable form.
func runJobCleanupCore(workDir, jobID string, all bool) error {
	if all {
		n, err := jobrunner.RemoveAll(workDir)
		if err != nil {
			return err
		}
		fmt.Printf("removed %d finished jobs\n", n)
		return nil
	}
	if jobID == "" {
		return errors.New("--job-id or --all required")
	}
	if err := jobrunner.Remove(workDir, jobID); err != nil {
		return err
	}
	fmt.Printf("removed job %s\n", jobID)
	return nil
}

// realPIDAliveCmd is the cmd-package wrapper around jobrunner's unexported
// realPIDAlive, needed because tests inject a seam. We re-export via a
// small wrapper so we don't widen jobrunner's surface.
func realPIDAliveCmd(pid int) bool {
	// Uses the same semantics as jobrunner.realPIDAlive by attempting
	// Signal(0).
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(nil) == nil || true
	// NOTE: os.Process.Signal(nil) is not standard; tests use the injected
	// seam. In production, jobrunner.Reconcile already handles liveness
	// for status lookups, so this wrapper is only used by runJobCollectCore.
	// Real implementation is delegated to the stale.go package function via
	// the exported Reconcile path in production flows.
}
```

**Note to implementer:** the `realPIDAliveCmd` implementation above is a placeholder. The clean fix is to export `jobrunner.IsProcessAlive(pid int) bool` — add it to `stale.go` when you do this task. Replace the body with:

```go
func realPIDAliveCmd(pid int) bool {
	return jobrunner.IsProcessAlive(pid)
}
```

And in `internal/runtime/jobrunner/stale.go`, add the exported wrapper:

```go
// IsProcessAlive is the exported wrapper for realPIDAlive. Returns true
// iff a process with the given PID is reachable via signal-0.
func IsProcessAlive(pid int) bool { return realPIDAlive(pid) }
```

Commit both changes together. The test remains unchanged because it injects its own `pidAlive` func.

- [ ] **Step 4: Verify green + race**

Run: `go test ./cmd/... ./internal/runtime/jobrunner/... -race -v -run 'Job|IsProcessAlive'`
Expected: PASS — 7 new tests in cmd + pre-existing jobrunner tests still pass.

- [ ] **Step 5: Verify gofmt + vet + windows**

Run: `gofmt -l cmd/ internal/runtime/jobrunner/ && go vet ./... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add cmd/scan_jobs.go cmd/scan_jobs_test.go internal/runtime/jobrunner/stale.go
git commit -m "feat(cmd): --status/--collect/--cancel/--list-jobs/--cleanup dispatchers"
```

---

## Task 15: Wire flags into cmd/root.go + dispatch switch

**Files:**
- Modify: `cmd/root.go`

- [ ] **Step 1: Register the new flags in init()**

Find the `init()` function in `cmd/root.go` (around line 151). After the final `_ = viper.BindPFlag(...)` call, add this block BEFORE the closing `}` of `init()`:

```go
	// Job-runner lifecycle flags (wired to runScan via dispatch switch).
	rootCmd.PersistentFlags().BoolVar(&detachMode, "detach", false,
		"run scan as a detached background job (returns job-id, survives SSH disconnect)")
	rootCmd.PersistentFlags().BoolVar(&statusMode, "status", false,
		"print status of a detached scan (requires --job-id)")
	rootCmd.PersistentFlags().BoolVar(&collectMode, "collect", false,
		"retrieve reports from a detached scan (requires --job-id)")
	rootCmd.PersistentFlags().BoolVar(&cancelMode, "cancel", false,
		"cancel a running detached scan (requires --job-id)")
	rootCmd.PersistentFlags().BoolVar(&listJobsMode, "list-jobs", false,
		"list all detached scan jobs under the work-dir")
	rootCmd.PersistentFlags().BoolVar(&cleanupMode, "cleanup", false,
		"remove finished job(s) from the work-dir (requires --job-id or --all)")

	rootCmd.PersistentFlags().StringVar(&detachJobID, "job-id", "",
		"explicit job id (default: auto-generated UUID for --detach)")
	rootCmd.PersistentFlags().StringVar(&detachWorkDir, "work-dir", "",
		"work-dir root for job state (default: ~/.triton/jobs)")
	rootCmd.PersistentFlags().BoolVar(&detachQuiet, "quiet", false,
		"print only the job-id on --detach (for scripting)")
	rootCmd.PersistentFlags().Bool("wait", false,
		"block until daemon terminates (only with --cancel)")
	rootCmd.PersistentFlags().Duration("timeout", 30*time.Second,
		"timeout for --cancel --wait")
	rootCmd.PersistentFlags().Bool("keep", false,
		"do not auto-remove the work-dir after --collect")
	rootCmd.PersistentFlags().Bool("all", false,
		"remove all finished jobs (only with --cleanup)")
	rootCmd.PersistentFlags().Bool("json", false,
		"machine-readable output for --status / --list-jobs")

	rootCmd.MarkFlagsMutuallyExclusive(
		"detach", "status", "collect", "cancel", "list-jobs", "cleanup",
	)
```

Also declare the new vars at the top of `cmd/root.go` in the existing `var (...)` block (around line 30-70):

```go
	// Job-runner lifecycle mode flags (one-of-six; mutually exclusive).
	detachMode   bool
	statusMode   bool
	collectMode  bool
	cancelMode   bool
	listJobsMode bool
	cleanupMode  bool
```

(`detachJobID`, `detachWorkDir`, `detachQuiet` are already declared in scan_jobs.go from Task 13; remove the temporary declarations there and use these package-level vars instead.)

- [ ] **Step 2: Add dispatch at the top of runScan**

Find `func runScan(cmd *cobra.Command, args []string) error {` (around line 322). Immediately after the opening brace and any current first-line checks (e.g. `if !validFormats[format] {`), add this dispatch BEFORE the existing body:

```go
	// Daemon mode: started by a parent via TRITON_DETACHED=1.
	if isDaemonMode() {
		return runScanDaemon(cmd, args)
	}
	// Lifecycle modes: mutually exclusive, dispatched to scan_jobs.go.
	switch {
	case detachMode:
		return runScanDetached(cmd, args)
	case statusMode:
		return runJobStatus(cmd, args)
	case collectMode:
		return runJobCollect(cmd, args)
	case cancelMode:
		return runJobCancel(cmd, args)
	case listJobsMode:
		return runJobList(cmd, args)
	case cleanupMode:
		return runJobCleanup(cmd, args)
	}
```

- [ ] **Step 3: Remove temporary var declarations from scan_jobs.go**

In `cmd/scan_jobs.go`, delete these lines (added in Task 13 as stubs; now they exist in root.go):

```go
var (
	detachJobID   string
	detachWorkDir string
	detachQuiet   bool
)
```

- [ ] **Step 4: Build and test**

Run: `go build ./... && go test ./... -race`
Expected: all pass.

- [ ] **Step 5: Smoke-test the CLI**

Run: `go run . --help 2>&1 | grep -E "detach|status|collect|cancel|list-jobs|cleanup|job-id|work-dir|keep"`
Expected: all new flags appear.

Run: `go run . --detach --profile quick --max-duration 10s 2>&1 | tail -5`
Expected: prints `Detached as job <uuid>` (or just the UUID if `--quiet`). A background scan starts.

Run: `go run . --list-jobs 2>&1 | tail -5`
Expected: the newly-spawned job appears.

Run: `JOB_ID=<uuid-from-above>; go run . --status --job-id $JOB_ID`
Expected: prints status fields.

Run: `go run . --cancel --job-id $JOB_ID --wait --timeout 15s`
Expected: cancel acknowledged; within ~4s status transitions to cancelled.

Run: `go run . --cleanup --job-id $JOB_ID`
Expected: prints `removed job <id>`.

- [ ] **Step 6: Verify gofmt + vet + windows**

Run: `gofmt -l cmd/ && go vet ./... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add cmd/root.go cmd/scan_jobs.go
git commit -m "feat(cmd): wire --detach/--status/--collect/--cancel/--list-jobs/--cleanup flags"
```

---

## Task 16: Integration test — end-to-end detached scan

**Files:**
- Create: `test/integration/scan_jobs_test.go`

- [ ] **Step 1: Write the test**

Create `test/integration/scan_jobs_test.go`:

```go
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

func TestJobRunner_EndToEnd_Cancel(t *testing.T) {
	bin := buildTritonBinary(t)
	workDir := t.TempDir()

	// Spawn detached scan.
	cmd := exec.Command(bin, "--detach", "--profile", "quick", "--max-duration", "30s",
		"--work-dir", workDir, "--quiet", "--license-key", "")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("detach failed: %v: %s", err, out)
	}
	jobID := strings.TrimSpace(string(out))
	if jobID == "" {
		t.Fatal("no job-id from --detach --quiet")
	}

	// Wait for state=running.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s, err := jobrunner.ReadStatus(filepath.Join(workDir, jobID))
		if err == nil && s.State == jobrunner.StateRunning {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Cancel with --wait.
	cancelCmd := exec.Command(bin, "--cancel", "--job-id", jobID,
		"--work-dir", workDir, "--wait", "--timeout", "15s", "--license-key", "")
	out2, err := cancelCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cancel failed: %v: %s", err, out2)
	}

	// Verify terminal state is cancelled.
	s, err := jobrunner.ReadStatus(filepath.Join(workDir, jobID))
	if err != nil {
		t.Fatalf("read status after cancel: %v", err)
	}
	if s.State != jobrunner.StateCancelled {
		t.Errorf("state after cancel: got %q, want %q", s.State, jobrunner.StateCancelled)
	}
	if s.CompletedAt == nil {
		t.Error("CompletedAt should be populated after terminal state")
	}
}

func TestJobRunner_EndToEnd_Complete(t *testing.T) {
	bin := buildTritonBinary(t)
	workDir := t.TempDir()

	// Use a scan target that completes fast (empty directory → no findings but clean completion).
	tmp := t.TempDir()
	cmd := exec.Command(bin, "--detach", "--profile", "quick", "--max-duration", "10s",
		"--work-dir", workDir, "--quiet", "--license-key", "", tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("detach failed: %v: %s", err, out)
	}
	jobID := strings.TrimSpace(string(out))

	// Wait for terminal state.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		s, err := jobrunner.ReadStatus(filepath.Join(workDir, jobID))
		if err == nil && s.State.IsTerminal() {
			if s.State == jobrunner.StateDone {
				return // happy path
			}
			if s.State == jobrunner.StateFailed {
				t.Fatalf("scan failed: %s", s.Error)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Error("scan did not reach terminal state within 20s")
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
```

- [ ] **Step 2: Run the test**

Run: `go test -tags integration ./test/integration/... -v -run TestJobRunner`
Expected: PASS — 3 tests.

Note: integration tests may take 30-60s due to real `go build` and scan execution. Consider `-timeout 180s` if CI flakes.

- [ ] **Step 3: Commit**

```bash
git add test/integration/scan_jobs_test.go
git commit -m "test(integration): end-to-end detached scan lifecycle (detach/status/cancel/complete/stale)"
```

---

## Task 17: Documentation

**Files:**
- Modify: `README.md` — add a "Detached scans" section under Usage
- Modify: `CLAUDE.md` — add a `### Job runner (detached scans)` reference under the existing "Resource limits" subsection

- [ ] **Step 1: Add README section**

In `README.md`, find the "Resource limits" section added by PR #71. After that section (before the next top-level `##`), insert:

```markdown
### Detached scans

Run a scan in the background so you can disconnect the SSH session, check progress later, and retrieve reports when done:

```bash
# Start a detached scan; returns a job-id immediately
JOB=$(triton scan --detach --profile standard --max-duration 4h --quiet)

# Disconnect SSH. Come back any time.

# Check progress
triton scan --status --job-id $JOB --json | jq .progress_pct

# Cancel (optional; waits up to 30s for graceful shutdown)
triton scan --cancel --job-id $JOB --wait

# Retrieve reports (streams a tar.gz; auto-cleans unless --keep)
triton scan --collect --job-id $JOB -o scan.tar.gz

# List all jobs
triton scan --list-jobs

# Manual cleanup (also happens automatically on --collect)
triton scan --cleanup --job-id $JOB
triton scan --cleanup --all        # all finished jobs
```

**Work-dir layout:** `~/.triton/jobs/<job-id>/` (override with `--work-dir`). Each job-dir contains `pid`, `status.json`, `cancel.flag`, `scan.log`, `reports/`, and `result.json`.

**SSH-agentless flow:**

```bash
# One-shot: copy binary, kick off detached scan, come back later
scp triton host:/tmp/
JOB=$(ssh host 'sudo /tmp/triton scan --detach --profile standard --max-memory 2GB --quiet')
# ...
ssh host "triton scan --collect --job-id $JOB -o -" > scan-$JOB.tar.gz
ssh host "rm /tmp/triton"
```

**Compatibility:** All flags work on Linux, macOS, and Windows. Cancellation uses a file-flag (not signals) for cross-platform parity.
```

- [ ] **Step 2: Add CLAUDE.md reference**

In `CLAUDE.md`, find the `### Resource limits (orthogonal to profile)` subsection. Immediately after it (before the next `###`), add:

```markdown
### Job runner (detached scans)

The `triton scan` command accepts six lifecycle flags — `--detach`, `--status`, `--collect`, `--cancel`, `--list-jobs`, `--cleanup` — implemented in `internal/runtime/jobrunner/`. A detached scan fork-exec's itself with `TRITON_DETACHED=1`, writes state to `~/.triton/jobs/<job-id>/`, and reuses the same `Limits.Apply()` pipeline as foreground scans. Cancellation is cooperative via `cancel.flag` for cross-platform parity. See `internal/runtime/jobrunner/doc.go` for caveats and `docs/plans/2026-04-18-job-runner-design.md` for the design spec.
```

- [ ] **Step 3: Verify build still clean**

Run: `go build ./... && go test ./... -race`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: document detached scan lifecycle (job runner)"
```

---

## Task 18: Final verification gates

Same pattern as PR #71 Task 10.

- [ ] **Step 1: Full build all platforms**

```bash
go build ./... && \
  GOOS=windows GOARCH=amd64 go build ./... && \
  GOOS=linux GOARCH=arm64 go build ./... && \
  GOOS=darwin GOARCH=arm64 go build ./...
```

Expected: all succeed.

- [ ] **Step 2: Full test suite with race detector**

```bash
go test ./... -race
```

Expected: all pass.

- [ ] **Step 3: Integration tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./test/integration/... -race -run 'TestJobRunner|TestLimitsApply' -timeout 180s
```

Expected: all pass.

- [ ] **Step 4: Lint**

```bash
golangci-lint run ./internal/runtime/jobrunner/... ./cmd/...
```

Expected: no new warnings.

- [ ] **Step 5: gofmt**

```bash
gofmt -l internal/runtime/jobrunner/ cmd/ test/integration/scan_jobs_test.go
```

Expected: no output.

- [ ] **Step 6: Coverage check**

```bash
go test -cover ./internal/runtime/jobrunner/... ./cmd/...
```

Expected: ≥80% on `internal/runtime/jobrunner/`.

- [ ] **Step 7: Smoke-test the help**

```bash
go run . --help | grep -E "detach|status|collect|cancel|list-jobs|cleanup|job-id|work-dir"
```

Expected: all flags appear with help text.

- [ ] **Step 8: End-to-end smoke**

```bash
WORK=$(mktemp -d)
JOB=$(go run . --detach --profile quick --max-duration 5s --work-dir $WORK --quiet)
echo "job=$JOB"
sleep 2
go run . --status --job-id $JOB --work-dir $WORK --json | head -20
sleep 5
go run . --list-jobs --work-dir $WORK
go run . --collect --job-id $JOB --work-dir $WORK -o $WORK/report.tar.gz --format tar
ls -la $WORK
```

Expected: job transitions to `done` or `cancelled` (depending on whether scan completes within 5s); tar.gz is created; after --collect the job-dir is removed (no --keep).

---

## Self-Review Checklist

Run this yourself before declaring the feature complete.

**1. Spec coverage:**

- ✅ §CLI surface: all 15 flags registered (Task 14)
- ✅ §Work-dir schema: pid, state.lock, started_at, config.json, status.json, scan.log, cancel.flag, reports/, result.json — all covered across Tasks 2, 3, 6, 8, 12
- ✅ §Atomicity: write-tmp-rename for status.json, result.json, pid (Tasks 2, 8)
- ✅ §Stale detection: Reconcile called from --status and --list-jobs flows (Tasks 6, 14)
- ✅ §Daemon lifecycle: runScanDaemon with three goroutines (scan + status + cancel) (Task 11)
- ✅ §Graceful shutdown ordering: cancel.flag → baseCancel → ctx.Done → writeStatusLoop flush → exit (Task 10)
- ✅ §Cancel --wait: 500ms polling with --timeout (Task 14)
- ✅ §Reports + --collect: result.json, tar.gz of reports/, single-format extraction (Tasks 12, 14)
- ✅ §Error handling matrix: duplicate job-id, missing job, running collect, stale daemon — all exercised (Tasks 6, 9, 13, 14)
- ✅ §Cross-platform: detach_unix/detach_windows, lock_unix/lock_windows, stale_unix/stale_windows (Tasks 3, 6, 7)

**2. Placeholder scan:**
None detected. Task 11 has explicit notes about stubbed helpers (`buildScanConfigForCmd`, `saveResultAndReports`) and calls out that they're replaced in Tasks 12 and 14. Task 13 has an explicit `versionPackage` placeholder with a note to the implementer; this needs resolution during implementation.

**3. Type consistency:**
- `Status.State` is `State` enum (string type) — consistent across tasks
- `JobSummary{JobID, Status}` — Task 9 definition used by Task 14 correctly
- `SpawnConfig{Executable, Args, Env, JobDir}` — Task 8 definition used by Task 13 correctly
- `Limits.Apply` signature from PR #71 — used verbatim in Task 11
- `runtime.MemStats.Sys / (1 << 20)` for RSS MB — matches PR #71's `sampleGoRuntimeMem`
- `buildLimits` from PR #71 cmd/root.go — reused in Task 11's `buildLimitsForCmd`

**4. Order dependency sanity:**
- Task 3 introduces `golang.org/x/sys` if missing. All subsequent tasks assume it's available.
- Task 6 depends on Task 2 (ReadStatus/WriteStatusAtomic). ✓
- Task 9 depends on Tasks 4, 6 (JobDir, realPIDAlive). ✓
- Task 11 depends on all of Tasks 1-10. ✓
- Task 13 depends on Task 8 (Spawn), Task 11 (runScanDaemon entry). ✓
- Task 14 depends on Task 13 (detachJobID var), Task 9 (List/Remove), Task 6 (Reconcile). ✓
- Task 15 depends on all of Tasks 10-14. ✓

If tasks are executed out of order, the implementer will hit compile errors at well-defined boundaries (undefined symbols). That's acceptable — TDD-style iteration.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-04-18-job-runner-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Best for catching scope drift.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
