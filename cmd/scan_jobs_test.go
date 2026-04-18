package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestCancelFlagPoller_CancelsOnFlagTouch(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "job")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cancelled atomic.Bool
	fakeCancel := func() { cancelled.Store(true) }

	done := make(chan struct{})
	go func() {
		cancelFlagPollerWithInterval(ctx, jobDir, fakeCancel, 10*time.Millisecond)
		close(done)
	}()

	if err := jobrunner.TouchCancelFlag(jobDir); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cancelled.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if !cancelled.Load() {
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
		t.Error("cancelFlagPoller did not exit within 200ms of context cancel")
	}
	_ = filepath.Join
	_ = os.Getpid
}

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

func TestSaveResultAndReports_WritesResultJSON(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := jobrunner.EnsureJobDir(tmp, "j")

	result := &model.ScanResult{
		ID: "test-scan",
		Metadata: model.ScanMetadata{
			Timestamp: time.Now(),
		},
		Findings: []model.Finding{},
	}
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
		ID: "test-scan",
		Metadata: model.ScanMetadata{
			Timestamp: time.Now(),
		},
		Findings: []model.Finding{},
	}
	origFormat := format
	format = "all"
	defer func() { format = origFormat }()

	if err := saveResultAndReports(jobDir, result, &scannerconfig.Config{}); err != nil {
		t.Fatalf("saveResultAndReports: %v", err)
	}
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
