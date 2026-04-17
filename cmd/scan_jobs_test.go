package cmd

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
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

	progressCh <- scanner.Progress{Percent: 0.25, Status: "certificate"}
	progressCh <- scanner.Progress{Percent: 0.50, Status: "library"}
	time.Sleep(50 * time.Millisecond)
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
