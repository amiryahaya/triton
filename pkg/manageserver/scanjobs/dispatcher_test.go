// pkg/manageserver/scanjobs/dispatcher_test.go
package scanjobs_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// Compile-time check: stubDispatcherStore must implement the Store methods used
// by Dispatcher. The embed provides no-op panics for all others.

// stubDispatcherStore implements only the Store methods needed by Dispatcher.
// All other methods panic if called unexpectedly.
type stubDispatcherStore struct {
	scanjobs.Store // embed for unimplemented methods

	listQueued    []scanjobs.Job
	listQueuedErr error
	listCallCount atomic.Int32

	claimErr error // if non-nil, ClaimByID returns this error
}

func (s *stubDispatcherStore) ListQueued(_ context.Context, _ []string, _ int) ([]scanjobs.Job, error) {
	s.listCallCount.Add(1)
	return s.listQueued, s.listQueuedErr
}

// ClaimByID satisfies the Store interface. Returns (Job{}, nil) by default so
// the dispatcher can proceed to spawn the subprocess. Set claimErr to simulate
// ErrAlreadyClaimed or other failures.
func (s *stubDispatcherStore) ClaimByID(_ context.Context, id uuid.UUID, _ string) (scanjobs.Job, error) {
	if s.claimErr != nil {
		return scanjobs.Job{}, s.claimErr
	}
	return scanjobs.Job{ID: id}, nil
}

// waitForFile polls until path exists or the deadline is exceeded.
// Returns true if the file appeared before the deadline.
func waitForFile(path string, deadline time.Duration) bool {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestDispatcher_SpawnsProcess verifies that when ListQueued returns one job the
// Dispatcher spawns a subprocess and the subprocess exits without error.
// A sentinel file written by the fake binary proves a real subprocess was started.
func TestDispatcher_SpawnsProcess(t *testing.T) {
	sentinelFile := filepath.Join(t.TempDir(), "spawned.txt")

	// Write a shell script that touches the sentinel file then exits.
	scriptDir := t.TempDir()
	scriptPath := filepath.Join(scriptDir, "fake-portscan.sh")
	script := fmt.Sprintf("#!/bin/sh\ntouch %s\nexit 0\n", sentinelFile)
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	jobID := uuid.New()
	store := &stubDispatcherStore{
		listQueued: []scanjobs.Job{
			{ID: jobID, JobType: scanjobs.JobTypePortSurvey},
		},
	}

	cfg := scanjobs.DispatcherConfig{
		Store:        store,
		BinaryPath:   scriptPath,
		ManageURL:    "http://localhost:9999",
		WorkerKey:    "test-key",
		Concurrency:  2,
		PollInterval: 10 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	d := scanjobs.NewDispatcher(cfg)

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Run(ctx)
	}()

	// Wait for the sentinel file, allowing up to 3s for macOS first-run
	// security checks (Gatekeeper/mds) which can delay new script execution
	// by ~400ms on the first invocation.
	if !waitForFile(sentinelFile, 3*time.Second) {
		t.Error("sentinel file not created within 3s — subprocess was not actually spawned")
	}

	cancel()
	<-done

	// ListQueued must have been called at least once.
	if store.listCallCount.Load() == 0 {
		t.Error("expected ListQueued to be called at least once")
	}
}

// TestDispatcher_RespectsConcurrencyCap verifies that with concurrency=1 and two
// queued jobs, the dispatcher does not spawn a second subprocess while the first
// is still running.
func TestDispatcher_RespectsConcurrencyCap(t *testing.T) {
	// Each spawned process touches a unique sentinel file (named after its PID)
	// then blocks on sleep 30. We embed the sentinel directory in the script so
	// no extra arguments need to be passed.
	sentinelDir := t.TempDir()
	scriptDir := t.TempDir()

	script := fmt.Sprintf("#!/bin/sh\ntouch %s/running-$$\nsleep 30\n", sentinelDir)
	scriptPath := filepath.Join(scriptDir, "blocking-portscan.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write blocking script: %v", err)
	}

	job1 := scanjobs.Job{ID: uuid.New(), JobType: scanjobs.JobTypePortSurvey}
	job2 := scanjobs.Job{ID: uuid.New(), JobType: scanjobs.JobTypePortSurvey}

	store := &stubDispatcherStore{
		listQueued: []scanjobs.Job{job1, job2},
	}

	cfg := scanjobs.DispatcherConfig{
		Store:        store,
		BinaryPath:   scriptPath,
		ManageURL:    "http://localhost:9999",
		WorkerKey:    "k",
		Concurrency:  1,
		PollInterval: 10 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	d := scanjobs.NewDispatcher(cfg)

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Run(ctx)
	}()

	// Wait until at least one sentinel file appears (the first subprocess has
	// started). Allow up to 3s for macOS first-run security checks on the new
	// script (Gatekeeper/mds can delay by ~400ms on first invocation).
	sentinelAppeared := false
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		entries, err := os.ReadDir(sentinelDir)
		if err != nil {
			t.Fatalf("read sentinel dir: %v", err)
		}
		if len(entries) >= 1 {
			sentinelAppeared = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sentinelAppeared {
		t.Fatal("no subprocess was spawned within 3s — dispatcher is broken")
	}

	// Now hold for another 300ms. With concurrency=1 and a blocking binary (sleep
	// 30), the dispatcher CANNOT spawn a second process — it is blocked waiting
	// for the semaphore slot held by the first. Exactly 1 sentinel should exist.
	time.Sleep(300 * time.Millisecond)

	entries, err := os.ReadDir(sentinelDir)
	if err != nil {
		t.Fatalf("read sentinel dir: %v", err)
	}
	if n := len(entries); n != 1 {
		t.Errorf("concurrency cap violated: expected exactly 1 subprocess running, got %d sentinel files", n)
	}

	cancel()
	<-done
}

// TestComputeCaps_ReturnsPositive verifies that ComputeCaps returns positive
// values for both maxProcs and maxMemMB.
func TestComputeCaps_ReturnsPositive(t *testing.T) {
	maxProcs, maxMemMB := scanjobs.ComputeCaps()
	if maxProcs <= 0 {
		t.Errorf("ComputeCaps: maxProcs = %d, want > 0", maxProcs)
	}
	if maxMemMB <= 0 {
		t.Errorf("ComputeCaps: maxMemMB = %d, want > 0", maxMemMB)
	}
}
