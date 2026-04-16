package scanjobs

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// reclaimRecorder captures the cutoff passed to ReclaimStale. Other Store
// methods are unreachable in a reaper test so they return zero values.
type reclaimRecorder struct {
	mu     sync.Mutex
	calls  []time.Time
	notify chan struct{}
}

func (r *reclaimRecorder) ReclaimStale(_ context.Context, cutoff time.Time) error {
	r.mu.Lock()
	r.calls = append(r.calls, cutoff)
	n := r.notify
	r.mu.Unlock()
	if n != nil {
		select {
		case n <- struct{}{}:
		default:
		}
	}
	return nil
}

// Unused Store methods — zero-value returns.
func (r *reclaimRecorder) CreateJob(context.Context, Job) (Job, error) { return Job{}, nil }
func (r *reclaimRecorder) GetJob(context.Context, uuid.UUID, uuid.UUID) (Job, error) {
	return Job{}, nil
}
func (r *reclaimRecorder) ListJobs(context.Context, uuid.UUID, int) ([]Job, error) { return nil, nil }
func (r *reclaimRecorder) CancelJob(context.Context, uuid.UUID, uuid.UUID) error   { return nil }
func (r *reclaimRecorder) ClaimNext(context.Context, uuid.UUID) (JobPayload, bool, error) {
	return JobPayload{}, false, nil
}
func (r *reclaimRecorder) UpdateProgress(context.Context, uuid.UUID, uuid.UUID, int, int) error {
	return nil
}
func (r *reclaimRecorder) FinishJob(context.Context, uuid.UUID, uuid.UUID, JobStatus, string) error {
	return nil
}
func (r *reclaimRecorder) RecordScanResult(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, []byte) error {
	return nil
}

var _ Store = (*reclaimRecorder)(nil)

func TestStaleReaper_ReclaimsOnTick(t *testing.T) {
	fixedNow := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	notify := make(chan struct{}, 1)
	store := &reclaimRecorder{notify: notify}
	r := &StaleReaper{
		Store:    store,
		Interval: 10 * time.Millisecond,
		Timeout:  30 * time.Minute,
		Now:      func() time.Time { return fixedNow },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	select {
	case <-notify:
	case <-time.After(time.Second):
		t.Fatal("reaper did not invoke ReclaimStale within 1s")
	}
	cancel()
	<-done

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.calls) == 0 {
		t.Fatal("ReclaimStale not called")
	}
}

func TestStaleReaper_UsesInjectedNow(t *testing.T) {
	fixedNow := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	notify := make(chan struct{}, 1)
	store := &reclaimRecorder{notify: notify}
	r := &StaleReaper{
		Store:    store,
		Interval: 10 * time.Millisecond,
		Timeout:  30 * time.Minute,
		Now:      func() time.Time { return fixedNow },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	select {
	case <-notify:
	case <-time.After(time.Second):
		t.Fatal("reaper did not fire within 1s")
	}
	cancel()
	<-done

	store.mu.Lock()
	defer store.mu.Unlock()
	wantCutoff := fixedNow.Add(-30 * time.Minute)
	if !store.calls[0].Equal(wantCutoff) {
		t.Errorf("cutoff = %v, want %v", store.calls[0], wantCutoff)
	}
}

func TestStaleReaper_ExitsOnContextCancel(t *testing.T) {
	r := &StaleReaper{Store: &reclaimRecorder{}, Interval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reaper did not exit after cancel")
	}
	// Defaults applied.
	if r.Timeout != 30*time.Minute {
		t.Errorf("Timeout default = %v, want 30m", r.Timeout)
	}
	if r.Now == nil {
		t.Error("Now default was not applied")
	}
}
