package discovery

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// reclaimRecordingStore extends a minimal fakeStore surface with a
// recorder for ReclaimStale calls. We don't reuse the handler-test
// fakeStore because it already lives in package discovery and pulling
// this method onto it would widen the blast radius of any change.
type reclaimRecordingStore struct {
	mu      sync.Mutex
	calls   []time.Time
	retErr  error
	notify  chan struct{}
	stopped bool
}

func (s *reclaimRecordingStore) ReclaimStale(_ context.Context, cutoff time.Time) error {
	s.mu.Lock()
	s.calls = append(s.calls, cutoff)
	n := s.notify
	s.mu.Unlock()
	if n != nil {
		select {
		case n <- struct{}{}:
		default:
		}
	}
	return s.retErr
}

// Remaining Store methods are never invoked by StaleReaper. Return
// zero values so the interface is satisfied.
func (s *reclaimRecordingStore) CreateJob(context.Context, Job) (Job, error) { return Job{}, nil }
func (s *reclaimRecordingStore) GetJob(context.Context, uuid.UUID, uuid.UUID) (Job, error) {
	return Job{}, nil
}
func (s *reclaimRecordingStore) ListJobs(context.Context, uuid.UUID) ([]Job, error) { return nil, nil }
func (s *reclaimRecordingStore) ListCandidates(context.Context, uuid.UUID) ([]Candidate, error) {
	return nil, nil
}
func (s *reclaimRecordingStore) MarkCandidatesPromoted(context.Context, []uuid.UUID) error {
	return nil
}
func (s *reclaimRecordingStore) CancelJob(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (s *reclaimRecordingStore) ClaimNext(context.Context, uuid.UUID) (Job, bool, error) {
	return Job{}, false, nil
}
func (s *reclaimRecordingStore) InsertCandidates(context.Context, uuid.UUID, []Candidate) error {
	return nil
}
func (s *reclaimRecordingStore) FinishJob(context.Context, uuid.UUID, JobStatus, string, int) error {
	return nil
}

var _ Store = (*reclaimRecordingStore)(nil)

func TestStaleReaper_ReclaimsStaleJobs(t *testing.T) {
	fixedNow := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	notify := make(chan struct{}, 1)
	store := &reclaimRecordingStore{notify: notify}
	r := &StaleReaper{
		Store:    store,
		Interval: 10 * time.Millisecond,
		Timeout:  15 * time.Minute,
		Now:      func() time.Time { return fixedNow },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	select {
	case <-notify:
	case <-time.After(time.Second):
		t.Fatal("ReclaimStale was not called within 1s")
	}
	cancel()
	<-done

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.calls) == 0 {
		t.Fatal("no ReclaimStale calls recorded")
	}
	wantCutoff := fixedNow.Add(-15 * time.Minute)
	if !store.calls[0].Equal(wantCutoff) {
		t.Errorf("cutoff = %v, want %v", store.calls[0], wantCutoff)
	}
}

func TestStaleReaper_UsesInjectedNow(t *testing.T) {
	fixedNow := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	notify := make(chan struct{}, 1)
	store := &reclaimRecordingStore{notify: notify}
	r := &StaleReaper{
		Store:    store,
		Interval: 10 * time.Millisecond,
		Timeout:  7 * time.Minute,
		Now:      func() time.Time { return fixedNow },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	select {
	case <-notify:
	case <-time.After(time.Second):
		t.Fatal("ReclaimStale not called")
	}
	cancel()
	<-done

	store.mu.Lock()
	defer store.mu.Unlock()
	wantCutoff := fixedNow.Add(-7 * time.Minute)
	if !store.calls[0].Equal(wantCutoff) {
		t.Errorf("cutoff = %v, want %v (Now was pinned to %v)", store.calls[0], wantCutoff, fixedNow)
	}
}

func TestStaleReaper_DefaultsApply(t *testing.T) {
	r := &StaleReaper{Store: &reclaimRecordingStore{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run should exit immediately
	r.Run(ctx)
	if r.Interval != 5*time.Minute {
		t.Errorf("Interval default = %v, want 5m", r.Interval)
	}
	if r.Timeout != 15*time.Minute {
		t.Errorf("Timeout default = %v, want 15m", r.Timeout)
	}
	if r.Now == nil {
		t.Error("Now default was not applied")
	}
}
