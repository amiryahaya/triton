package credentials

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// reclaimRecordingStore captures the cutoff passed to both reclaim
// methods. Other Store methods are unreachable in a reaper test so they
// return zero values.
type reclaimRecordingStore struct {
	mu            sync.Mutex
	deliveryCalls []time.Time
	testCalls     []time.Time
	notify        chan struct{}
}

func (s *reclaimRecordingStore) ReclaimStaleDeliveries(_ context.Context, cutoff time.Time) error {
	s.mu.Lock()
	s.deliveryCalls = append(s.deliveryCalls, cutoff)
	s.mu.Unlock()
	return nil
}

func (s *reclaimRecordingStore) ReclaimStaleTests(_ context.Context, cutoff time.Time) error {
	s.mu.Lock()
	s.testCalls = append(s.testCalls, cutoff)
	n := s.notify
	s.mu.Unlock()
	// Notify only after both calls have landed — the reaper invokes
	// deliveries first, then tests, so firing on tests guarantees the
	// pair is visible to the test goroutine.
	if n != nil {
		select {
		case n <- struct{}{}:
		default:
		}
	}
	return nil
}

// Unused Store methods — zero-value returns.
func (s *reclaimRecordingStore) CreateProfileWithDelivery(context.Context, Profile, []byte) (Profile, error) {
	return Profile{}, nil
}
func (s *reclaimRecordingStore) GetProfile(context.Context, uuid.UUID, uuid.UUID) (Profile, error) {
	return Profile{}, nil
}
func (s *reclaimRecordingStore) ListProfiles(context.Context, uuid.UUID) ([]Profile, error) {
	return nil, nil
}
func (s *reclaimRecordingStore) DeleteProfileWithDelivery(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}
func (s *reclaimRecordingStore) ClaimNextDelivery(context.Context, uuid.UUID) (Delivery, bool, error) {
	return Delivery{}, false, nil
}
func (s *reclaimRecordingStore) AckDelivery(context.Context, uuid.UUID, string) error { return nil }
func (s *reclaimRecordingStore) CreateTestJob(context.Context, TestJob) (TestJob, error) {
	return TestJob{}, nil
}
func (s *reclaimRecordingStore) GetTestJob(context.Context, uuid.UUID, uuid.UUID) (TestJob, error) {
	return TestJob{}, nil
}
func (s *reclaimRecordingStore) ListTestResults(context.Context, uuid.UUID) ([]TestResult, error) {
	return nil, nil
}
func (s *reclaimRecordingStore) ClaimNextTest(context.Context, uuid.UUID) (TestJob, bool, error) {
	return TestJob{}, false, nil
}
func (s *reclaimRecordingStore) InsertTestResults(context.Context, []TestResult) error { return nil }
func (s *reclaimRecordingStore) FinishTestJob(context.Context, uuid.UUID, string, string) error {
	return nil
}
func (s *reclaimRecordingStore) GetEngineEncryptionPubkey(context.Context, uuid.UUID) ([]byte, error) {
	return nil, nil
}

var _ Store = (*reclaimRecordingStore)(nil)

func TestStaleReaper_ReclaimsBoth(t *testing.T) {
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
		t.Fatal("reaper did not invoke reclaim within 1s")
	}
	cancel()
	<-done

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.deliveryCalls) == 0 {
		t.Fatal("ReclaimStaleDeliveries not called")
	}
	if len(store.testCalls) == 0 {
		t.Fatal("ReclaimStaleTests not called")
	}
	wantCutoff := fixedNow.Add(-15 * time.Minute)
	if !store.deliveryCalls[0].Equal(wantCutoff) {
		t.Errorf("delivery cutoff = %v, want %v", store.deliveryCalls[0], wantCutoff)
	}
	if !store.testCalls[0].Equal(wantCutoff) {
		t.Errorf("test cutoff = %v, want %v", store.testCalls[0], wantCutoff)
	}
}

func TestStaleReaper_DefaultsApply(t *testing.T) {
	r := &StaleReaper{Store: &reclaimRecordingStore{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
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
