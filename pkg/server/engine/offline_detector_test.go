package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// detectorStore captures calls to MarkStaleOffline. Channel-based so
// tests can wait for a sweep without sleeping.
type detectorStore struct {
	calls chan time.Time
}

func newDetectorStore() *detectorStore {
	return &detectorStore{calls: make(chan time.Time, 16)}
}

func (s *detectorStore) MarkStaleOffline(_ context.Context, cutoff time.Time) error {
	s.calls <- cutoff
	return nil
}

// Unused Store methods — panic if accidentally invoked.
func (s *detectorStore) UpsertCA(context.Context, uuid.UUID, *CA) error { panic("unused") }
func (s *detectorStore) GetCA(context.Context, uuid.UUID) (*CA, error)  { panic("unused") }
func (s *detectorStore) CreateEngine(context.Context, Engine) (Engine, error) {
	panic("unused")
}
func (s *detectorStore) GetEngine(context.Context, uuid.UUID, uuid.UUID) (Engine, error) {
	panic("unused")
}
func (s *detectorStore) GetEngineByFingerprint(context.Context, string) (Engine, error) {
	panic("unused")
}
func (s *detectorStore) ListEngines(context.Context, uuid.UUID) ([]Engine, error) {
	panic("unused")
}
func (s *detectorStore) RecordFirstSeen(context.Context, uuid.UUID, string) (bool, error) {
	panic("unused")
}
func (s *detectorStore) RecordPoll(context.Context, uuid.UUID) error { panic("unused") }
func (s *detectorStore) SetStatus(context.Context, uuid.UUID, string) error {
	panic("unused")
}
func (s *detectorStore) Revoke(context.Context, uuid.UUID, uuid.UUID) error { panic("unused") }
func (s *detectorStore) ListAllCAs(context.Context) ([][]byte, error)       { panic("unused") }
func (s *detectorStore) SetEncryptionPubkey(context.Context, uuid.UUID, []byte) error {
	panic("unused")
}
func (s *detectorStore) GetEncryptionPubkey(context.Context, uuid.UUID) ([]byte, error) {
	return nil, nil
}

var _ Store = (*detectorStore)(nil)

func TestOfflineDetector_FlipsStaleEngines(t *testing.T) {
	store := newDetectorStore()
	d := &OfflineDetector{
		Store:    store,
		Interval: 10 * time.Millisecond,
		Stale:    50 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.Run(ctx)
	}()

	select {
	case <-store.calls:
		// Received a sweep — detector is ticking.
	case <-time.After(200 * time.Millisecond):
		cancel()
		wg.Wait()
		t.Fatal("detector did not sweep within 200ms")
	}

	cancel()
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
		// Clean shutdown.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("detector did not exit after context cancel")
	}
}

func TestOfflineDetector_UsesInjectedNowAndCutoff(t *testing.T) {
	store := newDetectorStore()
	fixed := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	d := &OfflineDetector{
		Store:    store,
		Interval: 10 * time.Millisecond,
		Stale:    90 * time.Second,
		Now:      func() time.Time { return fixed },
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	select {
	case cutoff := <-store.calls:
		want := fixed.Add(-90 * time.Second)
		if !cutoff.Equal(want) {
			t.Fatalf("cutoff = %v, want %v", cutoff, want)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no sweep within 200ms")
	}
}
