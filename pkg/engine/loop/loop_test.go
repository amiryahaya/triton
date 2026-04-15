package loop

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type mockClient struct {
	enrollCalls    atomic.Int32
	heartbeatCalls atomic.Int32
	enrollFailN    int32 // fail first N enroll calls, then succeed
	heartbeatFailN int32 // fail first N heartbeat calls, then succeed
}

func (m *mockClient) Enroll(ctx context.Context) error {
	n := m.enrollCalls.Add(1)
	if n <= m.enrollFailN {
		return errors.New("enroll boom")
	}
	return nil
}

func (m *mockClient) Heartbeat(ctx context.Context) error {
	n := m.heartbeatCalls.Add(1)
	if n <= m.heartbeatFailN {
		return errors.New("hb boom")
	}
	return nil
}

func TestRun_ExitsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &mockClient{}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, m, Config{HeartbeatInterval: 10 * time.Millisecond})
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestRun_RetriesEnrollOnFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &mockClient{enrollFailN: 2}

	done := make(chan struct{})
	go func() {
		_ = Run(ctx, m, Config{
			HeartbeatInterval:    5 * time.Millisecond,
			EnrollMaxBackoff:     5 * time.Millisecond,
			EnrollInitialBackoff: 2 * time.Millisecond,
		})
		close(done)
	}()

	// Wait for enroll to succeed and at least one heartbeat to fire.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if m.heartbeatCalls.Load() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if got := m.enrollCalls.Load(); got != 3 {
		t.Errorf("enroll calls = %d, want 3", got)
	}
	if m.heartbeatCalls.Load() == 0 {
		t.Errorf("expected heartbeat to fire at least once after successful enroll")
	}
}

func TestLoop_OnEnrolled_FiresOnceAfterEnroll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &mockClient{enrollFailN: 2}

	var onEnrolledCalls atomic.Int32
	var enrollCountAtCallback atomic.Int32
	done := make(chan struct{})
	go func() {
		_ = Run(ctx, m, Config{
			HeartbeatInterval:    5 * time.Millisecond,
			EnrollMaxBackoff:     5 * time.Millisecond,
			EnrollInitialBackoff: 2 * time.Millisecond,
			OnEnrolled: func(context.Context) {
				enrollCountAtCallback.Store(m.enrollCalls.Load())
				onEnrolledCalls.Add(1)
			},
		})
		close(done)
	}()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if m.heartbeatCalls.Load() >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if got := onEnrolledCalls.Load(); got != 1 {
		t.Errorf("OnEnrolled fired %d times, want exactly 1", got)
	}
	if got := enrollCountAtCallback.Load(); got != 3 {
		t.Errorf("OnEnrolled fired at enroll attempt #%d, want 3 (2 failures + 1 success)", got)
	}
}

// fakeWorker records whether Run was invoked.
type fakeWorker struct {
	called atomic.Bool
	done   chan struct{}
}

func (w *fakeWorker) Run(ctx context.Context) {
	w.called.Store(true)
	if w.done != nil {
		close(w.done)
	}
	<-ctx.Done()
}

func TestLoop_SpawnsCredentialWorkersAfterEnroll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &mockClient{}

	hDone := make(chan struct{})
	tDone := make(chan struct{})
	handler := &fakeWorker{done: hDone}
	tw := &fakeWorker{done: tDone}

	done := make(chan struct{})
	go func() {
		_ = Run(ctx, m, Config{
			HeartbeatInterval:    5 * time.Millisecond,
			CredentialHandler:    handler,
			CredentialTestWorker: tw,
		})
		close(done)
	}()

	select {
	case <-hDone:
	case <-time.After(time.Second):
		t.Fatal("CredentialHandler.Run was not invoked")
	}
	select {
	case <-tDone:
	case <-time.After(time.Second):
		t.Fatal("CredentialTestWorker.Run was not invoked")
	}
	cancel()
	<-done
}

func TestRun_ContinuesAfterHeartbeatFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &mockClient{heartbeatFailN: 1}

	done := make(chan struct{})
	go func() {
		_ = Run(ctx, m, Config{HeartbeatInterval: 5 * time.Millisecond})
		close(done)
	}()

	// Wait for ≥ 3 heartbeats — proves the loop kept going after the
	// first one returned an error.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if m.heartbeatCalls.Load() >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if got := m.heartbeatCalls.Load(); got < 3 {
		t.Errorf("heartbeat calls = %d, want ≥ 3", got)
	}
}
