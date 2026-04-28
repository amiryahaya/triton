package tritonagent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// stub ManageAPI
// ---------------------------------------------------------------------------

type stubAPI struct {
	mu              sync.Mutex
	heartbeatCalls  int32 // atomic
	pollCalls       int32 // atomic
	pendingCmd      *AgentCommand
	pendingOnce     sync.Once // deliver pendingCmd only once
	submitCalls     int32     // atomic
	submittedBodies [][]byte
	submitErr       error
}

func (s *stubAPI) Heartbeat(_ context.Context) error {
	atomic.AddInt32(&s.heartbeatCalls, 1)
	return nil
}

func (s *stubAPI) PollCommand(_ context.Context) (*AgentCommand, error) {
	atomic.AddInt32(&s.pollCalls, 1)
	var cmd *AgentCommand
	s.pendingOnce.Do(func() {
		cmd = s.pendingCmd
	})
	return cmd, nil
}

func (s *stubAPI) SubmitScan(_ context.Context, _ string, body []byte) error {
	atomic.AddInt32(&s.submitCalls, 1)
	s.mu.Lock()
	s.submittedBodies = append(s.submittedBodies, body)
	s.mu.Unlock()
	return s.submitErr
}

// ---------------------------------------------------------------------------
// stub Scanner
// ---------------------------------------------------------------------------

type stubScanner struct {
	result any
	err    error
}

func (s *stubScanner) RunScan(_ context.Context, _ string) (any, error) {
	return s.result, s.err
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestRun_HeartbeatsOnInterval(t *testing.T) {
	api := &stubAPI{}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	err := Run(ctx, api, Config{
		HeartbeatInterval: 50 * time.Millisecond,
		PollInterval:      50 * time.Millisecond,
		Version:           "1.0.0-test",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}

	hb := atomic.LoadInt32(&api.heartbeatCalls)
	if hb < 1 {
		t.Fatalf("expected at least 1 heartbeat, got %d", hb)
	}
}

func TestRun_ExecutesScanOnCommand(t *testing.T) {
	api := &stubAPI{
		pendingCmd: &AgentCommand{ScanProfile: "quick", JobID: "job-123"},
	}

	scanResult := map[string]string{"status": "ok", "findings_count": "3"}
	scanner := &stubScanner{result: scanResult}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := Run(ctx, api, Config{
		HeartbeatInterval: 100 * time.Millisecond,
		PollInterval:      50 * time.Millisecond,
		Version:           "1.0.0-test",
		Scanner:           scanner,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}

	sc := atomic.LoadInt32(&api.submitCalls)
	if sc < 1 {
		t.Fatalf("expected at least 1 submit call, got %d", sc)
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.submittedBodies) == 0 {
		t.Fatal("expected submitted bodies")
	}
	if len(api.submittedBodies[0]) == 0 {
		t.Fatal("submitted body is empty")
	}
}

func TestRun_ExitsOnContextCancel(t *testing.T) {
	api := &stubAPI{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := Run(ctx, api, Config{Version: "1.0.0-test"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestRun_AuthFailedOnSubmit_ReturnsError(t *testing.T) {
	api := &stubAPI{
		pendingCmd: &AgentCommand{ScanProfile: "quick", JobID: "job-auth"},
		submitErr:  ErrAuthFailed,
	}
	scanner := &stubScanner{result: map[string]string{"ok": "1"}}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := Run(ctx, api, Config{
		HeartbeatInterval: 500 * time.Millisecond,
		PollInterval:      30 * time.Millisecond,
		Version:           "test",
		Scanner:           scanner,
	})
	if err == nil {
		t.Fatal("expected non-nil error when submit returns ErrAuthFailed")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed in error chain, got: %v", err)
	}
}

func TestRun_PollsRepeatedly(t *testing.T) {
	api := &stubAPI{}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_ = Run(ctx, api, Config{
		HeartbeatInterval: 200 * time.Millisecond,
		PollInterval:      30 * time.Millisecond,
		Version:           "1.0.0-test",
	})

	polls := atomic.LoadInt32(&api.pollCalls)
	if polls < 2 {
		t.Fatalf("expected at least 2 poll calls in 300ms with 30ms interval, got %d", polls)
	}
}
