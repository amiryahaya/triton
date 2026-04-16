package tritonagent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// stub EngineAPI
// ---------------------------------------------------------------------------

type stubAPI struct {
	mu              sync.Mutex
	registerCalls   int
	registerFailN   int   // fail the first N register calls
	registerErr     error // error to return on failure
	heartbeatCalls  int32 // atomic
	pollScanCalls   int32 // atomic
	pendingCmd      *ScanCommand
	pendingOnce     sync.Once // deliver pendingCmd only once
	submitCalls     int32     // atomic
	submittedBodies [][]byte
}

func (s *stubAPI) Register(_ context.Context, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registerCalls++
	if s.registerErr != nil && s.registerCalls <= s.registerFailN {
		return s.registerErr
	}
	return nil
}

func (s *stubAPI) Heartbeat(_ context.Context) error {
	atomic.AddInt32(&s.heartbeatCalls, 1)
	return nil
}

func (s *stubAPI) PollScan(_ context.Context) (*ScanCommand, error) {
	atomic.AddInt32(&s.pollScanCalls, 1)
	var cmd *ScanCommand
	s.pendingOnce.Do(func() {
		cmd = s.pendingCmd
	})
	return cmd, nil
}

func (s *stubAPI) SubmitFindings(_ context.Context, body []byte) error {
	atomic.AddInt32(&s.submitCalls, 1)
	s.mu.Lock()
	s.submittedBodies = append(s.submittedBodies, body)
	s.mu.Unlock()
	return nil
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
// reregisterAPI: heartbeat returns ErrUnauthorized on first call to
// simulate engine restart. Subsequent heartbeats succeed once re-registered.
// ---------------------------------------------------------------------------

type reregisterAPI struct {
	mu             sync.Mutex
	registerCalls  int
	heartbeatCount int32 // atomic
}

func (s *reregisterAPI) Register(_ context.Context, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registerCalls++
	return nil
}

func (s *reregisterAPI) Heartbeat(_ context.Context) error {
	n := atomic.AddInt32(&s.heartbeatCount, 1)
	if n == 1 {
		// First heartbeat after initial register — simulate engine restart
		return fmt.Errorf("/agent/heartbeat: %w", ErrUnauthorized)
	}
	return nil
}

func (s *reregisterAPI) PollScan(_ context.Context) (*ScanCommand, error) {
	return nil, nil
}

func (s *reregisterAPI) SubmitFindings(_ context.Context, _ []byte) error {
	return nil
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestRun_RegistersAndHeartbeats(t *testing.T) {
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

	api.mu.Lock()
	regCalls := api.registerCalls
	api.mu.Unlock()
	if regCalls != 1 {
		t.Fatalf("expected 1 register call, got %d", regCalls)
	}
	hb := atomic.LoadInt32(&api.heartbeatCalls)
	if hb < 1 {
		t.Fatalf("expected at least 1 heartbeat, got %d", hb)
	}
}

func TestRun_ExecutesScanOnCommand(t *testing.T) {
	api := &stubAPI{
		pendingCmd: &ScanCommand{ScanProfile: "quick"},
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

func TestRun_RetriesRegisterOnFailure(t *testing.T) {
	api := &stubAPI{
		registerErr:   errors.New("connection refused"),
		registerFailN: 2, // fail first 2 calls, succeed on 3rd
	}

	// Need enough time for 1s + 2s backoff sleeps plus the successful registration.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Run(ctx, api, Config{
		HeartbeatInterval: 100 * time.Millisecond,
		PollInterval:      100 * time.Millisecond,
		Version:           "1.0.0-test",
	})
	// Should succeed registration after retries, then timeout in the poll loop.
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected nil or DeadlineExceeded, got %v", err)
	}

	api.mu.Lock()
	regCalls := api.registerCalls
	api.mu.Unlock()
	if regCalls < 3 {
		t.Fatalf("expected at least 3 register calls (2 failures + 1 success), got %d", regCalls)
	}
}

func TestRun_ReRegistersOnHeartbeat401(t *testing.T) {
	// Simulate engine restart: heartbeat returns 401 (unauthorized)
	// on first call, then succeeds after re-register.
	api := &reregisterAPI{}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := Run(ctx, api, Config{
		HeartbeatInterval: 50 * time.Millisecond,
		PollInterval:      50 * time.Millisecond,
		Version:           "1.0.0-test",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}

	api.mu.Lock()
	regCalls := api.registerCalls
	api.mu.Unlock()
	// Initial register (1) + re-register from 401 (at least 1 more)
	if regCalls < 2 {
		t.Fatalf("expected at least 2 register calls (initial + re-register), got %d", regCalls)
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
