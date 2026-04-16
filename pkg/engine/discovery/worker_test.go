package discovery

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	srvdisc "github.com/amiryahaya/triton/pkg/server/discovery"
)

// fakeClient is a programmable clientAPI for worker tests.
type fakeClient struct {
	mu             sync.Mutex
	pollCalls      atomic.Int32
	submitCalls    atomic.Int32
	pollResponses  []pollResp // consumed in order; after exhaustion returns (nil, nil)
	submittedJobID uuid.UUID
	submittedCands []srvdisc.Candidate
	submittedErr   string
	submitSignal   chan struct{} // closed after first submit
	submitOnce     sync.Once
}

type pollResp struct {
	job *srvdisc.Job
	err error
}

func (f *fakeClient) PollDiscovery(ctx context.Context) (*srvdisc.Job, error) {
	idx := int(f.pollCalls.Add(1)) - 1
	f.mu.Lock()
	if idx >= len(f.pollResponses) {
		f.mu.Unlock()
		// Block until ctx cancels so the worker loop doesn't spin
		// after all programmed responses are exhausted.
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r := f.pollResponses[idx]
	f.mu.Unlock()
	return r.job, r.err
}

func (f *fakeClient) SubmitDiscovery(ctx context.Context, jobID uuid.UUID, candidates []srvdisc.Candidate, errMsg string) error {
	f.mu.Lock()
	f.submittedJobID = jobID
	f.submittedCands = candidates
	f.submittedErr = errMsg
	f.mu.Unlock()
	f.submitCalls.Add(1)
	f.submitOnce.Do(func() {
		if f.submitSignal != nil {
			close(f.submitSignal)
		}
	})
	return nil
}

func newSignalClient() *fakeClient {
	return &fakeClient{submitSignal: make(chan struct{})}
}

func TestWorker_ScansAndSubmits(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	jobID := uuid.New()
	fc := newSignalClient()
	fc.pollResponses = []pollResp{
		{job: &srvdisc.Job{
			ID:    jobID,
			CIDRs: []string{"127.0.0.1/32"},
			Ports: []int{port},
		}},
	}

	w := &Worker{
		Client:      fc,
		Scanner:     &Scanner{},
		ScanTimeout: 2 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-fc.submitSignal:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for submit")
	}
	cancel()
	<-done

	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.submittedJobID != jobID {
		t.Errorf("jobID = %s, want %s", fc.submittedJobID, jobID)
	}
	if fc.submittedErr != "" {
		t.Errorf("errMsg = %q, want empty", fc.submittedErr)
	}
	if len(fc.submittedCands) != 1 {
		t.Fatalf("candidates = %d, want 1", len(fc.submittedCands))
	}
	if !fc.submittedCands[0].Address.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("address = %v, want 127.0.0.1", fc.submittedCands[0].Address)
	}
}

func TestWorker_ScanError_SubmitsWithErrMsg(t *testing.T) {
	jobID := uuid.New()
	fc := newSignalClient()
	fc.pollResponses = []pollResp{
		{job: &srvdisc.Job{
			ID:    jobID,
			CIDRs: []string{"10.0.0.0/8"}, // triggers cap error
			Ports: []int{22},
		}},
	}

	w := &Worker{
		Client:      fc,
		Scanner:     &Scanner{},
		ScanTimeout: 2 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-fc.submitSignal:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for submit")
	}
	cancel()
	<-done

	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.submittedErr == "" {
		t.Error("expected non-empty errMsg on scan error")
	}
	if len(fc.submittedCands) != 0 {
		t.Errorf("candidates = %d, want 0 on scan error", len(fc.submittedCands))
	}
}

func TestWorker_PollError_RetriesAfterBackoff(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	jobID := uuid.New()
	fc := newSignalClient()
	fc.pollResponses = []pollResp{
		{err: errors.New("network kaboom")},
		{job: &srvdisc.Job{
			ID:    jobID,
			CIDRs: []string{"127.0.0.1/32"},
			Ports: []int{port},
		}},
	}

	w := &Worker{
		Client:        fc,
		Scanner:       &Scanner{},
		ScanTimeout:   2 * time.Second,
		PollErrorWait: 10 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-fc.submitSignal:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for submit after retry")
	}
	cancel()
	<-done

	if fc.pollCalls.Load() < 2 {
		t.Errorf("poll calls = %d, want ≥ 2", fc.pollCalls.Load())
	}
	if fc.submitCalls.Load() != 1 {
		t.Errorf("submit calls = %d, want 1", fc.submitCalls.Load())
	}
}
