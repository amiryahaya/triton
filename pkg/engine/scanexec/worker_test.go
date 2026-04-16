package scanexec

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/engine/client"
	"github.com/amiryahaya/triton/pkg/model"
)

// fakeAPI is a stub ScanAPI that records calls and replays a queue of
// PollScanJob responses.
type fakeAPI struct {
	mu sync.Mutex

	polls       []pollResult
	pollIdx     int
	pollCalls   int32
	progress    [][]client.ScanProgressUpdate
	findings    []findingsCall
	finishCalls []finishCall
	onFinish    func() // fired after FinishScanJob records the call
}

type pollResult struct {
	job *client.ScanJobPayload
	err error
}
type findingsCall struct {
	jobID, hostID string
	findings      int
	raw           []byte
}
type finishCall struct {
	jobID, status, errMsg string
}

func (f *fakeAPI) PollScanJob(_ context.Context) (*client.ScanJobPayload, error) {
	atomic.AddInt32(&f.pollCalls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pollIdx >= len(f.polls) {
		// Simulate "no more work" by blocking the caller briefly — tests cancel
		// the context to unblock the Run loop.
		return nil, errors.New("exhausted")
	}
	p := f.polls[f.pollIdx]
	f.pollIdx++
	return p.job, p.err
}

func (f *fakeAPI) SubmitScanProgress(_ context.Context, _ string, updates []client.ScanProgressUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Copy so caller's slice reuse doesn't mutate our record.
	cp := make([]client.ScanProgressUpdate, len(updates))
	copy(cp, updates)
	f.progress = append(f.progress, cp)
	return nil
}

func (f *fakeAPI) SubmitScanFindings(_ context.Context, jobID, hostID string, scanResult []byte, findings int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(scanResult))
	copy(cp, scanResult)
	f.findings = append(f.findings, findingsCall{jobID: jobID, hostID: hostID, findings: findings, raw: cp})
	return nil
}

func (f *fakeAPI) FinishScanJob(_ context.Context, jobID, status, errMsg string) error {
	f.mu.Lock()
	f.finishCalls = append(f.finishCalls, finishCall{jobID: jobID, status: status, errMsg: errMsg})
	fn := f.onFinish
	f.mu.Unlock()
	if fn != nil {
		fn()
	}
	return nil
}

// fakeScanner returns a canned HostResult per host ID.
type fakeScanner struct {
	byHost map[string]HostResult
}

func (f *fakeScanner) ScanHost(_ context.Context, host HostTarget, _ string, _ string, _ string) HostResult {
	r, ok := f.byHost[host.ID]
	if !ok {
		return HostResult{HostID: host.ID, Error: "no canned result"}
	}
	r.HostID = host.ID
	return r
}

func newJob(id string, hostIDs ...string) *client.ScanJobPayload {
	secret := "ref-1"
	hosts := make([]client.ScanHostTarget, 0, len(hostIDs))
	for _, h := range hostIDs {
		hosts = append(hosts, client.ScanHostTarget{ID: h, Address: "10.0.0.1", Port: 22})
	}
	return &client.ScanJobPayload{
		ID: id, ScanProfile: "quick", CredentialAuthType: "ssh-password",
		CredentialSecretRef: &secret, Hosts: hosts,
	}
}

func runWorkerUntilFinish(t *testing.T, api *fakeAPI, exec HostScanner, expectedFinishes int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	finishedAll := make(chan struct{})
	var once sync.Once
	api.onFinish = func() {
		api.mu.Lock()
		n := len(api.finishCalls)
		api.mu.Unlock()
		if n >= expectedFinishes {
			once.Do(func() { close(finishedAll) })
		}
	}
	w := &Worker{Client: api, Executor: exec, PollError: 5 * time.Millisecond}
	doneCh := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(doneCh)
	}()
	select {
	case <-finishedAll:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %d finish calls", expectedFinishes)
	}
	cancel()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after cancel")
	}
}

func TestWorker_ScansAndFinishes_AllSuccess(t *testing.T) {
	job := newJob("j1", "h1", "h2")
	api := &fakeAPI{polls: []pollResult{{job: job}}}
	exec := &fakeScanner{byHost: map[string]HostResult{
		"h1": {Success: true, Findings: 3, Result: &model.ScanResult{ID: "s1"}},
		"h2": {Success: true, Findings: 5, Result: &model.ScanResult{ID: "s2"}},
	}}
	runWorkerUntilFinish(t, api, exec, 1)

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.findings) != 2 {
		t.Errorf("findings calls = %d, want 2", len(api.findings))
	}
	if len(api.progress) != 2 {
		t.Errorf("progress calls = %d, want 2", len(api.progress))
	}
	if len(api.finishCalls) != 1 || api.finishCalls[0].status != "completed" {
		t.Errorf("finish = %+v", api.finishCalls)
	}
	if api.finishCalls[0].errMsg != "" {
		t.Errorf("expected no errMsg, got %q", api.finishCalls[0].errMsg)
	}
}

func TestWorker_ScansAndFinishes_AllFailed(t *testing.T) {
	job := newJob("j1", "h1", "h2")
	api := &fakeAPI{polls: []pollResult{{job: job}}}
	exec := &fakeScanner{byHost: map[string]HostResult{
		"h1": {Error: "dial refused"},
		"h2": {Error: "auth failed"},
	}}
	runWorkerUntilFinish(t, api, exec, 1)

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.findings) != 0 {
		t.Errorf("findings calls = %d, want 0", len(api.findings))
	}
	if len(api.finishCalls) != 1 || api.finishCalls[0].status != "failed" {
		t.Errorf("finish = %+v", api.finishCalls)
	}
	if !strings.Contains(api.finishCalls[0].errMsg, "all 2 hosts failed") {
		t.Errorf("errMsg = %q", api.finishCalls[0].errMsg)
	}
	if !strings.Contains(api.finishCalls[0].errMsg, "dial refused") {
		t.Errorf("expected first-error to be surfaced in errMsg, got %q", api.finishCalls[0].errMsg)
	}
}

func TestWorker_ScansAndFinishes_Mixed(t *testing.T) {
	job := newJob("j1", "h1", "h2", "h3")
	api := &fakeAPI{polls: []pollResult{{job: job}}}
	exec := &fakeScanner{byHost: map[string]HostResult{
		"h1": {Success: true, Findings: 1, Result: &model.ScanResult{ID: "s1"}},
		"h2": {Success: true, Findings: 2, Result: &model.ScanResult{ID: "s2"}},
		"h3": {Error: "timeout"},
	}}
	runWorkerUntilFinish(t, api, exec, 1)

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.findings) != 2 {
		t.Errorf("findings calls = %d, want 2", len(api.findings))
	}
	if api.finishCalls[0].status != "completed" {
		t.Errorf("status = %q", api.finishCalls[0].status)
	}
	if !strings.Contains(api.finishCalls[0].errMsg, "1 of 3 hosts failed") {
		t.Errorf("errMsg = %q", api.finishCalls[0].errMsg)
	}
	if !strings.Contains(api.finishCalls[0].errMsg, "timeout") {
		t.Errorf("expected first-error surfaced, got %q", api.finishCalls[0].errMsg)
	}
}

func TestWorker_PollError_BacksOff(t *testing.T) {
	job := newJob("j1", "h1")
	api := &fakeAPI{polls: []pollResult{
		{err: errors.New("boom")},
		{job: job},
	}}
	exec := &fakeScanner{byHost: map[string]HostResult{
		"h1": {Success: true, Findings: 0, Result: &model.ScanResult{ID: "s1"}},
	}}
	runWorkerUntilFinish(t, api, exec, 1)

	if atomic.LoadInt32(&api.pollCalls) < 2 {
		t.Errorf("expected at least 2 poll calls, got %d", api.pollCalls)
	}
}

func TestWorker_ExitsOnContextCancel(t *testing.T) {
	api := &fakeAPI{} // empty poll queue → returns error every time
	exec := &fakeScanner{}
	w := &Worker{Client: api, Executor: exec, PollError: 5 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	// Let it poll a couple of times then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not exit within 1s of cancel")
	}
}
