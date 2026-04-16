package agentpush

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/engine/client"
)

// --- fake PushAPI ---

type fakePushAPI struct {
	mu sync.Mutex

	polls       []pollResult
	pollIdx     int
	pollCalls   int32
	progress    [][]client.PushProgressUpdate
	finishCalls []finishCall
	registers   []registerCall
	onFinish    func()
}

type pollResult struct {
	job *client.PushJobPayload
	err error
}

type finishCall struct {
	jobID, status, errMsg string
}

type registerCall struct {
	hostID, fingerprint, version string
}

func (f *fakePushAPI) PollPushJob(_ context.Context) (*client.PushJobPayload, error) {
	atomic.AddInt32(&f.pollCalls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pollIdx >= len(f.polls) {
		return nil, errors.New("exhausted")
	}
	p := f.polls[f.pollIdx]
	f.pollIdx++
	return p.job, p.err
}

func (f *fakePushAPI) SubmitPushProgress(_ context.Context, _ string, updates []client.PushProgressUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]client.PushProgressUpdate, len(updates))
	copy(cp, updates)
	f.progress = append(f.progress, cp)
	return nil
}

func (f *fakePushAPI) FinishPushJob(_ context.Context, jobID, status, errMsg string) error {
	f.mu.Lock()
	f.finishCalls = append(f.finishCalls, finishCall{jobID: jobID, status: status, errMsg: errMsg})
	fn := f.onFinish
	f.mu.Unlock()
	if fn != nil {
		fn()
	}
	return nil
}

func (f *fakePushAPI) RegisterAgent(_ context.Context, hostID, fingerprint, version string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registers = append(f.registers, registerCall{hostID: hostID, fingerprint: fingerprint, version: version})
	return nil
}

// --- fake HostPusher ---

type fakePusher struct {
	byHost map[string]PushResult
}

func (f *fakePusher) PushToHost(_ context.Context, host HostTarget, _, _ string) PushResult {
	r, ok := f.byHost[host.ID]
	if !ok {
		return PushResult{HostID: host.ID, Error: "no canned result"}
	}
	r.HostID = host.ID
	return r
}

// --- helpers ---

func newPushJob(id string, hostIDs ...string) *client.PushJobPayload {
	hosts := make([]client.PushHostTarget, 0, len(hostIDs))
	for _, h := range hostIDs {
		hosts = append(hosts, client.PushHostTarget{ID: h, Address: "10.0.0.1", Port: 22})
	}
	return &client.PushJobPayload{
		ID:                  id,
		CredentialSecretRef: "ref-1",
		CredentialAuthType:  "bootstrap-admin",
		Hosts:               hosts,
	}
}

func runWorkerUntilFinish(t *testing.T, api *fakePushAPI, exec HostPusher, expectedFinishes int) {
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
	w := &Worker{Client: api, Executor: exec, PollError: 5 * time.Millisecond, Version: "test"}
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

// --- tests ---

func TestPushWorker_AllSuccess(t *testing.T) {
	job := newPushJob("j1", "h1", "h2")
	api := &fakePushAPI{polls: []pollResult{{job: job}}}
	exec := &fakePusher{byHost: map[string]PushResult{
		"h1": {Success: true, Fingerprint: "fp1"},
		"h2": {Success: true, Fingerprint: "fp2"},
	}}
	runWorkerUntilFinish(t, api, exec, 1)

	api.mu.Lock()
	defer api.mu.Unlock()

	if len(api.progress) != 2 {
		t.Errorf("progress calls = %d, want 2", len(api.progress))
	}
	if len(api.registers) != 2 {
		t.Errorf("register calls = %d, want 2", len(api.registers))
	}
	if len(api.finishCalls) != 1 || api.finishCalls[0].status != "completed" {
		t.Errorf("finish = %+v", api.finishCalls)
	}
	if api.finishCalls[0].errMsg != "" {
		t.Errorf("expected no errMsg, got %q", api.finishCalls[0].errMsg)
	}
}

func TestPushWorker_AllFailed(t *testing.T) {
	job := newPushJob("j1", "h1", "h2")
	api := &fakePushAPI{polls: []pollResult{{job: job}}}
	exec := &fakePusher{byHost: map[string]PushResult{
		"h1": {Error: "dial refused"},
		"h2": {Error: "auth failed"},
	}}
	runWorkerUntilFinish(t, api, exec, 1)

	api.mu.Lock()
	defer api.mu.Unlock()

	if len(api.registers) != 0 {
		t.Errorf("register calls = %d, want 0", len(api.registers))
	}
	if api.finishCalls[0].status != "failed" {
		t.Errorf("status = %q, want failed", api.finishCalls[0].status)
	}
	if !strings.Contains(api.finishCalls[0].errMsg, "all 2 hosts failed") {
		t.Errorf("errMsg = %q", api.finishCalls[0].errMsg)
	}
}

func TestPushWorker_Mixed(t *testing.T) {
	job := newPushJob("j1", "h1", "h2", "h3")
	api := &fakePushAPI{polls: []pollResult{{job: job}}}
	exec := &fakePusher{byHost: map[string]PushResult{
		"h1": {Success: true, Fingerprint: "fp1"},
		"h2": {Success: true, Fingerprint: "fp2"},
		"h3": {Error: "timeout"},
	}}
	runWorkerUntilFinish(t, api, exec, 1)

	api.mu.Lock()
	defer api.mu.Unlock()

	if len(api.registers) != 2 {
		t.Errorf("register calls = %d, want 2", len(api.registers))
	}
	if api.finishCalls[0].status != "completed" {
		t.Errorf("status = %q", api.finishCalls[0].status)
	}
	if !strings.Contains(api.finishCalls[0].errMsg, "1 of 3 hosts failed") {
		t.Errorf("errMsg = %q", api.finishCalls[0].errMsg)
	}
}

func TestPushWorker_PollError_BacksOff(t *testing.T) {
	job := newPushJob("j1", "h1")
	api := &fakePushAPI{polls: []pollResult{
		{err: errors.New("boom")},
		{job: job},
	}}
	exec := &fakePusher{byHost: map[string]PushResult{
		"h1": {Success: true, Fingerprint: "fp1"},
	}}
	runWorkerUntilFinish(t, api, exec, 1)

	if atomic.LoadInt32(&api.pollCalls) < 2 {
		t.Errorf("expected at least 2 poll calls, got %d", api.pollCalls)
	}
}

func TestPushWorker_ExitsOnContextCancel(t *testing.T) {
	api := &fakePushAPI{}
	exec := &fakePusher{}
	w := &Worker{Client: api, Executor: exec, PollError: 5 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not exit within 1s of cancel")
	}
}
