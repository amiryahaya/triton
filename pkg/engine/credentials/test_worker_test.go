package credentials

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

type fakeTestAPI struct {
	mu      sync.Mutex
	jobs    []*client.TestJobPayload
	polled  int32
	submits []submittedCall
	doneCh  chan struct{}
	wantN   int
}

type submittedCall struct {
	TestID  string
	Results []client.SubmittedTestResult
	ErrMsg  string
}

func (f *fakeTestAPI) PollCredentialTest(_ context.Context) (*client.TestJobPayload, error) {
	atomic.AddInt32(&f.polled, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.jobs) == 0 {
		time.Sleep(5 * time.Millisecond)
		return nil, nil
	}
	j := f.jobs[0]
	f.jobs = f.jobs[1:]
	return j, nil
}

func (f *fakeTestAPI) SubmitCredentialTest(_ context.Context, id string, res []client.SubmittedTestResult, errMsg string) error {
	f.mu.Lock()
	f.submits = append(f.submits, submittedCall{id, res, errMsg})
	done := f.doneCh != nil && len(f.submits) == f.wantN
	f.mu.Unlock()
	if done {
		close(f.doneCh)
	}
	return nil
}

type fakeProber struct {
	results map[string]ProbeResult // keyed by address
}

func (p *fakeProber) Probe(_ context.Context, _ string, _ Secret, address string, _ int) ProbeResult {
	if r, ok := p.results[address]; ok {
		return r
	}
	return ProbeResult{Success: false, Error: "no canned result for " + address}
}

func newDoneTestAPI(wantN int, jobs []*client.TestJobPayload) *fakeTestAPI {
	return &fakeTestAPI{jobs: jobs, wantN: wantN, doneCh: make(chan struct{})}
}

func runWorkerUntilSubmitted(t *testing.T, w *TestWorker, fake *fakeTestAPI, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go w.Run(ctx)
	select {
	case <-fake.doneCh:
	case <-time.After(timeout):
		cancel()
		t.Fatal("timed out waiting for submits")
	}
	cancel()
}

func TestTestWorker_RunsProbePerHost(t *testing.T) {
	ks := newTestKS(t)
	secretJSON := []byte(`{"username":"u","password":"pw"}`)
	if err := ks.Put(context.Background(), "r1", "p1", "ssh-password", secretJSON); err != nil {
		t.Fatalf("Put: %v", err)
	}

	job := &client.TestJobPayload{
		ID: "t1", ProfileID: "p1", SecretRef: "r1", AuthType: "ssh-password",
		Hosts: []client.HostTarget{
			{ID: "h1", Address: "10.0.0.1", Port: 22},
			{ID: "h2", Address: "10.0.0.2", Port: 22},
		},
	}
	fake := newDoneTestAPI(1, []*client.TestJobPayload{job})
	prober := &fakeProber{results: map[string]ProbeResult{
		"10.0.0.1": {Success: true, LatencyMs: 10},
		"10.0.0.2": {Success: false, Error: "auth"},
	}}
	w := &TestWorker{Client: fake, Keystore: ks, Prober: prober, PollBackoff: 10 * time.Millisecond}
	runWorkerUntilSubmitted(t, w, fake, 2*time.Second)

	if len(fake.submits) != 1 {
		t.Fatalf("submits = %d", len(fake.submits))
	}
	s := fake.submits[0]
	if s.TestID != "t1" || s.ErrMsg != "" {
		t.Errorf("submit = %+v", s)
	}
	if len(s.Results) != 2 {
		t.Fatalf("results len = %d", len(s.Results))
	}
	if !s.Results[0].Success || s.Results[0].HostID != "h1" || s.Results[0].LatencyMs != 10 {
		t.Errorf("result[0] = %+v", s.Results[0])
	}
	if s.Results[1].Success || s.Results[1].HostID != "h2" || s.Results[1].Error == "" {
		t.Errorf("result[1] = %+v", s.Results[1])
	}
}

func TestTestWorker_SecretNotInKeystore_SubmitsErrorResult(t *testing.T) {
	ks := newTestKS(t)
	job := &client.TestJobPayload{
		ID: "t1", SecretRef: "missing", AuthType: "ssh-password",
		Hosts: []client.HostTarget{{ID: "h1", Address: "10.0.0.1", Port: 22}},
	}
	fake := newDoneTestAPI(1, []*client.TestJobPayload{job})
	w := &TestWorker{Client: fake, Keystore: ks, Prober: &fakeProber{}, PollBackoff: 10 * time.Millisecond}
	runWorkerUntilSubmitted(t, w, fake, 2*time.Second)

	if fake.submits[0].ErrMsg == "" {
		t.Fatal("expected job-level error")
	}
	if !strings.Contains(fake.submits[0].ErrMsg, "keystore lookup failed") {
		t.Errorf("errMsg = %q", fake.submits[0].ErrMsg)
	}
	if len(fake.submits[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(fake.submits[0].Results))
	}
}

func TestTestWorker_AuthTypeMismatch_SubmitsError(t *testing.T) {
	ks := newTestKS(t)
	_ = ks.Put(context.Background(), "r1", "p1", "ssh-key", []byte(`{"username":"u"}`))

	job := &client.TestJobPayload{
		ID: "t1", SecretRef: "r1", AuthType: "ssh-password",
		Hosts: []client.HostTarget{{ID: "h1", Address: "10.0.0.1", Port: 22}},
	}
	fake := newDoneTestAPI(1, []*client.TestJobPayload{job})
	w := &TestWorker{Client: fake, Keystore: ks, Prober: &fakeProber{}, PollBackoff: 10 * time.Millisecond}
	runWorkerUntilSubmitted(t, w, fake, 2*time.Second)

	if !strings.Contains(fake.submits[0].ErrMsg, "auth_type mismatch") {
		t.Errorf("errMsg = %q", fake.submits[0].ErrMsg)
	}
}

func TestTestWorker_PollError_BacksOff(t *testing.T) {
	ks := newTestKS(t)
	_ = ks.Put(context.Background(), "r1", "p1", "ssh-password", []byte(`{"username":"u"}`))

	// Fake returns an error on the first poll, then a job.
	job := &client.TestJobPayload{
		ID: "t1", SecretRef: "r1", AuthType: "ssh-password",
		Hosts: []client.HostTarget{{ID: "h1", Address: "10.0.0.1", Port: 22}},
	}
	fake := &flakyTestAPI{
		base:   newDoneTestAPI(1, []*client.TestJobPayload{job}),
		errRem: 1,
	}
	prober := &fakeProber{results: map[string]ProbeResult{"10.0.0.1": {Success: true}}}
	w := &TestWorker{Client: fake, Keystore: ks, Prober: prober, PollBackoff: 20 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	select {
	case <-fake.base.doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
	if len(fake.base.submits) != 1 || fake.base.submits[0].ErrMsg != "" {
		t.Errorf("submits = %+v", fake.base.submits)
	}
}

type flakyTestAPI struct {
	base   *fakeTestAPI
	mu     sync.Mutex
	errRem int
}

func (f *flakyTestAPI) PollCredentialTest(ctx context.Context) (*client.TestJobPayload, error) {
	f.mu.Lock()
	if f.errRem > 0 {
		f.errRem--
		f.mu.Unlock()
		return nil, errors.New("transient")
	}
	f.mu.Unlock()
	return f.base.PollCredentialTest(ctx)
}

func (f *flakyTestAPI) SubmitCredentialTest(ctx context.Context, id string, res []client.SubmittedTestResult, errMsg string) error {
	return f.base.SubmitCredentialTest(ctx, id, res, errMsg)
}
