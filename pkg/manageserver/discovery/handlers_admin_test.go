//go:build !integration

package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
)

// ---------------------------------------------------------------------------
// noopWorker — WorkerRunner that does nothing (prevents goroutine leaks in
// unit tests).
// ---------------------------------------------------------------------------

type noopWorker struct{}

func (w *noopWorker) Run(_ context.Context, _ Job) {}

// ---------------------------------------------------------------------------
// handlerFakeStore — extends fakeStore with fine-grained control over
// ActiveJobExists and ErrNotFound semantics.
// ---------------------------------------------------------------------------

type handlerFakeStore struct {
	fakeStore
	activeExists bool
	cancelCalled bool
	hasJob       bool // when false, GetCurrentJob returns ErrNotFound
}

func (s *handlerFakeStore) ActiveJobExists(_ context.Context, _ uuid.UUID) (bool, error) {
	return s.activeExists, nil
}

func (s *handlerFakeStore) GetCurrentJob(ctx context.Context, tenantID uuid.UUID) (Job, error) {
	if !s.hasJob {
		return Job{}, ErrNotFound
	}
	return s.fakeStore.GetCurrentJob(ctx, tenantID)
}

func (s *handlerFakeStore) SetCancelRequested(_ context.Context, _ uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelCalled = true
	s.job.CancelRequested = true
	return nil
}

// ---------------------------------------------------------------------------
// fakeCapGuard — HostCapGuard with a configurable limit.
// ---------------------------------------------------------------------------

type fakeCapGuard struct {
	limit int64
}

func (g *fakeCapGuard) LimitCap(_, _ string) int64 { return g.limit }

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func withTenant(r *http.Request, tenantID uuid.UUID) *http.Request {
	return r.WithContext(orgctx.WithInstanceID(r.Context(), tenantID))
}

// ---------------------------------------------------------------------------
// HandleStart tests
// ---------------------------------------------------------------------------

func TestHandleStart_409WhenActive(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)
	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}
	store.activeExists = true

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	body := `{"cidr":"10.0.0.0/24"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req = withTenant(req, tenantID)

	h.HandleStart(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rec.Code)
	}
}

func TestHandleStart_InvalidCIDR(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)
	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}
	store.activeExists = false

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	body := `{"cidr":"not-a-cidr"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req = withTenant(req, tenantID)

	h.HandleStart(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleStart_CIDRTooLarge(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)
	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}
	store.activeExists = false

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	// /15 has 17 host bits — exceeds the /16 limit.
	body := `{"cidr":"10.0.0.0/15"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req = withTenant(req, tenantID)

	h.HandleStart(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if !strings.Contains(resp["error"], "/16") {
		t.Errorf("expected /16 mention in error, got %q", resp["error"])
	}
}

func TestHandleStart_201(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)
	job.CIDR = "192.168.1.0/24"
	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}
	store.activeExists = false

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	body := `{"cidr":"192.168.1.0/24","ports":[22,80]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req = withTenant(req, tenantID)

	h.HandleStart(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp Job
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CIDR != "192.168.1.0/24" {
		t.Errorf("expected cidr=192.168.1.0/24, got %q", resp.CIDR)
	}
	if len(resp.Ports) != 2 {
		t.Errorf("expected 2 ports, got %v", resp.Ports)
	}
}

func TestHandleStart_DefaultPorts(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)
	job.Ports = defaultPorts
	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}
	store.activeExists = false

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	// No ports field supplied.
	body := `{"cidr":"10.1.0.0/24"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req = withTenant(req, tenantID)

	h.HandleStart(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// HandleGet tests
// ---------------------------------------------------------------------------

func TestHandleGet_404NoJob(t *testing.T) {
	tenantID := uuid.New()
	// hasJob=false (default) — GetCurrentJob returns ErrNotFound.
	store := &handlerFakeStore{fakeStore: fakeStore{insertErrFor: map[string]bool{}}}

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = withTenant(req, tenantID)

	h.HandleGet(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleGet_200(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)
	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}
	// Seed two candidates.
	store.candidates = []Candidate{
		{ID: uuid.New(), JobID: job.ID, IP: "10.0.0.1", OpenPorts: []int{22}},
		{ID: uuid.New(), JobID: job.ID, IP: "10.0.0.2", OpenPorts: []int{443}},
	}

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = withTenant(req, tenantID)

	h.HandleGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := resp["job"]; !ok {
		t.Error("expected 'job' key in response")
	}
	var candidates []Candidate
	if err := json.Unmarshal(resp["candidates"], &candidates); err != nil {
		t.Fatalf("decode candidates: %v", err)
	}
	if len(candidates) != 2 {
		t.Errorf("expected 2 candidates, got %d", len(candidates))
	}
}

// ---------------------------------------------------------------------------
// HandleCancel tests
// ---------------------------------------------------------------------------

func TestHandleCancel_404NoJob(t *testing.T) {
	tenantID := uuid.New()
	// hasJob=false (default) — GetCurrentJob returns ErrNotFound.
	store := &handlerFakeStore{fakeStore: fakeStore{insertErrFor: map[string]bool{}}}

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/cancel", nil)
	req = withTenant(req, tenantID)

	h.HandleCancel(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleCancel_409NotActive(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)
	job.Status = "completed"
	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/cancel", nil)
	req = withTenant(req, tenantID)

	h.HandleCancel(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rec.Code)
	}
}

func TestHandleCancel_204(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)
	job.Status = "running"
	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/cancel", nil)
	req = withTenant(req, tenantID)

	h.HandleCancel(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if !store.cancelCalled {
		t.Error("expected SetCancelRequested to have been called")
	}
}

// ---------------------------------------------------------------------------
// HandleImport tests
// ---------------------------------------------------------------------------

func TestHandleImport_SkipsExisting(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)

	existingHostID := uuid.New()
	candA := Candidate{ID: uuid.New(), JobID: job.ID, IP: "10.0.0.1", OpenPorts: []int{22}}
	candB := Candidate{ID: uuid.New(), JobID: job.ID, IP: "10.0.0.2", OpenPorts: []int{22}, ExistingHostID: &existingHostID}

	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}
	store.candidates = []Candidate{candA, candB}

	hs := &fakeHostsStore{}
	h := NewAdminHandlers(store, hs, &noopWorker{}, nil)

	body, _ := json.Marshal(importRequest{
		Candidates: []ImportItem{
			{ID: candA.ID, Hostname: "host-a"},
			{ID: candB.ID, Hostname: "host-b"},
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(string(body)))
	req = withTenant(req, tenantID)

	h.HandleImport(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var result ImportResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Imported != 1 {
		t.Errorf("expected imported=1, got %d", result.Imported)
	}
	if result.Skipped != 1 {
		t.Errorf("expected skipped=1, got %d", result.Skipped)
	}
}

func TestHandleImport_400MissingHostname(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)

	candA := Candidate{ID: uuid.New(), JobID: job.ID, IP: "10.0.0.1", OpenPorts: []int{22}}

	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}
	store.candidates = []Candidate{candA}

	h := NewAdminHandlers(store, &fakeHostsStore{}, &noopWorker{}, nil)

	// Hostname is empty string — should fail.
	body, _ := json.Marshal(importRequest{
		Candidates: []ImportItem{
			{ID: candA.ID, Hostname: ""},
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(string(body)))
	req = withTenant(req, tenantID)

	h.HandleImport(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleImport_403CapExceeded(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)

	candA := Candidate{ID: uuid.New(), JobID: job.ID, IP: "10.0.0.1", OpenPorts: []int{22}}

	store := &handlerFakeStore{fakeStore: fakeStore{job: job, insertErrFor: map[string]bool{}}, hasJob: true}
	store.candidates = []Candidate{candA}

	// hostsStore already has 5 hosts; cap is 5 → importing 1 more exceeds cap.
	hs := &fakeHostsStore{}
	for i := 0; i < 5; i++ {
		hs.hosts = append(hs.hosts, hosts.Host{ID: uuid.New(), Hostname: "existing", IP: "10.0.0.99"})
	}

	guard := &fakeCapGuard{limit: 5}
	h := NewAdminHandlers(store, hs, &noopWorker{}, func() HostCapGuard { return guard })

	body, _ := json.Marshal(importRequest{
		Candidates: []ImportItem{
			{ID: candA.ID, Hostname: "new-host"},
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(string(body)))
	req = withTenant(req, tenantID)

	h.HandleImport(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}
