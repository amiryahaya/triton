// pkg/manageserver/scanjobs/worker_handlers_test.go
package scanjobs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/model"
)

// stubWorkerStore implements only the Store methods needed by WorkerHandlers.
type stubWorkerStore struct {
	scanjobs.Store // embed for other methods (will panic if called)

	claimResult  scanjobs.Job
	claimErr     error
	heartbeatErr error
	completeErr  error
	failErr      error
}

// stubHostsStore implements scanjobs.HostsStore for tests.
type stubHostsStore struct {
	hostname string
	ip       string
	err      error
}

func (s *stubHostsStore) GetHostBasic(_ context.Context, _ uuid.UUID) (string, string, int, error) {
	return s.hostname, s.ip, 22, s.err
}

func (s *stubWorkerStore) ClaimByID(_ context.Context, _ uuid.UUID, _ string) (scanjobs.Job, error) {
	return s.claimResult, s.claimErr
}
func (s *stubWorkerStore) Heartbeat(_ context.Context, _ uuid.UUID, _ string) error {
	return s.heartbeatErr
}
func (s *stubWorkerStore) Complete(_ context.Context, _ uuid.UUID) error {
	return s.completeErr
}
func (s *stubWorkerStore) Fail(_ context.Context, _ uuid.UUID, _ string) error {
	return s.failErr
}

func routedRequest(method, path, body string, jobID uuid.UUID) (*httptest.ResponseRecorder, *http.Request) {
	var b *bytes.Reader
	if body != "" {
		b = bytes.NewReader([]byte(body))
	} else {
		b = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, b)
	r.Header.Set("X-Worker-Key", "test-key")
	r.Header.Set("Content-Type", "application/json")

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	return httptest.NewRecorder(), r
}

func TestWorkerClaim_OK(t *testing.T) {
	jobID, hostID := uuid.New(), uuid.New()
	store := &stubWorkerStore{
		claimResult: scanjobs.Job{
			ID: jobID, HostID: hostID, Profile: scanjobs.ProfileStandard,
			Status: scanjobs.StatusRunning,
		},
	}
	h := scanjobs.NewWorkerHandlers(store, &stubHostsStore{})
	w, r := routedRequest(http.MethodPost, "/v1/worker/jobs/"+jobID.String()+"/claim", "", jobID)
	h.Claim(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var resp scanjobs.ClaimWorkerResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.HostID != hostID {
		t.Errorf("host_id mismatch")
	}
}

func TestWorkerClaim_AlreadyClaimed_Returns409(t *testing.T) {
	store := &stubWorkerStore{claimErr: scanjobs.ErrAlreadyClaimed}
	h := scanjobs.NewWorkerHandlers(store, &stubHostsStore{})
	w, r := routedRequest(http.MethodPost, "/", "", uuid.New())
	h.Claim(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("status: got %d, want 409", w.Code)
	}
}

func TestWorkerClaim_NotFound_Returns404(t *testing.T) {
	store := &stubWorkerStore{claimErr: scanjobs.ErrNotFound}
	h := scanjobs.NewWorkerHandlers(store, &stubHostsStore{})
	w, r := routedRequest(http.MethodPost, "/", "", uuid.New())
	h.Claim(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
}

func TestWorkerHeartbeat_OK(t *testing.T) {
	store := &stubWorkerStore{}
	h := scanjobs.NewWorkerHandlers(store, &stubHostsStore{})
	w, r := routedRequest(http.MethodPatch, "/", "", uuid.New())
	h.Heartbeat(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
}

func TestWorkerComplete_OK(t *testing.T) {
	store := &stubWorkerStore{}
	h := scanjobs.NewWorkerHandlers(store, &stubHostsStore{})
	w, r := routedRequest(http.MethodPost, "/", "", uuid.New())
	h.Complete(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
}

func TestWorkerFail_OK(t *testing.T) {
	store := &stubWorkerStore{}
	h := scanjobs.NewWorkerHandlers(store, &stubHostsStore{})
	w, r := routedRequest(http.MethodPost, "/", `{"error":"boom"}`, uuid.New())
	h.Fail(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
}

// stubResultEnqueuer implements WorkerResultEnqueuer for tests.
type stubResultEnqueuer struct {
	err        error
	enqueued   int
	sourceType string
}

func (s *stubResultEnqueuer) Enqueue(_ context.Context, _ uuid.UUID, sourceType string, _ uuid.UUID, _ *model.ScanResult) error {
	if s.err != nil {
		return s.err
	}
	s.enqueued++
	s.sourceType = sourceType
	return nil
}

func TestWorkerSubmit_OK(t *testing.T) {
	jobID := uuid.New()
	store := &stubWorkerStore{}
	enqueuer := &stubResultEnqueuer{}
	h := scanjobs.NewWorkerHandlersWithEnqueuer(store, &stubHostsStore{}, enqueuer)
	h.SetSourceID(uuid.New())

	body := `{"id":"` + uuid.NewString() + `","metadata":{"hostname":"h1","source":"triton-portscan"}}`
	w, r := routedRequest(http.MethodPost, "/v1/worker/jobs/"+jobID.String()+"/submit", body, jobID)
	h.Submit(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202 — body: %s", w.Code, w.Body.String())
	}
	if enqueuer.enqueued != 1 {
		t.Errorf("enqueuer.enqueued: got %d, want 1", enqueuer.enqueued)
	}
	if enqueuer.sourceType != "triton-portscan" {
		t.Errorf("sourceType: got %q, want triton-portscan", enqueuer.sourceType)
	}
}

func TestWorkerSubmit_NoEnqueuer_Returns501(t *testing.T) {
	h := scanjobs.NewWorkerHandlers(&stubWorkerStore{}, &stubHostsStore{})
	w, r := routedRequest(http.MethodPost, "/", `{}`, uuid.New())
	h.Submit(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status: got %d, want 501", w.Code)
	}
}

func TestWorkerSubmit_BadJSON_Returns400(t *testing.T) {
	h := scanjobs.NewWorkerHandlersWithEnqueuer(&stubWorkerStore{}, &stubHostsStore{}, &stubResultEnqueuer{})
	w, r := routedRequest(http.MethodPost, "/", `{not json`, uuid.New())
	h.Submit(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
}

func TestWorkerSubmit_EnqueueError_Returns500(t *testing.T) {
	store := &stubWorkerStore{}
	enqueuer := &stubResultEnqueuer{err: errors.New("db down")}
	h := scanjobs.NewWorkerHandlersWithEnqueuer(store, &stubHostsStore{}, enqueuer)
	w, r := routedRequest(http.MethodPost, "/", `{}`, uuid.New())
	h.Submit(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", w.Code)
	}
}

func TestWorkerKeyAuth_Rejects(t *testing.T) {
	r := chi.NewRouter()
	r.Use(scanjobs.WorkerKeyAuth("correct-key"))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Worker-Key", "wrong-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
