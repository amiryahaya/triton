// pkg/manageserver/scanjobs/worker_handlers_test.go
package scanjobs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
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
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/v1/worker/jobs/"+jobID.String()+"/claim", "", jobID)
	h.Claim(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var resp scanjobs.ClaimWorkerResp
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.HostID != hostID {
		t.Errorf("host_id mismatch")
	}
}

func TestWorkerClaim_AlreadyClaimed_Returns409(t *testing.T) {
	store := &stubWorkerStore{claimErr: scanjobs.ErrAlreadyClaimed}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/", "", uuid.New())
	h.Claim(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("status: got %d, want 409", w.Code)
	}
}

func TestWorkerClaim_NotFound_Returns404(t *testing.T) {
	store := &stubWorkerStore{claimErr: scanjobs.ErrNotFound}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/", "", uuid.New())
	h.Claim(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
}

func TestWorkerHeartbeat_OK(t *testing.T) {
	store := &stubWorkerStore{}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPatch, "/", "", uuid.New())
	h.Heartbeat(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
}

func TestWorkerComplete_OK(t *testing.T) {
	store := &stubWorkerStore{}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/", "", uuid.New())
	h.Complete(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
}

func TestWorkerFail_OK(t *testing.T) {
	store := &stubWorkerStore{}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/", `{"error":"boom"}`, uuid.New())
	h.Fail(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
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
