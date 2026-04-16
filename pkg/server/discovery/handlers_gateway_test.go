package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/server/engine"
)

// gwReq builds a request with an engine in context simulating that
// MTLSMiddleware has already run.
func gwReq(method, url string, body any, eng *engine.Engine) *http.Request {
	var b *bytes.Buffer
	if body != nil {
		buf, _ := json.Marshal(body)
		b = bytes.NewBuffer(buf)
	} else {
		b = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, url, b)
	req.Header.Set("Content-Type", "application/json")
	if eng != nil {
		req = req.WithContext(engine.ContextWithEngineForTesting(req.Context(), eng))
	}
	return req
}

func buildGatewayRouter(h *GatewayHandlers) http.Handler {
	r := chi.NewRouter()
	r.Route("/engine/discovery", func(r chi.Router) {
		MountGatewayRoutes(r, h)
	})
	return r
}

func TestPoll_ReturnsJobWhenClaimed(t *testing.T) {
	fs := newFakeStore()
	engID := uuid.Must(uuid.NewV7())
	job := Job{ID: uuid.Must(uuid.NewV7()), EngineID: engID, Status: StatusClaimed,
		CIDRs: []string{"10.0.0.0/24"}, Ports: []int{22}}
	fs.claimQueue = []Job{job}

	h := NewGatewayHandlers(fs)
	h.PollTimeout = 100 * time.Millisecond
	h.PollInterval = 10 * time.Millisecond
	r := buildGatewayRouter(h)

	req := gwReq(http.MethodGet, "/engine/discovery/poll", nil, &engine.Engine{ID: engID})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var got Job
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, job.ID, got.ID)
}

func TestPoll_TimesOutReturns204(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	h.PollTimeout = 50 * time.Millisecond
	h.PollInterval = 10 * time.Millisecond
	r := buildGatewayRouter(h)

	req := gwReq(http.MethodGet, "/engine/discovery/poll", nil, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()

	start := time.Now()
	r.ServeHTTP(rr, req)
	elapsed := time.Since(start)

	require.Equal(t, http.StatusNoContent, rr.Code)
	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond, "must wait for timeout before returning 204")
}

func TestPoll_NoEngineContext_500(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	h.PollTimeout = 50 * time.Millisecond
	r := buildGatewayRouter(h)

	req := gwReq(http.MethodGet, "/engine/discovery/poll", nil, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestSubmit_SuccessWithCandidates_204AndStoresPersisted(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	body := map[string]any{
		"candidates": []map[string]any{
			{"address": "10.0.0.1", "hostname": "a", "open_ports": []int{22}},
			{"address": "10.0.0.2", "open_ports": []int{443}},
		},
	}
	req := gwReq(http.MethodPost, "/engine/discovery/"+jobID.String()+"/submit", body,
		&engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code, "body=%s", rr.Body.String())
	require.Len(t, fs.insertCalls, 1)
	assert.Len(t, fs.insertCalls[0].Candidates, 2)
	require.Len(t, fs.finishCalls, 1)
	assert.Equal(t, StatusCompleted, fs.finishCalls[0].Status)
	assert.Equal(t, 2, fs.finishCalls[0].Count)
}

func TestSubmit_WithError_MarksJobFailed(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	body := map[string]any{"error": "scan timeout"}
	req := gwReq(http.MethodPost, "/engine/discovery/"+jobID.String()+"/submit", body,
		&engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, fs.finishCalls, 1)
	assert.Equal(t, StatusFailed, fs.finishCalls[0].Status)
	assert.Equal(t, "scan timeout", fs.finishCalls[0].Err)
	assert.Empty(t, fs.insertCalls, "candidates must not be inserted on engine-reported failure")
}

func TestSubmit_InvalidAddress_SkipsCandidate(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	body := map[string]any{
		"candidates": []map[string]any{
			{"address": "not-an-ip", "open_ports": []int{22}},
			{"address": "10.0.0.5", "open_ports": []int{22}},
		},
	}
	req := gwReq(http.MethodPost, "/engine/discovery/"+jobID.String()+"/submit", body,
		&engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, fs.insertCalls, 1)
	require.Len(t, fs.insertCalls[0].Candidates, 1, "malformed addresses are silently skipped")
	assert.True(t, fs.insertCalls[0].Candidates[0].Address.Equal(net.ParseIP("10.0.0.5")))
}

// fakeAuditRecorder captures audit events emitted by gateway handlers.
type fakeAuditRecorder struct {
	mu     sync.Mutex
	events []auditEvent
}

type auditEvent struct {
	Event   string
	Subject string
	Fields  map[string]any
}

func (f *fakeAuditRecorder) Record(_ context.Context, event, subject string, fields map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, auditEvent{Event: event, Subject: subject, Fields: fields})
}

func TestSubmit_EmitsAuditEvent(t *testing.T) {
	fs := newFakeStore()
	audit := &fakeAuditRecorder{}
	h := &GatewayHandlers{Store: fs, Audit: audit}
	r := buildGatewayRouter(h)

	engID := uuid.Must(uuid.NewV7())
	jobID := uuid.Must(uuid.NewV7())
	body := map[string]any{
		"candidates": []map[string]any{
			{"address": "10.0.0.1", "open_ports": []int{22}},
		},
	}
	req := gwReq(http.MethodPost, "/engine/discovery/"+jobID.String()+"/submit", body,
		&engine.Engine{ID: engID})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, audit.events, 1, "expected one audit event")
	assert.Equal(t, "discovery.candidates.submitted", audit.events[0].Event)
	assert.Equal(t, jobID.String(), audit.events[0].Subject)
	assert.Equal(t, engID.String(), audit.events[0].Fields["engine_id"])
	assert.Equal(t, 1, audit.events[0].Fields["candidate_count"])
}

func TestSubmit_ErrorEmitsAuditEvent(t *testing.T) {
	fs := newFakeStore()
	audit := &fakeAuditRecorder{}
	h := &GatewayHandlers{Store: fs, Audit: audit}
	r := buildGatewayRouter(h)

	engID := uuid.Must(uuid.NewV7())
	jobID := uuid.Must(uuid.NewV7())
	body := map[string]any{"error": "engine timeout"}
	req := gwReq(http.MethodPost, "/engine/discovery/"+jobID.String()+"/submit", body,
		&engine.Engine{ID: engID})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, audit.events, 1, "expected one audit event for failure path")
	assert.Equal(t, "discovery.job.failed", audit.events[0].Event)
	assert.Equal(t, jobID.String(), audit.events[0].Subject)
}

func TestSubmit_NilAudit_NoPanic(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs) // Audit is nil
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	body := map[string]any{
		"candidates": []map[string]any{
			{"address": "10.0.0.1", "open_ports": []int{22}},
		},
	}
	req := gwReq(http.MethodPost, "/engine/discovery/"+jobID.String()+"/submit", body,
		&engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code, "nil Audit must not panic")
}

func TestSubmit_NoEngineContext_500(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	req := gwReq(http.MethodPost, "/engine/discovery/"+jobID.String()+"/submit",
		map[string]any{"candidates": []any{}}, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
}
