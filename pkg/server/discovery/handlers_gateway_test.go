package discovery

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestSubmit_AfterReclaim_Returns409(t *testing.T) {
	// Simulate the race: ReclaimStale bounced the job to another engine
	// which finished it first, leaving the original engine's late Submit
	// to hit ErrJobAlreadyTerminal. The handler must map that to 409.
	fs := newFakeStore()
	fs.finishErr = ErrJobAlreadyTerminal
	h := NewGatewayHandlers(fs)
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

	require.Equal(t, http.StatusConflict, rr.Code, "late Submit after reclaim must return 409")

	// Failed path: same guard applies.
	fs2 := newFakeStore()
	fs2.finishErr = ErrJobAlreadyTerminal
	h2 := NewGatewayHandlers(fs2)
	r2 := buildGatewayRouter(h2)

	failBody := map[string]any{"error": "scan timeout"}
	req2 := gwReq(http.MethodPost, "/engine/discovery/"+jobID.String()+"/submit", failBody,
		&engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr2 := httptest.NewRecorder()
	r2.ServeHTTP(rr2, req2)

	require.Equal(t, http.StatusConflict, rr2.Code)
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
