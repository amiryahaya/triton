package scanjobs

import (
	"bytes"
	"encoding/json"
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

func buildGatewayRouter(h *GatewayHandlers) http.Handler {
	r := chi.NewRouter()
	r.Route("/engine/scans", func(r chi.Router) {
		MountGatewayRoutes(r, h)
	})
	return r
}

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

func TestPoll_ReturnsJobWhenClaimed(t *testing.T) {
	fs := newFakeStore()
	jobID := uuid.Must(uuid.NewV7())
	fs.claimOut = JobPayload{ID: jobID, ScanProfile: ProfileQuick}
	fs.claimFind = true

	h := NewGatewayHandlers(fs)
	h.PollTimeout = 100 * time.Millisecond
	h.PollInterval = 10 * time.Millisecond
	r := buildGatewayRouter(h)

	req := gwReq(http.MethodGet, "/engine/scans/poll", nil, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var got JobPayload
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, jobID, got.ID)
}

func TestPoll_TimesOutReturns204(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	h.PollTimeout = 50 * time.Millisecond
	h.PollInterval = 10 * time.Millisecond
	r := buildGatewayRouter(h)

	req := gwReq(http.MethodGet, "/engine/scans/poll", nil, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()

	start := time.Now()
	r.ServeHTTP(rr, req)
	elapsed := time.Since(start)

	require.Equal(t, http.StatusNoContent, rr.Code)
	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond)
}

func TestPoll_NoEngineContext_500(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	h.PollTimeout = 10 * time.Millisecond
	r := buildGatewayRouter(h)

	req := gwReq(http.MethodGet, "/engine/scans/poll", nil, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestProgress_AggregatesCounts(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	updates := []ProgressUpdate{
		{HostID: uuid.Must(uuid.NewV7()), Status: "completed"},
		{HostID: uuid.Must(uuid.NewV7()), Status: "completed"},
		{HostID: uuid.Must(uuid.NewV7()), Status: "failed"},
		{HostID: uuid.Must(uuid.NewV7()), Status: "running"},
	}
	req := gwReq(http.MethodPost, "/engine/scans/"+jobID.String()+"/progress", updates, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, fs.updateCalls, 1)
	assert.Equal(t, 2, fs.updateCalls[0].done)
	assert.Equal(t, 1, fs.updateCalls[0].failed)
}

func TestSubmit_CallsRecordScanResult(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	engID := uuid.Must(uuid.NewV7())
	hostID := uuid.Must(uuid.NewV7())
	body := map[string]any{
		"host_id":        hostID.String(),
		"findings_count": 5,
		"scan_result":    map[string]any{"hostname": "h1"},
	}
	req := gwReq(http.MethodPost, "/engine/scans/"+jobID.String()+"/submit", body, &engine.Engine{ID: engID})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code, "body=%s", rr.Body.String())
	require.Len(t, fs.recordCalls, 1)
	assert.Equal(t, jobID, fs.recordCalls[0].jobID)
	assert.Equal(t, engID, fs.recordCalls[0].engineID)
	assert.Equal(t, hostID, fs.recordCalls[0].hostID)
}

func TestFinish_Completed_204(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	body := map[string]any{"status": "completed"}
	req := gwReq(http.MethodPost, "/engine/scans/"+jobID.String()+"/finish", body, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, fs.finishCalls, 1)
	assert.Equal(t, StatusCompleted, fs.finishCalls[0].status)
}

func TestFinish_AlreadyTerminal_409(t *testing.T) {
	fs := newFakeStore()
	fs.finishErr = ErrJobAlreadyTerminal
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	body := map[string]any{"status": "completed"}
	req := gwReq(http.MethodPost, "/engine/scans/"+uuid.Must(uuid.NewV7()).String()+"/finish", body, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
}

func TestFinish_InvalidStatus_400(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	body := map[string]any{"status": "bogus"}
	req := gwReq(http.MethodPost, "/engine/scans/"+uuid.Must(uuid.NewV7()).String()+"/finish", body, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}
