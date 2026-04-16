package agentpush

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/server/engine"
	"github.com/amiryahaya/triton/pkg/server/inventory"
)

// --- fake Store ---------------------------------------------------------------

type fakeStore struct {
	createErr error
	getErr    error
	listErr   error
	cancelErr error

	jobs      map[uuid.UUID]PushJob
	listOut   []PushJob
	claimOut  PushJobPayload
	claimFind bool
	claimErr  error

	updateCalls []struct{ done, failed int }
	finishCalls []struct {
		id     uuid.UUID
		status JobStatus
		errMsg string
	}
	finishErr error

	agents           []FleetAgent
	registerErr      error
	statusErr        error
	heartbeatHostIDs []uuid.UUID
}

func newFakeStore() *fakeStore {
	return &fakeStore{jobs: map[uuid.UUID]PushJob{}}
}

func (f *fakeStore) CreatePushJob(_ context.Context, j PushJob) (PushJob, error) {
	if f.createErr != nil {
		return PushJob{}, f.createErr
	}
	j.Status = StatusQueued
	j.RequestedAt = time.Now()
	f.jobs[j.ID] = j
	return j, nil
}

func (f *fakeStore) GetPushJob(_ context.Context, _, id uuid.UUID) (PushJob, error) {
	if f.getErr != nil {
		return PushJob{}, f.getErr
	}
	j, ok := f.jobs[id]
	if !ok {
		return PushJob{}, ErrJobNotFound
	}
	return j, nil
}

func (f *fakeStore) ListPushJobs(_ context.Context, _ uuid.UUID, _ int) ([]PushJob, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listOut, nil
}

func (f *fakeStore) CancelPushJob(_ context.Context, _, _ uuid.UUID) error {
	return f.cancelErr
}

func (f *fakeStore) ClaimNext(_ context.Context, _ uuid.UUID) (PushJobPayload, bool, error) {
	if f.claimErr != nil {
		return PushJobPayload{}, false, f.claimErr
	}
	return f.claimOut, f.claimFind, nil
}

func (f *fakeStore) UpdateProgress(_ context.Context, _ uuid.UUID, done, failed int) error {
	f.updateCalls = append(f.updateCalls, struct{ done, failed int }{done, failed})
	return nil
}

func (f *fakeStore) FinishJob(_ context.Context, _, id uuid.UUID, status JobStatus, errMsg string) error {
	if f.finishErr != nil {
		return f.finishErr
	}
	f.finishCalls = append(f.finishCalls, struct {
		id     uuid.UUID
		status JobStatus
		errMsg string
	}{id, status, errMsg})
	return nil
}

func (f *fakeStore) ReclaimStale(_ context.Context, _ time.Time) error { return nil }

func (f *fakeStore) RegisterAgent(_ context.Context, a FleetAgent) error {
	if f.registerErr != nil {
		return f.registerErr
	}
	f.agents = append(f.agents, a)
	return nil
}

func (f *fakeStore) GetAgent(_ context.Context, _, _ uuid.UUID) (FleetAgent, error) {
	return FleetAgent{}, ErrAgentNotFound
}

func (f *fakeStore) ListAgents(_ context.Context, _ uuid.UUID) ([]FleetAgent, error) {
	return f.agents, nil
}

func (f *fakeStore) UpdateAgentHeartbeat(_ context.Context, _ uuid.UUID) error { return nil }

func (f *fakeStore) RecordAgentHeartbeat(_ context.Context, hostID uuid.UUID) error {
	f.heartbeatHostIDs = append(f.heartbeatHostIDs, hostID)
	return nil
}

func (f *fakeStore) SetAgentStatus(_ context.Context, _ uuid.UUID, _ string) error {
	return f.statusErr
}

var _ Store = (*fakeStore)(nil)

// --- fake InventoryQuerier ---------------------------------------------------

type fakeInventory struct {
	hosts   []inventory.Host
	listErr error
	engines map[uuid.UUID]struct{}
	engErr  error
}

func (f *fakeInventory) ListHosts(_ context.Context, _ uuid.UUID, _ inventory.HostFilters) ([]inventory.Host, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.hosts, nil
}

func (f *fakeInventory) GetEnginesForHosts(_ context.Context, _ uuid.UUID, _ []uuid.UUID) (map[uuid.UUID]struct{}, error) {
	if f.engErr != nil {
		return nil, f.engErr
	}
	return f.engines, nil
}

// --- helpers -----------------------------------------------------------------

func buildAdminRouter(h *AdminHandlers) http.Handler {
	r := chi.NewRouter()
	r.Route("/agent-push", func(r chi.Router) {
		MountAdminRoutes(r, h)
	})
	return r
}

func buildGatewayRouter(h *GatewayHandlers) http.Handler {
	r := chi.NewRouter()
	r.Route("/engine/agent-push", func(r chi.Router) {
		MountGatewayRoutes(r, h)
	})
	return r
}

func adminReq(t *testing.T, method, path string, body any, role string) *http.Request {
	t.Helper()
	var b *bytes.Buffer
	if body != nil {
		buf, err := json.Marshal(body)
		require.NoError(t, err)
		b = bytes.NewBuffer(buf)
	} else {
		b = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, b)
	req.Header.Set("Content-Type", "application/json")
	orgID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	claims := &auth.UserClaims{Sub: userID.String(), Org: orgID.String(), Role: role}
	req = req.WithContext(server.ContextWithClaimsForTesting(req.Context(), claims))
	return req
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

// --- admin tests -------------------------------------------------------------

func TestCreatePushJob_ByGroup_Engineer_201(t *testing.T) {
	fs := newFakeStore()
	groupID := uuid.Must(uuid.NewV7())
	engineID := uuid.Must(uuid.NewV7())
	credID := uuid.Must(uuid.NewV7())
	inv := &fakeInventory{
		hosts: []inventory.Host{
			{ID: uuid.Must(uuid.NewV7())},
			{ID: uuid.Must(uuid.NewV7())},
		},
		engines: map[uuid.UUID]struct{}{engineID: {}},
	}
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"group_id":              groupID.String(),
		"credential_profile_id": credID.String(),
	}
	req := adminReq(t, http.MethodPost, "/agent-push/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "body=%s", rr.Body.String())
	var got PushJob
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, engineID, got.EngineID)
	assert.Equal(t, 2, got.ProgressTotal)
}

func TestCreatePushJob_ByHostIDs_Engineer_201(t *testing.T) {
	fs := newFakeStore()
	engineID := uuid.Must(uuid.NewV7())
	credID := uuid.Must(uuid.NewV7())
	inv := &fakeInventory{engines: map[uuid.UUID]struct{}{engineID: {}}}
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"host_ids":              []string{uuid.Must(uuid.NewV7()).String()},
		"credential_profile_id": credID.String(),
	}
	req := adminReq(t, http.MethodPost, "/agent-push/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "body=%s", rr.Body.String())
}

func TestCreatePushJob_Officer_403(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"host_ids":              []string{uuid.Must(uuid.NewV7()).String()},
		"credential_profile_id": uuid.Must(uuid.NewV7()).String(),
	}
	req := adminReq(t, http.MethodPost, "/agent-push/", body, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestCreatePushJob_NoCredential_400(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"host_ids": []string{uuid.Must(uuid.NewV7()).String()},
	}
	req := adminReq(t, http.MethodPost, "/agent-push/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "credential_profile_id")
}

func TestCreatePushJob_MultipleEngines_400(t *testing.T) {
	fs := newFakeStore()
	e1 := uuid.Must(uuid.NewV7())
	e2 := uuid.Must(uuid.NewV7())
	inv := &fakeInventory{engines: map[uuid.UUID]struct{}{e1: {}, e2: {}}}
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"host_ids":              []string{uuid.Must(uuid.NewV7()).String()},
		"credential_profile_id": uuid.Must(uuid.NewV7()).String(),
	}
	req := adminReq(t, http.MethodPost, "/agent-push/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "multiple engines")
}

func TestListPushJobs_Officer_200(t *testing.T) {
	fs := newFakeStore()
	fs.listOut = []PushJob{{ID: uuid.Must(uuid.NewV7())}}
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	req := adminReq(t, http.MethodGet, "/agent-push/", nil, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var got []PushJob
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Len(t, got, 1)
}

func TestGetPushJob_NotFound_404(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	req := adminReq(t, http.MethodGet, "/agent-push/"+uuid.Must(uuid.NewV7()).String(), nil, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestCancelPushJob_Queued_204(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	req := adminReq(t, http.MethodPost, "/agent-push/"+uuid.Must(uuid.NewV7()).String()+"/cancel", nil, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
}

func TestCancelPushJob_NotCancellable_409(t *testing.T) {
	fs := newFakeStore()
	fs.cancelErr = ErrJobNotCancellable
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	req := adminReq(t, http.MethodPost, "/agent-push/"+uuid.Must(uuid.NewV7()).String()+"/cancel", nil, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
}

// --- gateway tests -----------------------------------------------------------

func TestGatewayPoll_ReturnsJobWhenClaimed(t *testing.T) {
	fs := newFakeStore()
	jobID := uuid.Must(uuid.NewV7())
	fs.claimOut = PushJobPayload{ID: jobID}
	fs.claimFind = true

	h := NewGatewayHandlers(fs)
	h.PollTimeout = 100 * time.Millisecond
	h.PollInterval = 10 * time.Millisecond
	r := buildGatewayRouter(h)

	req := gwReq(http.MethodGet, "/engine/agent-push/poll", nil, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var got PushJobPayload
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, jobID, got.ID)
}

func TestGatewayPoll_TimesOutReturns204(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	h.PollTimeout = 50 * time.Millisecond
	h.PollInterval = 10 * time.Millisecond
	r := buildGatewayRouter(h)

	req := gwReq(http.MethodGet, "/engine/agent-push/poll", nil, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
}

func TestGatewayPoll_NoEngineContext_500(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	h.PollTimeout = 10 * time.Millisecond
	r := buildGatewayRouter(h)

	req := gwReq(http.MethodGet, "/engine/agent-push/poll", nil, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestGatewayProgress_AggregatesCounts(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	updates := []ProgressUpdate{
		{HostID: uuid.Must(uuid.NewV7()), Status: "completed"},
		{HostID: uuid.Must(uuid.NewV7()), Status: "failed"},
	}
	req := gwReq(http.MethodPost, "/engine/agent-push/"+jobID.String()+"/progress", updates, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, fs.updateCalls, 1)
	assert.Equal(t, 1, fs.updateCalls[0].done)
	assert.Equal(t, 1, fs.updateCalls[0].failed)
}

func TestGatewayFinish_Completed_204(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	body := map[string]any{"status": "completed"}
	req := gwReq(http.MethodPost, "/engine/agent-push/"+jobID.String()+"/finish", body, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, fs.finishCalls, 1)
	assert.Equal(t, StatusCompleted, fs.finishCalls[0].status)
}

func TestGatewayFinish_AlreadyTerminal_409(t *testing.T) {
	fs := newFakeStore()
	fs.finishErr = ErrJobAlreadyTerminal
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	body := map[string]any{"status": "completed"}
	req := gwReq(http.MethodPost, "/engine/agent-push/"+uuid.Must(uuid.NewV7()).String()+"/finish", body, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
}

func TestGatewayFinish_InvalidStatus_400(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	body := map[string]any{"status": "bogus"}
	req := gwReq(http.MethodPost, "/engine/agent-push/"+uuid.Must(uuid.NewV7()).String()+"/finish", body, &engine.Engine{ID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestGatewayRegisterAgent_204(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	hostID := uuid.Must(uuid.NewV7())
	engID := uuid.Must(uuid.NewV7())
	body := map[string]any{
		"host_id":          hostID.String(),
		"cert_fingerprint": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		"version":          "1.0.0",
	}
	req := gwReq(http.MethodPost, "/engine/agent-push/agents/register", body, &engine.Engine{ID: engID, OrgID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code, "body=%s", rr.Body.String())
	require.Len(t, fs.agents, 1)
	assert.Equal(t, hostID, fs.agents[0].HostID)
	assert.Equal(t, engID, fs.agents[0].EngineID)
}

func TestGatewayAgentHeartbeat_FlipsToHealthy_204(t *testing.T) {
	fs := newFakeStore()
	fs.heartbeatHostIDs = []uuid.UUID{}
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	hostID := uuid.Must(uuid.NewV7())
	body := map[string]any{
		"host_id":          hostID.String(),
		"cert_fingerprint": "abcdef",
	}
	req := gwReq(http.MethodPost, "/engine/agent-push/agents/heartbeat", body, &engine.Engine{ID: uuid.Must(uuid.NewV7()), OrgID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, fs.heartbeatHostIDs, 1)
	assert.Equal(t, hostID, fs.heartbeatHostIDs[0])
}

func TestGatewayAgentHeartbeat_BadHostID_400(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	body := map[string]any{
		"host_id":          "not-a-uuid",
		"cert_fingerprint": "abcdef",
	}
	req := gwReq(http.MethodPost, "/engine/agent-push/agents/heartbeat", body, &engine.Engine{ID: uuid.Must(uuid.NewV7()), OrgID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestGatewayRegisterAgent_MissingFingerprint_400(t *testing.T) {
	fs := newFakeStore()
	h := NewGatewayHandlers(fs)
	r := buildGatewayRouter(h)

	body := map[string]any{
		"host_id": uuid.Must(uuid.NewV7()).String(),
	}
	req := gwReq(http.MethodPost, "/engine/agent-push/agents/register", body, &engine.Engine{ID: uuid.Must(uuid.NewV7()), OrgID: uuid.Must(uuid.NewV7())})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}
