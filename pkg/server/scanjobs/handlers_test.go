package scanjobs

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
	"github.com/amiryahaya/triton/pkg/server/inventory"
)

// --- fake Store --------------------------------------------------------------

type fakeStore struct {
	createErr error
	getErr    error
	listErr   error
	cancelErr error

	jobs      map[uuid.UUID]Job
	listOut   []Job
	claimOut  JobPayload
	claimFind bool
	claimErr  error

	updateCalls []struct{ done, failed int }
	recordCalls []struct{ jobID, engineID, hostID uuid.UUID }
	finishCalls []struct {
		id     uuid.UUID
		status JobStatus
		errMsg string
	}
	finishErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{jobs: map[uuid.UUID]Job{}}
}

func (f *fakeStore) CreateJob(_ context.Context, j Job) (Job, error) {
	if f.createErr != nil {
		return Job{}, f.createErr
	}
	j.Status = StatusQueued
	j.RequestedAt = time.Now()
	f.jobs[j.ID] = j
	return j, nil
}

func (f *fakeStore) GetJob(_ context.Context, _, id uuid.UUID) (Job, error) {
	if f.getErr != nil {
		return Job{}, f.getErr
	}
	j, ok := f.jobs[id]
	if !ok {
		return Job{}, ErrJobNotFound
	}
	return j, nil
}

func (f *fakeStore) ListJobs(_ context.Context, _ uuid.UUID, _ int) ([]Job, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listOut, nil
}

func (f *fakeStore) CancelJob(_ context.Context, _, _ uuid.UUID) error {
	return f.cancelErr
}

func (f *fakeStore) ClaimNext(_ context.Context, _ uuid.UUID) (JobPayload, bool, error) {
	if f.claimErr != nil {
		return JobPayload{}, false, f.claimErr
	}
	return f.claimOut, f.claimFind, nil
}

func (f *fakeStore) UpdateProgress(_ context.Context, _ uuid.UUID, done, failed int) error {
	f.updateCalls = append(f.updateCalls, struct{ done, failed int }{done, failed})
	return nil
}

func (f *fakeStore) FinishJob(_ context.Context, _ /* engineID */, id uuid.UUID, status JobStatus, errMsg string) error {
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

func (f *fakeStore) RecordScanResult(_ context.Context, jobID, engineID, hostID uuid.UUID, _ []byte) error {
	f.recordCalls = append(f.recordCalls, struct{ jobID, engineID, hostID uuid.UUID }{jobID, engineID, hostID})
	return nil
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
	r.Route("/scan-jobs", func(r chi.Router) {
		MountAdminRoutes(r, h)
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

// --- admin tests -------------------------------------------------------------

func TestCreateJob_ByGroup_Engineer_201(t *testing.T) {
	fs := newFakeStore()
	groupID := uuid.Must(uuid.NewV7())
	engineID := uuid.Must(uuid.NewV7())
	inv := &fakeInventory{
		hosts: []inventory.Host{
			{ID: uuid.Must(uuid.NewV7())},
			{ID: uuid.Must(uuid.NewV7())},
			{ID: uuid.Must(uuid.NewV7())},
		},
		engines: map[uuid.UUID]struct{}{engineID: {}},
	}
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"group_id":     groupID.String(),
		"scan_profile": "quick",
	}
	req := adminReq(t, http.MethodPost, "/scan-jobs/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "body=%s", rr.Body.String())
	var got Job
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, engineID, got.EngineID)
	assert.Equal(t, 3, got.ProgressTotal)
	assert.Equal(t, ProfileQuick, got.ScanProfile)
}

func TestCreateJob_ByHostIDs_Engineer_201(t *testing.T) {
	fs := newFakeStore()
	engineID := uuid.Must(uuid.NewV7())
	inv := &fakeInventory{engines: map[uuid.UUID]struct{}{engineID: {}}}
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"host_ids": []string{uuid.Must(uuid.NewV7()).String(), uuid.Must(uuid.NewV7()).String()},
	}
	req := adminReq(t, http.MethodPost, "/scan-jobs/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "body=%s", rr.Body.String())
	var got Job
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, ProfileStandard, got.ScanProfile) // defaulted
	assert.Equal(t, 2, got.ProgressTotal)
}

func TestCreateJob_Officer_403(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	body := map[string]any{"host_ids": []string{uuid.Must(uuid.NewV7()).String()}}
	req := adminReq(t, http.MethodPost, "/scan-jobs/", body, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	assert.Empty(t, fs.jobs)
}

func TestCreateJob_NoHosts_400(t *testing.T) {
	fs := newFakeStore()
	groupID := uuid.Must(uuid.NewV7())
	inv := &fakeInventory{hosts: nil, engines: map[uuid.UUID]struct{}{}}
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	body := map[string]any{"group_id": groupID.String()}
	req := adminReq(t, http.MethodPost, "/scan-jobs/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCreateJob_BothGroupAndHostIDs_400(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"group_id": uuid.Must(uuid.NewV7()).String(),
		"host_ids": []string{uuid.Must(uuid.NewV7()).String()},
	}
	req := adminReq(t, http.MethodPost, "/scan-jobs/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCreateJob_NeitherGroupNorHostIDs_400(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	body := map[string]any{}
	req := adminReq(t, http.MethodPost, "/scan-jobs/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCreateJob_HostsSpanTwoEngines_400(t *testing.T) {
	fs := newFakeStore()
	e1 := uuid.Must(uuid.NewV7())
	e2 := uuid.Must(uuid.NewV7())
	inv := &fakeInventory{
		engines: map[uuid.UUID]struct{}{e1: {}, e2: {}},
	}
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	body := map[string]any{"host_ids": []string{uuid.Must(uuid.NewV7()).String()}}
	req := adminReq(t, http.MethodPost, "/scan-jobs/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "multiple engines")
}

func TestCreateJob_NoEngineAssigned_400(t *testing.T) {
	fs := newFakeStore()
	inv := &fakeInventory{engines: map[uuid.UUID]struct{}{}}
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	body := map[string]any{"host_ids": []string{uuid.Must(uuid.NewV7()).String()}}
	req := adminReq(t, http.MethodPost, "/scan-jobs/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "no engine assigned")
}

func TestCreateJob_InvalidProfile_400(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"host_ids":     []string{uuid.Must(uuid.NewV7()).String()},
		"scan_profile": "turbo",
	}
	req := adminReq(t, http.MethodPost, "/scan-jobs/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestListJobs_Officer_200(t *testing.T) {
	fs := newFakeStore()
	fs.listOut = []Job{{ID: uuid.Must(uuid.NewV7())}}
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	req := adminReq(t, http.MethodGet, "/scan-jobs/", nil, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var got []Job
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Len(t, got, 1)
}

func TestGetJob_NotFound_404(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	req := adminReq(t, http.MethodGet, "/scan-jobs/"+uuid.Must(uuid.NewV7()).String(), nil, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestCancelJob_QueuedByEngineer_204(t *testing.T) {
	fs := newFakeStore()
	fs.cancelErr = nil
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	req := adminReq(t, http.MethodPost, "/scan-jobs/"+uuid.Must(uuid.NewV7()).String()+"/cancel", nil, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
}

func TestCancelJob_RunningByEngineer_409(t *testing.T) {
	fs := newFakeStore()
	fs.cancelErr = ErrJobNotCancellable
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	req := adminReq(t, http.MethodPost, "/scan-jobs/"+uuid.Must(uuid.NewV7()).String()+"/cancel", nil, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
}

func TestCancelJob_ByOfficer_403(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, &fakeInventory{}, nil)
	r := buildAdminRouter(h)

	req := adminReq(t, http.MethodPost, "/scan-jobs/"+uuid.Must(uuid.NewV7()).String()+"/cancel", nil, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}
