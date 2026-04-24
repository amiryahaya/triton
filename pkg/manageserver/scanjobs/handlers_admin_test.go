package scanjobs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// --- fakeQueueDepther ------------------------------------------------------

// fakeQueueDepther is a tiny stub for scanjobs.QueueDepther. Unset
// Depth returns 0 (not saturated). QueueErr is returned verbatim if
// non-nil.
type fakeQueueDepther struct {
	Depth    int64
	QueueErr error
}

func (f *fakeQueueDepther) QueueDepth(_ context.Context) (int64, error) {
	if f.QueueErr != nil {
		return 0, f.QueueErr
	}
	return f.Depth, nil
}

// --- fakeStore --------------------------------------------------------------

// fakeStore is an in-memory scanjobs.Store for handler unit tests.
type fakeStore struct {
	mu        sync.Mutex
	items     map[uuid.UUID]scanjobs.Job
	calls     []string
	enqErr    error // if set, Enqueue returns it
	listErr   error // if set, List returns it
	cancelled map[uuid.UUID]bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		items:     map[uuid.UUID]scanjobs.Job{},
		cancelled: map[uuid.UUID]bool{},
	}
}

func (f *fakeStore) recordCall(name string) { f.calls = append(f.calls, name) }

func (f *fakeStore) Enqueue(_ context.Context, req scanjobs.EnqueueReq) ([]scanjobs.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("Enqueue")
	if f.enqErr != nil {
		return nil, f.enqErr
	}
	out := make([]scanjobs.Job, 0, len(req.ZoneIDs))
	for _, z := range req.ZoneIDs {
		j := scanjobs.Job{
			ID:         uuid.Must(uuid.NewV7()),
			TenantID:   req.TenantID,
			ZoneID:     z,
			HostID:     uuid.Must(uuid.NewV7()),
			Profile:    req.Profile,
			Status:     scanjobs.StatusQueued,
			EnqueuedAt: time.Now(),
		}
		f.items[j.ID] = j
		out = append(out, j)
	}
	return out, nil
}

func (f *fakeStore) Get(_ context.Context, id uuid.UUID) (scanjobs.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("Get")
	j, ok := f.items[id]
	if !ok {
		return scanjobs.Job{}, scanjobs.ErrNotFound
	}
	return j, nil
}

func (f *fakeStore) List(_ context.Context, tenantID uuid.UUID, limit int) ([]scanjobs.Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("List")
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []scanjobs.Job{}
	for _, j := range f.items {
		if j.TenantID == tenantID {
			out = append(out, j)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeStore) RequestCancel(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("RequestCancel")
	if _, ok := f.items[id]; !ok {
		return scanjobs.ErrNotFound
	}
	f.cancelled[id] = true
	return nil
}

// The remaining methods aren't exercised by the handler suite but the
// interface requires them; they no-op with sensible defaults.

func (f *fakeStore) ClaimNext(_ context.Context, _ string) (scanjobs.Job, bool, error) {
	return scanjobs.Job{}, false, nil
}
func (f *fakeStore) Heartbeat(_ context.Context, _ uuid.UUID, _ string) error { return nil }
func (f *fakeStore) IsCancelRequested(_ context.Context, id uuid.UUID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cancelled[id], nil
}
func (f *fakeStore) Complete(_ context.Context, _ uuid.UUID) error             { return nil }
func (f *fakeStore) Fail(_ context.Context, _ uuid.UUID, _ string) error       { return nil }
func (f *fakeStore) Cancel(_ context.Context, _ uuid.UUID) error               { return nil }
func (f *fakeStore) ReapStale(_ context.Context, _ time.Duration) (int, error) { return 0, nil }
func (f *fakeStore) PlanEnqueueCount(_ context.Context, req scanjobs.EnqueueReq) (int64, error) {
	// Matches the real store's "one job per zone (assuming one host per
	// zone)" fake shape so cap tests can reason about the count
	// without touching postgres.
	return int64(len(req.ZoneIDs)), nil
}
func (f *fakeStore) CountCompletedSince(_ context.Context, _ uuid.UUID, _ time.Time) (int64, error) {
	// Handler-layer tests don't exercise the usage-pusher path;
	// zero is the safe default that keeps the Store interface
	// contract satisfied.
	return 0, nil
}
func (f *fakeStore) CountActive(_ context.Context, _ uuid.UUID) (int64, error) {
	// Handler-layer tests don't exercise the deactivation-watcher path;
	// zero is the safe default that keeps the Store interface
	// contract satisfied.
	return 0, nil
}

// --- helpers ----------------------------------------------------------------

// newTestServer mounts MountAdminRoutes with a middleware that stashes
// a stable tenant UUID into orgctx — mirrors what the real Manage
// server does via injectInstanceOrg.
func newTestServer(t *testing.T, s scanjobs.Store, tenantID uuid.UUID) *httptest.Server {
	return newTestServerWithQueueDepth(t, s, tenantID, &fakeQueueDepther{})
}

// newTestServerWithQueueDepth is the saturation-aware variant: caller
// supplies a fakeQueueDepther with a pre-set Depth to drive the
// handler's 503 branch.
func newTestServerWithQueueDepth(t *testing.T, s scanjobs.Store, tenantID uuid.UUID, qd scanjobs.QueueDepther) *httptest.Server {
	t.Helper()
	injectTenant := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := orgctx.WithInstanceID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	r := chi.NewRouter()
	r.Route("/api/v1/admin/scan-jobs", func(r chi.Router) {
		r.Use(injectTenant)
		scanjobs.MountAdminRoutes(r, scanjobs.NewAdminHandlers(s, qd, nil))
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

// newTestServerWithGuard is the cap-aware variant that swaps in a
// caller-supplied ScanCapGuard so the Batch H cap tests can exercise
// the 403 branch without signing a licence token.
func newTestServerWithGuard(t *testing.T, s scanjobs.Store, tenantID uuid.UUID, guard scanjobs.ScanCapGuard) *httptest.Server {
	t.Helper()
	injectTenant := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := orgctx.WithInstanceID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	var provider func() scanjobs.ScanCapGuard
	if guard != nil {
		provider = func() scanjobs.ScanCapGuard { return guard }
	}
	r := chi.NewRouter()
	r.Route("/api/v1/admin/scan-jobs", func(r chi.Router) {
		r.Use(injectTenant)
		scanjobs.MountAdminRoutes(r, scanjobs.NewAdminHandlers(s, &fakeQueueDepther{}, provider))
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

// newTestServerNoTenant mounts the router without the orgctx shim so
// we can assert defence-in-depth 503 on missing instance id.
func newTestServerNoTenant(t *testing.T, s scanjobs.Store) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/api/v1/admin/scan-jobs", func(r chi.Router) {
		scanjobs.MountAdminRoutes(r, scanjobs.NewAdminHandlers(s, &fakeQueueDepther{}, nil))
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func doReq(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, buf)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// --- tests ------------------------------------------------------------------

func TestScanJobsAdmin_Enqueue_Success(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	ts := newTestServer(t, store, tenantID)

	zoneID := uuid.Must(uuid.NewV7())
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{zoneID.String()},
		"profile": "quick",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body struct {
		Jobs []scanjobs.Job `json:"jobs"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body.Jobs, 1)
	assert.Equal(t, tenantID, body.Jobs[0].TenantID, "handler must inject tenant from orgctx")
	assert.Equal(t, scanjobs.ProfileQuick, body.Jobs[0].Profile)
}

func TestScanJobsAdmin_Enqueue_MissingZones_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore(), uuid.Must(uuid.NewV7()))

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"profile": "quick",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestScanJobsAdmin_Enqueue_BadProfile_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore(), uuid.Must(uuid.NewV7()))

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{uuid.Must(uuid.NewV7()).String()},
		"profile": "not-a-profile",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestScanJobsAdmin_Enqueue_MalformedJSON_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore(), uuid.Must(uuid.NewV7()))

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/",
		bytes.NewReader([]byte("{not-json")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestScanJobsAdmin_Enqueue_InternalError_Returns500(t *testing.T) {
	store := newFakeStore()
	store.enqErr = errors.New("boom: constraint manage_scan_jobs_pkey")
	ts := newTestServer(t, store, uuid.Must(uuid.NewV7()))

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{uuid.Must(uuid.NewV7()).String()},
		"profile": "quick",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	// Sanitised body — pg error text must not leak.
	b, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(b), "constraint")
	assert.Contains(t, string(b), "internal server error")
}

func TestScanJobsAdmin_Create_QueueSaturated_Returns503(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	ts := newTestServerWithQueueDepth(t, store, tenantID, &fakeQueueDepther{Depth: 10_000})

	zoneID := uuid.Must(uuid.NewV7())
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{zoneID.String()},
		"profile": "quick",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	b, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(b), "saturated", "body must reference the saturated state")
	assert.Contains(t, string(b), "/api/v1/admin/push-status",
		"body must point operators at /push-status")

	// Store.Enqueue must NOT have been called when the queue is
	// saturated — backpressure is a pre-check.
	assert.NotContains(t, store.calls, "Enqueue")
}

func TestScanJobsAdmin_Create_QueueDepthError_Returns500(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	qd := &fakeQueueDepther{QueueErr: errors.New("boom: pg down")}
	ts := newTestServerWithQueueDepth(t, store, tenantID, qd)

	zoneID := uuid.Must(uuid.NewV7())
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{zoneID.String()},
		"profile": "quick",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestScanJobsAdmin_Enqueue_MissingTenant_Returns503(t *testing.T) {
	ts := newTestServerNoTenant(t, newFakeStore())

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/", map[string]any{
		"zones":   []string{uuid.Must(uuid.NewV7()).String()},
		"profile": "quick",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestScanJobsAdmin_List_FiltersByTenant(t *testing.T) {
	store := newFakeStore()
	tenantA := uuid.Must(uuid.NewV7())
	tenantB := uuid.Must(uuid.NewV7())

	// Pre-populate tenant-A and tenant-B rows directly.
	store.items[uuid.Must(uuid.NewV7())] = scanjobs.Job{ID: uuid.Must(uuid.NewV7()), TenantID: tenantA, Profile: scanjobs.ProfileQuick}
	store.items[uuid.Must(uuid.NewV7())] = scanjobs.Job{ID: uuid.Must(uuid.NewV7()), TenantID: tenantB, Profile: scanjobs.ProfileQuick}

	ts := newTestServer(t, store, tenantA)
	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/scan-jobs/", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var list []scanjobs.Job
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	require.Len(t, list, 1)
	assert.Equal(t, tenantA, list[0].TenantID)
}

func TestScanJobsAdmin_List_LimitQueryParam(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	for i := 0; i < 5; i++ {
		id := uuid.Must(uuid.NewV7())
		store.items[id] = scanjobs.Job{ID: id, TenantID: tenantID, Profile: scanjobs.ProfileQuick}
	}

	ts := newTestServer(t, store, tenantID)
	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/scan-jobs/?limit=2", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var list []scanjobs.Job
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	assert.Len(t, list, 2)
}

func TestScanJobsAdmin_Get_Success(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	j := scanjobs.Job{ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, Profile: scanjobs.ProfileStandard, Status: scanjobs.StatusQueued}
	store.items[j.ID] = j

	ts := newTestServer(t, store, tenantID)
	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/scan-jobs/"+j.ID.String(), nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got scanjobs.Job
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, j.ID, got.ID)
	assert.Equal(t, scanjobs.ProfileStandard, got.Profile)
}

func TestScanJobsAdmin_Get_MissingReturns404(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store, uuid.Must(uuid.NewV7()))

	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/scan-jobs/"+uuid.Must(uuid.NewV7()).String(), nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestScanJobsAdmin_Get_BadUUID_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore(), uuid.Must(uuid.NewV7()))
	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/scan-jobs/not-a-uuid", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestScanJobsAdmin_Cancel_Success(t *testing.T) {
	store := newFakeStore()
	tenantID := uuid.Must(uuid.NewV7())
	j := scanjobs.Job{ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, Profile: scanjobs.ProfileQuick, Status: scanjobs.StatusQueued}
	store.items[j.ID] = j

	ts := newTestServer(t, store, tenantID)
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/"+j.ID.String()+"/cancel", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	requested, _ := store.IsCancelRequested(context.Background(), j.ID)
	assert.True(t, requested, "cancel handler must flip cancel_requested via store")
}

func TestScanJobsAdmin_Cancel_MissingReturns404(t *testing.T) {
	ts := newTestServer(t, newFakeStore(), uuid.Must(uuid.NewV7()))
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/scan-jobs/"+uuid.Must(uuid.NewV7()).String()+"/cancel", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
