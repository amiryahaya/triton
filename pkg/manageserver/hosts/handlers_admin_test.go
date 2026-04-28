package hosts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
)

// --- fakeStore --------------------------------------------------------------

// fakeStore is an in-memory hosts.Store for handler unit tests.
// Concurrency guard mirrors the real store's thread-safety envelope.
type fakeStore struct {
	mu    sync.Mutex
	items map[uuid.UUID]hosts.Host

	// calls records which API entrypoints were invoked (used by
	// list-filter tests to assert the correct query path).
	calls []string

	// createErr, if set, is returned from the next Create call so
	// handler tests can drive the internal-error branch.
	createErr error

	// tags maps hostID → []tagID for SetTags/ListByTags.
	tags map[uuid.UUID][]uuid.UUID
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		items: map[uuid.UUID]hosts.Host{},
		tags:  map[uuid.UUID][]uuid.UUID{},
	}
}

func (f *fakeStore) recordCall(name string) {
	f.calls = append(f.calls, name)
}

func (f *fakeStore) Create(_ context.Context, h hosts.Host) (hosts.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("Create")
	if f.createErr != nil {
		err := f.createErr
		f.createErr = nil
		return hosts.Host{}, err
	}
	// ip is the unique key now.
	for _, existing := range f.items {
		if existing.IP == h.IP {
			return hosts.Host{}, hosts.ErrConflict
		}
	}
	h.ID = uuid.Must(uuid.NewV7())
	f.items[h.ID] = h
	return h, nil
}

func (f *fakeStore) Get(_ context.Context, id uuid.UUID) (hosts.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("Get")
	h, ok := f.items[id]
	if !ok {
		return hosts.Host{}, hosts.ErrNotFound
	}
	return h, nil
}

func (f *fakeStore) List(_ context.Context) ([]hosts.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("List")
	out := make([]hosts.Host, 0, len(f.items))
	for _, h := range f.items {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

func (f *fakeStore) Update(_ context.Context, h hosts.Host) (hosts.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("Update")
	if _, ok := f.items[h.ID]; !ok {
		return hosts.Host{}, hosts.ErrNotFound
	}
	// ip is the unique key now.
	for id, existing := range f.items {
		if existing.IP == h.IP && id != h.ID {
			return hosts.Host{}, hosts.ErrConflict
		}
	}
	f.items[h.ID] = h
	return h, nil
}

func (f *fakeStore) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("Delete")
	if _, ok := f.items[id]; !ok {
		return hosts.ErrNotFound
	}
	delete(f.items, id)
	return nil
}

func (f *fakeStore) Count(_ context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("Count")
	return int64(len(f.items)), nil
}

func (f *fakeStore) SetTags(_ context.Context, hostID uuid.UUID, tagIDs []uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("SetTags")
	f.tags[hostID] = tagIDs
	return nil
}

func (f *fakeStore) ResolveTagNames(_ context.Context, names []string, _ string) ([]uuid.UUID, error) {
	f.recordCall("ResolveTagNames")
	ids := make([]uuid.UUID, len(names))
	for i := range names {
		ids[i] = uuid.New()
	}
	return ids, nil
}

func (f *fakeStore) ListByTags(_ context.Context, tagIDs []uuid.UUID) ([]hosts.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("ListByTags")
	want := map[uuid.UUID]struct{}{}
	for _, id := range tagIDs {
		want[id] = struct{}{}
	}
	seen := map[uuid.UUID]struct{}{}
	out := make([]hosts.Host, 0)
	for hostID, hostTagIDs := range f.tags {
		for _, tid := range hostTagIDs {
			if _, ok := want[tid]; ok {
				if _, dup := seen[hostID]; !dup {
					if h, ok := f.items[hostID]; ok {
						out = append(out, h)
						seen[hostID] = struct{}{}
					}
				}
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

func (f *fakeStore) CountByTag(_ context.Context, tagID uuid.UUID) (int64, error) {
	list, _ := f.ListByTags(context.Background(), []uuid.UUID{tagID})
	return int64(len(list)), nil
}

func (f *fakeStore) ListByHostnames(_ context.Context, names []string) ([]hosts.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("ListByHostnames")
	set := map[string]struct{}{}
	for _, n := range names {
		set[n] = struct{}{}
	}
	out := make([]hosts.Host, 0)
	for _, h := range f.items {
		if _, ok := set[h.Hostname]; ok {
			out = append(out, h)
		}
	}
	return out, nil
}

// BulkCreate mirrors the real store's transactional semantics: any
// conflict rolls back every insert in the batch.
func (f *fakeStore) BulkCreate(_ context.Context, batch []hosts.Host) ([]hosts.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCall("BulkCreate")
	// Stage a snapshot so we can roll back on conflict.
	snapshot := make(map[uuid.UUID]hosts.Host, len(f.items))
	for k, v := range f.items {
		snapshot[k] = v
	}
	out := make([]hosts.Host, 0, len(batch))
	seen := map[string]struct{}{}
	for _, h := range batch {
		// Conflict against pre-existing row (ip is the unique key).
		for _, existing := range f.items {
			if existing.IP == h.IP {
				f.items = snapshot
				return nil, hosts.ErrConflict
			}
		}
		// Conflict within the batch itself.
		if _, dup := seen[h.IP]; dup {
			f.items = snapshot
			return nil, hosts.ErrConflict
		}
		seen[h.IP] = struct{}{}
		h.ID = uuid.Must(uuid.NewV7())
		f.items[h.ID] = h
		out = append(out, h)
	}
	return out, nil
}

// --- helpers ---------------------------------------------------------------

func newTestServer(t *testing.T, s hosts.Store) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/api/v1/admin/hosts", func(r chi.Router) {
		hosts.MountAdminRoutes(r, hosts.NewAdminHandlers(s, nil))
	})
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

// mountTest returns an http.Handler for unit tests that use httptest.NewRecorder
// directly (no test server). Routes are mounted at "/{id}" and "/{id}/tags".
func mountTest(s hosts.Store) http.Handler {
	r := chi.NewRouter()
	r.Route("/", func(r chi.Router) {
		hosts.MountAdminRoutes(r, hosts.NewAdminHandlers(s, nil))
	})
	return r
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

// --- tests -----------------------------------------------------------------

func TestHostsAdmin_CreateGetListPatchDelete_RoundTrip(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/", map[string]string{
		"ip":       "10.0.0.5",
		"hostname": "web01.example.com",
		"os":       "linux",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created hosts.Host
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	assert.Equal(t, "10.0.0.5", created.IP)
	assert.Equal(t, "web01.example.com", created.Hostname)

	resp = doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/hosts/"+created.ID.String(), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	resp = doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/hosts/", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list []hosts.Host
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	resp.Body.Close()
	assert.Len(t, list, 1)

	resp = doReq(t, http.MethodPatch, ts.URL+"/api/v1/admin/hosts/"+created.ID.String(), map[string]string{
		"ip":       "10.0.0.5",
		"hostname": "web01-renamed",
		"os":       "linux-ubuntu",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var patched hosts.Host
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&patched))
	resp.Body.Close()
	assert.Equal(t, "web01-renamed", patched.Hostname)
	assert.Equal(t, "linux-ubuntu", patched.OS)

	resp = doReq(t, http.MethodDelete, ts.URL+"/api/v1/admin/hosts/"+created.ID.String(), nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	resp = doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/hosts/"+created.ID.String(), nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

// TestHostsAdmin_Create_MissingIP_Returns400 verifies that omitting the
// required ip field is rejected with a 400 before reaching the store.
func TestHostsAdmin_Create_MissingIP_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/", map[string]string{"os": "linux"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

// TestHostsAdmin_Create_MissingHostname_Returns400 keeps a placeholder test
// that now verifies hostname-only requests are rejected (no ip).
func TestHostsAdmin_Create_MissingHostname_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	// Sending hostname without ip should be rejected (ip is now required).
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/", map[string]string{"hostname": "only-hostname"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestHostsAdmin_Create_ConflictReturns409(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	// First insert ok.
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/", map[string]string{"ip": "10.0.0.1"})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// Second insert with same ip conflicts.
	resp = doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/", map[string]string{"ip": "10.0.0.1"})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
}

func TestHostsAdmin_List_NoTagFilter_CallsList(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/hosts/", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	assert.Contains(t, store.calls, "List")
	assert.NotContains(t, store.calls, "ListByTags")
}

func TestHostsAdmin_List_WithTagFilter_CallsListByTags(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	tagID := uuid.Must(uuid.NewV7())
	h1, err := store.Create(context.Background(), hosts.Host{IP: "10.0.0.1", Hostname: "tagged"})
	require.NoError(t, err)
	err = store.SetTags(context.Background(), h1.ID, []uuid.UUID{tagID})
	require.NoError(t, err)
	_, err = store.Create(context.Background(), hosts.Host{IP: "10.0.0.2", Hostname: "untagged"})
	require.NoError(t, err)
	// Reset call log so the test only inspects the LIST invocation.
	store.calls = nil

	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/hosts/?tag_id="+tagID.String(), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list []hosts.Host
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	resp.Body.Close()
	assert.Len(t, list, 1)
	assert.Equal(t, "10.0.0.1", list[0].IP)

	assert.Contains(t, store.calls, "ListByTags")
	assert.NotContains(t, store.calls, "List")
}

func TestHostsAdmin_List_BadTagID_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/hosts/?tag_id=not-a-uuid", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestHostsAdmin_BulkCreate_Success(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	body := map[string]any{
		"hosts": []map[string]string{
			{"ip": "10.0.0.1", "hostname": "bulk-1"},
			{"ip": "10.0.0.2", "hostname": "bulk-2"},
			{"ip": "10.0.0.3"},
		},
	}
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/bulk", body)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var out []hosts.Host
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	resp.Body.Close()
	assert.Len(t, out, 3)

	// All three persisted.
	count, err := store.Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestHostsAdmin_BulkCreate_ConflictRollsBackAll(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	// Pre-existing row that the batch will collide with.
	_, err := store.Create(context.Background(), hosts.Host{IP: "10.0.0.99"})
	require.NoError(t, err)

	body := map[string]any{
		"hosts": []map[string]string{
			{"ip": "10.0.0.1"},
			{"ip": "10.0.0.99"}, // boom — collides with pre-existing
			{"ip": "10.0.0.2"},
		},
	}
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/bulk", body)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()

	// Only the pre-existing row should remain; no partial inserts.
	all, err := store.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, all, 1)
	assert.Equal(t, "10.0.0.99", all[0].IP)
}

func TestHostsAdmin_BulkCreate_EmptyBody_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/bulk", map[string]any{"hosts": []map[string]string{}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestHostsAdmin_Get_BadUUID_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/hosts/not-a-uuid", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestHostsAdmin_Patch_MissingReturns404(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	resp := doReq(t, http.MethodPatch, ts.URL+"/api/v1/admin/hosts/"+uuid.Must(uuid.NewV7()).String(),
		map[string]string{"ip": "10.0.0.1"})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

// TestHostsAdmin_Update_EmptyIPRejected verifies that PATCH with a blank
// (whitespace-only) ip is rejected 400 before reaching the store.
func TestHostsAdmin_Update_EmptyIPRejected(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	h, err := store.Create(context.Background(), hosts.Host{IP: "10.0.0.1"})
	require.NoError(t, err)

	resp := doReq(t, http.MethodPatch, ts.URL+"/api/v1/admin/hosts/"+h.ID.String(),
		map[string]string{"ip": "   "})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

// TestHostsAdmin_Update_EmptyHostnameRejected is kept as a regression guard:
// hostname is now optional, so sending an empty hostname with a valid ip must
// succeed (not be rejected).
func TestHostsAdmin_Update_EmptyHostnameRejected(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	h, err := store.Create(context.Background(), hosts.Host{IP: "10.0.0.1", Hostname: "seeded"})
	require.NoError(t, err)

	// Empty hostname with valid ip should now succeed (hostname is optional).
	resp := doReq(t, http.MethodPatch, ts.URL+"/api/v1/admin/hosts/"+h.ID.String(),
		map[string]string{"ip": "10.0.0.1", "hostname": "   "})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestHostsAdmin_Create_InvalidIPReturns400(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/", map[string]string{
		"ip": "not-an-ip",
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()

	// Ensure the store was never called with invalid input.
	assert.NotContains(t, store.calls, "Create")
}

func TestHostsAdmin_Update_InvalidIPReturns400(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	h, err := store.Create(context.Background(), hosts.Host{IP: "10.0.0.1"})
	require.NoError(t, err)
	store.calls = nil

	resp := doReq(t, http.MethodPatch, ts.URL+"/api/v1/admin/hosts/"+h.ID.String(), map[string]string{
		"ip": "not-an-ip",
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
	assert.NotContains(t, store.calls, "Update")
}

// TestHostsAdmin_Create_InternalError_NoLeakage asserts that when the
// store returns an arbitrary non-sentinel error (typical of a pg driver
// failure like connection lost or SQLSTATE leaking), the handler
// returns a generic body instead of echoing the pg error text.
func TestHostsAdmin_Create_InternalError_NoLeakage(t *testing.T) {
	store := newFakeStore()
	store.createErr = errors.New("ERROR: connection refused to host=secret.db.internal (SQLSTATE 08006)")
	ts := newTestServer(t, store)

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/", map[string]string{
		"ip": "10.0.0.1",
	})
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()

	assert.Equal(t, "internal server error", body["error"],
		"internal error must be sanitised before reaching the client")
	assert.NotContains(t, body["error"], "secret.db.internal",
		"pg connection details must never leak to clients")
}

func TestHostsAdmin_BulkCreate_InvalidIPReturns400(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	body := map[string]any{
		"hosts": []map[string]string{
			{"ip": "10.0.0.1"},
			{"ip": "not-an-ip"}, // boom at index 1
			{"ip": "10.0.0.3"},
		},
	}
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/hosts/bulk", body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()

	// No partial inserts: the store must never have been called.
	assert.NotContains(t, store.calls, "BulkCreate")

	count, err := store.Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestHandlers_SetTags(t *testing.T) {
	store := newFakeStore()
	h, err := store.Create(context.Background(), hosts.Host{IP: "10.0.0.1", OS: "linux"})
	require.NoError(t, err)

	tagID := uuid.New()
	body, err := json.Marshal(map[string]any{"tag_ids": []string{tagID.String()}})
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPut, "/"+h.ID.String()+"/tags", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}
