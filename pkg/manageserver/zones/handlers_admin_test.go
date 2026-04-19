package zones_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/zones"
)

// --- fakeStore --------------------------------------------------------------

// fakeStore is an in-memory zones.Store for handler unit tests.
type fakeStore struct {
	mu    sync.Mutex
	items map[uuid.UUID]zones.Zone

	// createErr, if set, is returned from the next Create call.
	createErr error

	// conflictOnName, if non-empty, causes the next Create or Update
	// call with a matching (trimmed) name to return zones.ErrConflict
	// and then clear the hook. Lets tests deterministically trigger
	// the 409 path without relying on store-internal uniqueness.
	conflictOnName string
}

func newFakeStore() *fakeStore {
	return &fakeStore{items: map[uuid.UUID]zones.Zone{}}
}

func (f *fakeStore) Create(_ context.Context, z zones.Zone) (zones.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return zones.Zone{}, f.createErr
	}
	if f.conflictOnName != "" && z.Name == f.conflictOnName {
		f.conflictOnName = ""
		return zones.Zone{}, zones.ErrConflict
	}
	z.ID = uuid.Must(uuid.NewV7())
	f.items[z.ID] = z
	return z, nil
}

func (f *fakeStore) Get(_ context.Context, id uuid.UUID) (zones.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	z, ok := f.items[id]
	if !ok {
		return zones.Zone{}, zones.ErrNotFound
	}
	return z, nil
}

func (f *fakeStore) List(_ context.Context) ([]zones.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]zones.Zone, 0, len(f.items))
	for _, z := range f.items {
		out = append(out, z)
	}
	return out, nil
}

func (f *fakeStore) Update(_ context.Context, z zones.Zone) (zones.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.items[z.ID]; !ok {
		return zones.Zone{}, zones.ErrNotFound
	}
	if f.conflictOnName != "" && z.Name == f.conflictOnName {
		f.conflictOnName = ""
		return zones.Zone{}, zones.ErrConflict
	}
	f.items[z.ID] = z
	return z, nil
}

func (f *fakeStore) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.items[id]; !ok {
		return zones.ErrNotFound
	}
	delete(f.items, id)
	return nil
}

func (f *fakeStore) Count(_ context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.items)), nil
}

// --- helpers ---------------------------------------------------------------

func newTestServer(t *testing.T, s zones.Store) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/api/v1/admin/zones", func(r chi.Router) {
		zones.MountAdminRoutes(r, zones.NewAdminHandlers(s))
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

// --- tests -----------------------------------------------------------------

func TestZonesAdmin_CreateGetListPatchDelete_RoundTrip(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	// POST -> 201 Created
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/zones/", map[string]string{
		"name":        "dmz",
		"description": "perimeter",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created zones.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	assert.Equal(t, "dmz", created.Name)
	assert.NotEqual(t, uuid.Nil, created.ID)

	// GET -> 200 OK
	resp = doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/zones/"+created.ID.String(), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var fetched zones.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&fetched))
	resp.Body.Close()
	assert.Equal(t, created.ID, fetched.ID)

	// LIST -> 200 OK
	resp = doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/zones/", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list []zones.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	resp.Body.Close()
	assert.Len(t, list, 1)

	// PATCH -> 200 OK
	resp = doReq(t, http.MethodPatch, ts.URL+"/api/v1/admin/zones/"+created.ID.String(), map[string]string{
		"name":        "dmz-updated",
		"description": "perimeter v2",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var patched zones.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&patched))
	resp.Body.Close()
	assert.Equal(t, "dmz-updated", patched.Name)
	assert.Equal(t, "perimeter v2", patched.Description)

	// DELETE -> 204 No Content
	resp = doReq(t, http.MethodDelete, ts.URL+"/api/v1/admin/zones/"+created.ID.String(), nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// GET again -> 404
	resp = doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/zones/"+created.ID.String(), nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestZonesAdmin_Create_MissingName_Returns400(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/zones/", map[string]string{"description": "oops"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestZonesAdmin_Create_BadJSON_Returns400(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/zones/", bytes.NewReader([]byte("not-json")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestZonesAdmin_Get_BadUUID_Returns400(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/zones/not-a-uuid", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestZonesAdmin_Get_MissingReturns404(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	resp := doReq(t, http.MethodGet, ts.URL+"/api/v1/admin/zones/"+uuid.Must(uuid.NewV7()).String(), nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestZonesAdmin_Patch_MissingReturns404(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	resp := doReq(t, http.MethodPatch, ts.URL+"/api/v1/admin/zones/"+uuid.Must(uuid.NewV7()).String(),
		map[string]string{"name": "ghost"})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestZonesAdmin_Delete_MissingReturns404(t *testing.T) {
	ts := newTestServer(t, newFakeStore())

	resp := doReq(t, http.MethodDelete, ts.URL+"/api/v1/admin/zones/"+uuid.Must(uuid.NewV7()).String(), nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestZonesAdmin_Create_DuplicateNameReturns409(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	// Arm the conflict hook so the next Create("dmz") returns ErrConflict.
	store.conflictOnName = "dmz"
	resp := doReq(t, http.MethodPost, ts.URL+"/api/v1/admin/zones/", map[string]string{"name": "dmz"})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
}

func TestZonesAdmin_Update_DuplicateNameReturns409(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	// Seed a zone so Update has something to PATCH.
	z, err := store.Create(context.Background(), zones.Zone{Name: "initial"})
	require.NoError(t, err)

	// Arm the conflict hook so the next Update(name: "clash") returns ErrConflict.
	store.conflictOnName = "clash"
	resp := doReq(t, http.MethodPatch, ts.URL+"/api/v1/admin/zones/"+z.ID.String(),
		map[string]string{"name": "clash"})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
}

func TestZonesAdmin_Update_EmptyNameRejected(t *testing.T) {
	store := newFakeStore()
	ts := newTestServer(t, store)

	z, err := store.Create(context.Background(), zones.Zone{Name: "seed"})
	require.NoError(t, err)

	resp := doReq(t, http.MethodPatch, ts.URL+"/api/v1/admin/zones/"+z.ID.String(),
		map[string]string{"name": "   ", "description": "whitespace only"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}
