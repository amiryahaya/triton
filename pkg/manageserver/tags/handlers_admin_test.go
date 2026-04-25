package tags_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
)

// --- fakeStore --------------------------------------------------------------

// fakeStore is an in-memory tags.Store for handler unit tests.
type fakeStore struct {
	mu      sync.Mutex
	items   map[uuid.UUID]tags.Tag
	listErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{items: map[uuid.UUID]tags.Tag{}}
}

func (f *fakeStore) Create(_ context.Context, t tags.Tag) (tags.Tag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.items {
		if existing.Name == t.Name {
			return tags.Tag{}, tags.ErrConflict
		}
	}
	t.ID = uuid.Must(uuid.NewV7())
	f.items[t.ID] = t
	return t, nil
}

func (f *fakeStore) Get(_ context.Context, id uuid.UUID) (tags.Tag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.items[id]
	if !ok {
		return tags.Tag{}, tags.ErrNotFound
	}
	return t, nil
}

func (f *fakeStore) List(_ context.Context) ([]tags.Tag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]tags.Tag, 0, len(f.items))
	for _, t := range f.items {
		out = append(out, t)
	}
	return out, nil
}

func (f *fakeStore) Update(_ context.Context, t tags.Tag) (tags.Tag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.items[t.ID]; !ok {
		return tags.Tag{}, tags.ErrNotFound
	}
	f.items[t.ID] = t
	return t, nil
}

func (f *fakeStore) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.items[id]; !ok {
		return tags.ErrNotFound
	}
	delete(f.items, id)
	return nil
}

// --- helpers ----------------------------------------------------------------

func mountTest(s tags.Store) *chi.Mux {
	r := chi.NewRouter()
	tags.MountAdminRoutes(r, tags.NewAdminHandlers(s))
	return r
}

// --- tests ------------------------------------------------------------------

func TestHandlers_List(t *testing.T) {
	store := newFakeStore()
	_, err := store.Create(context.Background(), tags.Tag{Name: "alpha", Color: "#EF4444"})
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var out []tags.Tag
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.Len(t, out, 1)
}

func TestHandlers_Create(t *testing.T) {
	store := newFakeStore()
	body := `{"name":"production","color":"#EF4444"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)
	var out tags.Tag
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.Equal(t, "production", out.Name)
	assert.Equal(t, "#EF4444", out.Color)
}

func TestHandlers_Create_InvalidColor(t *testing.T) {
	store := newFakeStore()
	body := `{"name":"x","color":"not-a-color"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Create_MissingName(t *testing.T) {
	store := newFakeStore()
	body := `{"color":"#EF4444"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Create_Conflict(t *testing.T) {
	store := newFakeStore()
	_, err := store.Create(context.Background(), tags.Tag{Name: "dup", Color: "#EF4444"})
	require.NoError(t, err)

	body := `{"name":"dup","color":"#22C55E"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestHandlers_Update(t *testing.T) {
	store := newFakeStore()
	tag, err := store.Create(context.Background(), tags.Tag{Name: "old", Color: "#EF4444"})
	require.NoError(t, err)

	body := `{"name":"new","color":"#22C55E"}`
	r := httptest.NewRequest(http.MethodPatch, "/"+tag.ID.String(), bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var out tags.Tag
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.Equal(t, "new", out.Name)
	assert.Equal(t, "#22C55E", out.Color)
}

func TestHandlers_Delete(t *testing.T) {
	store := newFakeStore()
	tag, err := store.Create(context.Background(), tags.Tag{Name: "gone", Color: "#EF4444"})
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodDelete, "/"+tag.ID.String(), nil)
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestHandlers_Delete_NotFound(t *testing.T) {
	store := newFakeStore()
	r := httptest.NewRequest(http.MethodDelete, "/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandlers_List_StoreError(t *testing.T) {
	store := newFakeStore()
	store.listErr = errors.New("db down")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
