package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/server"
)

// --- fakeStore ---------------------------------------------------------------

// fakeStore is an in-memory Store for handler tests. All methods are
// safe for sequential tests; concurrent use is not required here.
type fakeStore struct {
	mu sync.Mutex

	cas     map[uuid.UUID]*CA
	engines map[uuid.UUID]Engine

	// createErr, if set, is returned from the next CreateEngine call.
	createErr error

	firstSeenCalls []uuid.UUID
	pollCalls      []uuid.UUID
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		cas:     map[uuid.UUID]*CA{},
		engines: map[uuid.UUID]Engine{},
	}
}

func (f *fakeStore) UpsertCA(_ context.Context, orgID uuid.UUID, ca *CA) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas[orgID] = ca
	return nil
}

func (f *fakeStore) GetCA(_ context.Context, orgID uuid.UUID) (*CA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ca, ok := f.cas[orgID]
	if !ok {
		return nil, ErrCANotFound
	}
	return ca, nil
}

func (f *fakeStore) CreateEngine(_ context.Context, e Engine) (Engine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		err := f.createErr
		f.createErr = nil
		return Engine{}, err
	}
	for _, existing := range f.engines {
		if existing.OrgID == e.OrgID && existing.Label == e.Label {
			return Engine{}, &pgconn.PgError{Code: "23505", Message: "duplicate label"}
		}
	}
	f.engines[e.ID] = e
	return e, nil
}

func (f *fakeStore) GetEngine(_ context.Context, orgID, id uuid.UUID) (Engine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.engines[id]
	if !ok || e.OrgID != orgID {
		return Engine{}, ErrEngineNotFound
	}
	return e, nil
}

func (f *fakeStore) GetEngineByFingerprint(_ context.Context, fp string) (Engine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.engines {
		if e.CertFingerprint == fp {
			return e, nil
		}
	}
	return Engine{}, ErrEngineNotFound
}

func (f *fakeStore) ListEngines(_ context.Context, orgID uuid.UUID) ([]Engine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Engine{}
	for _, e := range f.engines {
		if e.OrgID == orgID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeStore) RecordFirstSeen(_ context.Context, id uuid.UUID, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.firstSeenCalls = append(f.firstSeenCalls, id)
	e, ok := f.engines[id]
	if !ok {
		return false, errors.New("not found")
	}
	if e.FirstSeenAt != nil {
		return false, nil
	}
	now := time.Now().UTC()
	e.FirstSeenAt = &now
	e.Status = StatusOnline
	f.engines[id] = e
	return true, nil
}

func (f *fakeStore) RecordPoll(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollCalls = append(f.pollCalls, id)
	e, ok := f.engines[id]
	if !ok {
		return errors.New("not found")
	}
	now := time.Now().UTC()
	e.LastPollAt = &now
	f.engines[id] = e
	return nil
}

func (f *fakeStore) SetStatus(_ context.Context, id uuid.UUID, status string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.engines[id]
	if !ok {
		return errors.New("not found")
	}
	e.Status = status
	f.engines[id] = e
	return nil
}

func (f *fakeStore) Revoke(_ context.Context, orgID, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.engines[id]
	if !ok || e.OrgID != orgID {
		return nil // Revoke is idempotent at this fake boundary
	}
	e.Status = StatusRevoked
	now := time.Now().UTC()
	e.RevokedAt = &now
	f.engines[id] = e
	return nil
}

var _ Store = (*fakeStore)(nil)

// --- helpers -----------------------------------------------------------------

// buildRouter wires just the admin handlers onto a bare Chi router for
// tests. It skips JWTAuth; callers use withClaims to inject identity.
func buildRouter(h *AdminHandlers) http.Handler {
	r := chi.NewRouter()
	r.Route("/engines", func(r chi.Router) {
		MountAdminRoutes(r, h)
	})
	return r
}

func withClaims(r *http.Request, role, orgID string) *http.Request {
	claims := &auth.UserClaims{
		Sub:  uuid.NewString(),
		Org:  orgID,
		Role: role,
	}
	ctx := server.ContextWithClaimsForTesting(r.Context(), claims)
	return r.WithContext(ctx)
}

func zeroMasterKey() []byte { return make([]byte, 32) }

// --- tests -------------------------------------------------------------------

func TestCreateEngine_Engineer_201_ReturnsGzipBundle(t *testing.T) {
	store := newFakeStore()
	h := NewAdminHandlers(store, zeroMasterKey(), "https://portal.example.com")
	r := buildRouter(h)

	orgID := uuid.NewString()
	body := strings.NewReader(`{"label":"edge-1"}`)
	req := httptest.NewRequest(http.MethodPost, "/engines/", body)
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, server.RoleEngineer, orgID)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/gzip" {
		t.Errorf("Content-Type = %q, want application/gzip", got)
	}
	if rec.Header().Get("X-Triton-Engine-Id") == "" {
		t.Error("missing X-Triton-Engine-Id header")
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "engine-edge-1.tar.gz") {
		t.Errorf("Content-Disposition = %q; expected engine-edge-1.tar.gz",
			rec.Header().Get("Content-Disposition"))
	}

	// Verify gzip tar contains engine.json.
	gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		seen[hdr.Name] = true
	}
	for _, want := range []string{"engine.json", "engine.key", "engine.crt", "portal-ca.crt"} {
		if !seen[want] {
			t.Errorf("bundle missing %s", want)
		}
	}
}

func TestCreateEngine_Officer_403(t *testing.T) {
	store := newFakeStore()
	h := NewAdminHandlers(store, zeroMasterKey(), "https://portal.example.com")
	r := buildRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/engines/", strings.NewReader(`{"label":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, server.RoleOfficer, uuid.NewString())

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestCreateEngine_DuplicateLabel_409(t *testing.T) {
	store := newFakeStore()
	h := NewAdminHandlers(store, zeroMasterKey(), "https://portal.example.com")
	r := buildRouter(h)

	orgID := uuid.NewString()

	// First create succeeds.
	req := httptest.NewRequest(http.MethodPost, "/engines/", strings.NewReader(`{"label":"dup"}`))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, server.RoleEngineer, orgID)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// Second with same label → 409.
	req = httptest.NewRequest(http.MethodPost, "/engines/", strings.NewReader(`{"label":"dup"}`))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, server.RoleEngineer, orgID)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestListEngines_Officer_200(t *testing.T) {
	store := newFakeStore()
	orgID := uuid.New()
	store.engines[uuid.New()] = Engine{ID: uuid.New(), OrgID: orgID, Label: "a", Status: StatusEnrolled}

	h := NewAdminHandlers(store, zeroMasterKey(), "https://portal.example.com")
	r := buildRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/engines/", nil)
	req = withClaims(req, server.RoleOfficer, orgID.String())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []Engine
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestGetEngine_NotFound_404(t *testing.T) {
	store := newFakeStore()
	h := NewAdminHandlers(store, zeroMasterKey(), "https://portal.example.com")
	r := buildRouter(h)

	bogus := uuid.NewString()
	req := httptest.NewRequest(http.MethodGet, "/engines/"+bogus, nil)
	req = withClaims(req, server.RoleOfficer, uuid.NewString())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRevokeEngine_Owner_204(t *testing.T) {
	store := newFakeStore()
	orgID := uuid.New()
	engID := uuid.New()
	store.engines[engID] = Engine{ID: engID, OrgID: orgID, Label: "a", Status: StatusEnrolled}

	h := NewAdminHandlers(store, zeroMasterKey(), "https://portal.example.com")
	r := buildRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/engines/"+engID.String()+"/revoke", nil)
	req = withClaims(req, server.RoleOwner, orgID.String())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if store.engines[engID].Status != StatusRevoked {
		t.Errorf("engine status = %q, want %q", store.engines[engID].Status, StatusRevoked)
	}
}

func TestRevokeEngine_Engineer_403(t *testing.T) {
	store := newFakeStore()
	orgID := uuid.New()
	engID := uuid.New()
	store.engines[engID] = Engine{ID: engID, OrgID: orgID, Label: "a", Status: StatusEnrolled}

	h := NewAdminHandlers(store, zeroMasterKey(), "https://portal.example.com")
	r := buildRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/engines/"+engID.String()+"/revoke", nil)
	req = withClaims(req, server.RoleEngineer, orgID.String())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
