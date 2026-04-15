package inventory

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

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/server"
)

// --- fake Store for handler tests ---

type fakeStore struct {
	mu     sync.Mutex
	groups map[uuid.UUID]Group
	hosts  map[uuid.UUID]Host
	tags   map[uuid.UUID][]Tag
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		groups: map[uuid.UUID]Group{},
		hosts:  map[uuid.UUID]Host{},
		tags:   map[uuid.UUID][]Tag{},
	}
}

func (f *fakeStore) CreateGroup(_ context.Context, g Group) (Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups[g.ID] = g
	return g, nil
}

func (f *fakeStore) GetGroup(_ context.Context, orgID, id uuid.UUID) (Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.groups[id]
	if !ok || g.OrgID != orgID {
		return Group{}, errors.New("not found")
	}
	return g, nil
}

func (f *fakeStore) ListGroups(_ context.Context, orgID uuid.UUID) ([]Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Group{}
	for _, g := range f.groups {
		if g.OrgID == orgID {
			out = append(out, g)
		}
	}
	return out, nil
}

func (f *fakeStore) UpdateGroup(_ context.Context, orgID, id uuid.UUID, name, desc string) (Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.groups[id]
	if !ok || g.OrgID != orgID {
		return Group{}, errors.New("not found")
	}
	g.Name = name
	g.Description = desc
	f.groups[id] = g
	return g, nil
}

func (f *fakeStore) DeleteGroup(_ context.Context, orgID, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if g, ok := f.groups[id]; ok && g.OrgID == orgID {
		delete(f.groups, id)
	}
	return nil
}

func (f *fakeStore) CreateHost(_ context.Context, h Host) (Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts[h.ID] = h
	return h, nil
}

func (f *fakeStore) GetHost(_ context.Context, orgID, id uuid.UUID) (Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.hosts[id]
	if !ok || h.OrgID != orgID {
		return Host{}, errors.New("not found")
	}
	h.Tags = f.tags[id]
	return h, nil
}

func (f *fakeStore) ListHosts(_ context.Context, orgID uuid.UUID, fl HostFilters) ([]Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Host{}
	for _, h := range f.hosts {
		if h.OrgID != orgID {
			continue
		}
		if fl.GroupID != nil && h.GroupID != *fl.GroupID {
			continue
		}
		if fl.OS != "" && h.OS != fl.OS {
			continue
		}
		if fl.Mode != "" && h.Mode != fl.Mode {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func (f *fakeStore) UpdateHost(_ context.Context, orgID, id uuid.UUID, p HostPatch) (Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.hosts[id]
	if !ok || h.OrgID != orgID {
		return Host{}, errors.New("not found")
	}
	if p.GroupID != nil {
		h.GroupID = *p.GroupID
	}
	if p.Hostname != nil {
		h.Hostname = *p.Hostname
	}
	if p.OS != nil {
		h.OS = *p.OS
	}
	if p.Mode != nil {
		h.Mode = *p.Mode
	}
	f.hosts[id] = h
	return h, nil
}

func (f *fakeStore) DeleteHost(_ context.Context, orgID, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h, ok := f.hosts[id]; ok && h.OrgID == orgID {
		delete(f.hosts, id)
	}
	return nil
}

func (f *fakeStore) SetTags(_ context.Context, hostID uuid.UUID, tags []Tag) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tags[hostID] = tags
	return nil
}

func (f *fakeStore) GetTags(_ context.Context, hostID uuid.UUID) ([]Tag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tags[hostID], nil
}

// --- test helpers ---

func makeReqWithClaims(t *testing.T, method, path string, body any, role string) (*http.Request, uuid.UUID, uuid.UUID) {
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
	return req, orgID, userID
}

func newMountedRouter(h *Handlers) chi.Router {
	r := chi.NewRouter()
	MountRoutes(r, h)
	return r
}

// --- tests ---

func TestCreateGroup_Success(t *testing.T) {
	fs := newFakeStore()
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	req, _, _ := makeReqWithClaims(t, "POST", "/groups",
		map[string]string{"name": "prod"}, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "body=%s", rr.Body.String())
	var got Group
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, "prod", got.Name)
}

func TestListGroups_OfficerCanRead(t *testing.T) {
	fs := newFakeStore()
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	req, _, _ := makeReqWithClaims(t, "GET", "/groups", nil, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
}

func TestCreateGroup_OfficerForbidden(t *testing.T) {
	fs := newFakeStore()
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	req, _, _ := makeReqWithClaims(t, "POST", "/groups",
		map[string]string{"name": "prod"}, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestCreateHost_DecodesAddress(t *testing.T) {
	fs := newFakeStore()
	// Seed a group so we have a valid group_id (the fake doesn't enforce FK,
	// but we still want to mirror real input shape).
	gID := uuid.Must(uuid.NewV7())

	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	req, _, _ := makeReqWithClaims(t, "POST", "/hosts", map[string]any{
		"group_id": gID.String(),
		"hostname": "db-1",
		"address":  "10.0.0.42",
		"os":       "linux",
	}, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "body=%s", rr.Body.String())
	var got Host
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, "db-1", got.Hostname)
	require.NotNil(t, got.Address)
	assert.Equal(t, "10.0.0.42", got.Address.String())
}

func TestListHosts_FiltersByGroup(t *testing.T) {
	fs := newFakeStore()
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	orgID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	gA := uuid.Must(uuid.NewV7())
	gB := uuid.Must(uuid.NewV7())
	// Seed hosts directly in the fake so we don't have to round-trip.
	fs.hosts[uuid.Must(uuid.NewV7())] = Host{
		ID: uuid.Must(uuid.NewV7()), OrgID: orgID, GroupID: gA, Hostname: "a1", Mode: "agentless",
	}
	fs.hosts[uuid.Must(uuid.NewV7())] = Host{
		ID: uuid.Must(uuid.NewV7()), OrgID: orgID, GroupID: gB, Hostname: "b1", Mode: "agentless",
	}

	// Build req manually to reuse our orgID/userID for the fake.
	req := httptest.NewRequest("GET", "/hosts?group_id="+gA.String(), nil)
	claims := &auth.UserClaims{Sub: userID.String(), Org: orgID.String(), Role: server.RoleOfficer}
	req = req.WithContext(server.ContextWithClaimsForTesting(req.Context(), claims))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var got []Host
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got, 1)
	assert.Equal(t, gA, got[0].GroupID)
}
