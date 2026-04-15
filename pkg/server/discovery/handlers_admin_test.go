package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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

// --- fake discovery Store ----------------------------------------------------

type fakeStore struct {
	mu         sync.Mutex
	jobs       map[uuid.UUID]Job
	candidates map[uuid.UUID][]Candidate

	claimQueue []Job // pre-seeded jobs ClaimNext returns one at a time
	claimErr   error

	cancelErr error // if set, CancelJob returns this instead of the default

	promoteCalls [][]uuid.UUID
	finishCalls  []finishCall
	insertCalls  []insertCall

	createErr error
}

type finishCall struct {
	JobID  uuid.UUID
	Status JobStatus
	Err    string
	Count  int
}

type insertCall struct {
	JobID      uuid.UUID
	Candidates []Candidate
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		jobs:       map[uuid.UUID]Job{},
		candidates: map[uuid.UUID][]Candidate{},
	}
}

func (f *fakeStore) CreateJob(_ context.Context, j Job) (Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return Job{}, f.createErr
	}
	if j.Status == "" {
		j.Status = StatusQueued
	}
	f.jobs[j.ID] = j
	return j, nil
}

func (f *fakeStore) GetJob(_ context.Context, orgID, id uuid.UUID) (Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[id]
	if !ok || j.OrgID != orgID {
		return Job{}, ErrJobNotFound
	}
	return j, nil
}

func (f *fakeStore) ListJobs(_ context.Context, orgID uuid.UUID) ([]Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Job{}
	for _, j := range f.jobs {
		if j.OrgID == orgID {
			out = append(out, j)
		}
	}
	return out, nil
}

func (f *fakeStore) ListCandidates(_ context.Context, jobID uuid.UUID) ([]Candidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.candidates[jobID], nil
}

func (f *fakeStore) MarkCandidatesPromoted(_ context.Context, ids []uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.promoteCalls = append(f.promoteCalls, append([]uuid.UUID(nil), ids...))
	set := map[uuid.UUID]bool{}
	for _, id := range ids {
		set[id] = true
	}
	for jid, cs := range f.candidates {
		for i := range cs {
			if set[cs[i].ID] {
				cs[i].Promoted = true
			}
		}
		f.candidates[jid] = cs
	}
	return nil
}

func (f *fakeStore) CancelJob(_ context.Context, orgID, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cancelErr != nil {
		return f.cancelErr
	}
	j, ok := f.jobs[id]
	if !ok || j.OrgID != orgID {
		return ErrJobNotFound
	}
	if j.Status != StatusQueued {
		return ErrJobNotCancellable
	}
	j.Status = StatusCancelled
	f.jobs[id] = j
	return nil
}

func (f *fakeStore) ClaimNext(_ context.Context, _ uuid.UUID) (Job, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claimErr != nil {
		return Job{}, false, f.claimErr
	}
	if len(f.claimQueue) == 0 {
		return Job{}, false, nil
	}
	j := f.claimQueue[0]
	f.claimQueue = f.claimQueue[1:]
	return j, true, nil
}

func (f *fakeStore) InsertCandidates(_ context.Context, jobID uuid.UUID, cs []Candidate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.insertCalls = append(f.insertCalls, insertCall{JobID: jobID, Candidates: append([]Candidate(nil), cs...)})
	f.candidates[jobID] = append(f.candidates[jobID], cs...)
	return nil
}

func (f *fakeStore) FinishJob(_ context.Context, jobID uuid.UUID, status JobStatus, errMsg string, count int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finishCalls = append(f.finishCalls, finishCall{JobID: jobID, Status: status, Err: errMsg, Count: count})
	return nil
}

func (f *fakeStore) ReclaimStale(_ context.Context, _ time.Time) error {
	return nil
}

var _ Store = (*fakeStore)(nil)

// --- fake inventory Store (promote path only) --------------------------------

type fakeInventoryStore struct {
	mu             sync.Mutex
	hosts          map[uuid.UUID]inventory.Host
	createHostErr  error
	createHostErrs map[string]error // by address, one-shot
}

func newFakeInventoryStore() *fakeInventoryStore {
	return &fakeInventoryStore{
		hosts:          map[uuid.UUID]inventory.Host{},
		createHostErrs: map[string]error{},
	}
}

func (f *fakeInventoryStore) CreateGroup(_ context.Context, g inventory.Group) (inventory.Group, error) {
	return g, nil
}
func (f *fakeInventoryStore) GetGroup(_ context.Context, _, _ uuid.UUID) (inventory.Group, error) {
	return inventory.Group{}, nil
}
func (f *fakeInventoryStore) ListGroups(_ context.Context, _ uuid.UUID) ([]inventory.Group, error) {
	return nil, nil
}
func (f *fakeInventoryStore) UpdateGroup(_ context.Context, _, _ uuid.UUID, _, _ string) (inventory.Group, error) {
	return inventory.Group{}, nil
}
func (f *fakeInventoryStore) DeleteGroup(_ context.Context, _, _ uuid.UUID) error { return nil }

func (f *fakeInventoryStore) CreateHost(_ context.Context, h inventory.Host) (inventory.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h.Address != nil {
		if err, ok := f.createHostErrs[h.Address.String()]; ok {
			delete(f.createHostErrs, h.Address.String())
			return inventory.Host{}, err
		}
	}
	if f.createHostErr != nil {
		return inventory.Host{}, f.createHostErr
	}
	f.hosts[h.ID] = h
	return h, nil
}

func (f *fakeInventoryStore) GetHost(_ context.Context, _, _ uuid.UUID) (inventory.Host, error) {
	return inventory.Host{}, nil
}
func (f *fakeInventoryStore) ListHosts(_ context.Context, _ uuid.UUID, _ inventory.HostFilters) ([]inventory.Host, error) {
	return nil, nil
}
func (f *fakeInventoryStore) UpdateHost(_ context.Context, _, _ uuid.UUID, _ inventory.HostPatch) (inventory.Host, error) {
	return inventory.Host{}, nil
}
func (f *fakeInventoryStore) DeleteHost(_ context.Context, _, _ uuid.UUID) error { return nil }
func (f *fakeInventoryStore) SetTags(_ context.Context, _ uuid.UUID, _ []inventory.Tag) error {
	return nil
}
func (f *fakeInventoryStore) GetTags(_ context.Context, _ uuid.UUID) ([]inventory.Tag, error) {
	return nil, nil
}
func (f *fakeInventoryStore) ImportHosts(_ context.Context, _, _ uuid.UUID, _ []inventory.ImportRow, _ bool) (inventory.ImportResult, error) {
	return inventory.ImportResult{}, nil
}

var _ inventory.Store = (*fakeInventoryStore)(nil)

// --- helpers -----------------------------------------------------------------

func buildAdminRouter(h *AdminHandlers) http.Handler {
	r := chi.NewRouter()
	r.Route("/discovery", func(r chi.Router) {
		MountAdminRoutes(r, h)
	})
	return r
}

func makeReq(t *testing.T, method, path string, body any, role string) (*http.Request, uuid.UUID, uuid.UUID) {
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

// --- tests -------------------------------------------------------------------

func TestCreateDiscovery_Engineer_201(t *testing.T) {
	fs := newFakeStore()
	inv := newFakeInventoryStore()
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"engine_id": uuid.Must(uuid.NewV7()).String(),
		"cidrs":     []string{"10.0.0.0/24"},
		"ports":     []int{22, 443},
	}
	req, _, _ := makeReq(t, http.MethodPost, "/discovery/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "body=%s", rr.Body.String())
	var got Job
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, StatusQueued, got.Status)
	assert.Equal(t, []int{22, 443}, got.Ports)
}

func TestCreateDiscovery_Officer_403(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, newFakeInventoryStore(), nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"engine_id": uuid.Must(uuid.NewV7()).String(),
		"cidrs":     []string{"10.0.0.0/24"},
	}
	req, _, _ := makeReq(t, http.MethodPost, "/discovery/", body, server.RoleOfficer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	assert.Empty(t, fs.jobs)
}

func TestCreateDiscovery_InvalidCIDR_400(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, newFakeInventoryStore(), nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"engine_id": uuid.Must(uuid.NewV7()).String(),
		"cidrs":     []string{"not-a-cidr"},
	}
	req, _, _ := makeReq(t, http.MethodPost, "/discovery/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestCreateDiscovery_DefaultPorts(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, newFakeInventoryStore(), nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"engine_id": uuid.Must(uuid.NewV7()).String(),
		"cidrs":     []string{"10.0.0.0/24"},
	}
	req, _, _ := makeReq(t, http.MethodPost, "/discovery/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)
	var got Job
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, []int{22, 80, 443, 3389, 5985}, got.Ports)
}

func TestCreateDiscovery_InvalidPort_400(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, newFakeInventoryStore(), nil)
	r := buildAdminRouter(h)

	body := map[string]any{
		"engine_id": uuid.Must(uuid.NewV7()).String(),
		"cidrs":     []string{"10.0.0.0/24"},
		"ports":     []int{70000},
	}
	req, _, _ := makeReq(t, http.MethodPost, "/discovery/", body, server.RoleEngineer)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestGetDiscovery_ReturnsJobAndCandidates(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, newFakeInventoryStore(), nil)
	r := buildAdminRouter(h)

	// Seed a job + candidates in fs. Because makeReq generates a fresh
	// orgID per request, we build the request first and then seed.
	req, orgID, _ := makeReq(t, http.MethodGet, "/discovery/"+uuid.Must(uuid.NewV7()).String(), nil, server.RoleOfficer)
	jobID := uuid.MustParse(chiLastPath(req.URL.Path))
	fs.jobs[jobID] = Job{ID: jobID, OrgID: orgID, Status: StatusCompleted}
	fs.candidates[jobID] = []Candidate{
		{ID: uuid.Must(uuid.NewV7()), JobID: jobID, Address: net.ParseIP("10.0.0.5")},
	}

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var got jobWithCandidates
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, jobID, got.Job.ID)
	require.Len(t, got.Candidates, 1)
	assert.Equal(t, "10.0.0.5", got.Candidates[0].Address.String())
}

// chiLastPath returns the final "/{id}" segment of a URL path. Small
// helper so we don't pull strings into the test for a one-liner.
func chiLastPath(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func TestPromoteCandidates_Engineer_CreatesHostsAndMarksPromoted(t *testing.T) {
	fs := newFakeStore()
	inv := newFakeInventoryStore()
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	c1 := Candidate{ID: uuid.Must(uuid.NewV7()), JobID: jobID, Address: net.ParseIP("10.0.0.1")}
	c2 := Candidate{ID: uuid.Must(uuid.NewV7()), JobID: jobID, Address: net.ParseIP("10.0.0.2")}

	body := map[string]any{
		"candidate_ids": []string{c1.ID.String(), c2.ID.String()},
		"group_id":      uuid.Must(uuid.NewV7()).String(),
	}
	req, orgID, _ := makeReq(t, http.MethodPost, "/discovery/"+jobID.String()+"/promote", body, server.RoleEngineer)
	fs.jobs[jobID] = Job{ID: jobID, OrgID: orgID}
	fs.candidates[jobID] = []Candidate{c1, c2}

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var got promoteResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, 2, got.Promoted)
	assert.Equal(t, 0, got.Failed)
	assert.Len(t, inv.hosts, 2)
	require.Len(t, fs.promoteCalls, 1)
	assert.ElementsMatch(t, []uuid.UUID{c1.ID, c2.ID}, fs.promoteCalls[0])
}

func TestPromoteCandidates_DuplicateHost_ReportedButContinues(t *testing.T) {
	fs := newFakeStore()
	inv := newFakeInventoryStore()
	h := NewAdminHandlers(fs, inv, nil)
	r := buildAdminRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	c1 := Candidate{ID: uuid.Must(uuid.NewV7()), JobID: jobID, Address: net.ParseIP("10.0.0.1")}
	c2 := Candidate{ID: uuid.Must(uuid.NewV7()), JobID: jobID, Address: net.ParseIP("10.0.0.2")}
	inv.createHostErrs["10.0.0.2"] = errors.New("duplicate address")

	body := map[string]any{
		"candidate_ids": []string{c1.ID.String(), c2.ID.String()},
		"group_id":      uuid.Must(uuid.NewV7()).String(),
	}
	req, orgID, _ := makeReq(t, http.MethodPost, "/discovery/"+jobID.String()+"/promote", body, server.RoleEngineer)
	fs.jobs[jobID] = Job{ID: jobID, OrgID: orgID}
	fs.candidates[jobID] = []Candidate{c1, c2}

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var got promoteResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, 1, got.Promoted)
	assert.Equal(t, 1, got.Failed)
	require.Len(t, got.Errors, 1)
	assert.Equal(t, c2.ID.String(), got.Errors[0].CandidateID)
	// MarkCandidatesPromoted only called with successes.
	require.Len(t, fs.promoteCalls, 1)
	assert.Equal(t, []uuid.UUID{c1.ID}, fs.promoteCalls[0])
}

func TestCancelDiscovery_QueuedJob_200(t *testing.T) {
	fs := newFakeStore()
	h := NewAdminHandlers(fs, newFakeInventoryStore(), nil)
	r := buildAdminRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	req, orgID, _ := makeReq(t, http.MethodPost, "/discovery/"+jobID.String()+"/cancel", nil, server.RoleEngineer)
	fs.jobs[jobID] = Job{ID: jobID, OrgID: orgID, Status: StatusQueued}

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	assert.Equal(t, StatusCancelled, fs.jobs[jobID].Status)
}

func TestCancelDiscovery_ClaimedJob_409(t *testing.T) {
	fs := newFakeStore()
	fs.cancelErr = ErrJobNotCancellable
	h := NewAdminHandlers(fs, newFakeInventoryStore(), nil)
	r := buildAdminRouter(h)

	jobID := uuid.Must(uuid.NewV7())
	req, _, _ := makeReq(t, http.MethodPost, "/discovery/"+jobID.String()+"/cancel", nil, server.RoleEngineer)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
}
