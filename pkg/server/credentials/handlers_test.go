package credentials

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/amiryahaya/triton/pkg/server/engine"
	"github.com/amiryahaya/triton/pkg/server/hostmatch"
	"github.com/amiryahaya/triton/pkg/server/inventory"
)

// --- fakeStore (credentials.Store) ------------------------------------------

type fakeStore struct {
	mu         sync.Mutex
	profiles   map[uuid.UUID]Profile
	deliveries []Delivery
	tests      map[uuid.UUID]TestJob
	results    map[uuid.UUID][]TestResult
	pubkeys    map[uuid.UUID][]byte
	createErr  error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		profiles: map[uuid.UUID]Profile{},
		tests:    map[uuid.UUID]TestJob{},
		results:  map[uuid.UUID][]TestResult{},
		pubkeys:  map[uuid.UUID][]byte{},
	}
}

func (f *fakeStore) CreateProfileWithDelivery(_ context.Context, p Profile, ct []byte) (Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return Profile{}, f.createErr
	}
	for _, existing := range f.profiles {
		if existing.OrgID == p.OrgID && existing.Name == p.Name {
			return Profile{}, fakeUniqueViolation{}
		}
	}
	p.CreatedAt = time.Now().UTC()
	f.profiles[p.ID] = p
	f.deliveries = append(f.deliveries, Delivery{
		ID: uuid.New(), OrgID: p.OrgID, EngineID: p.EngineID,
		ProfileID: &p.ID, SecretRef: p.SecretRef, AuthType: p.AuthType,
		Kind: DeliveryPush, Ciphertext: ct, Status: "queued",
	})
	return p, nil
}

func (f *fakeStore) GetProfile(_ context.Context, orgID, id uuid.UUID) (Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.profiles[id]
	if !ok || p.OrgID != orgID {
		return Profile{}, ErrProfileNotFound
	}
	return p, nil
}

func (f *fakeStore) ListProfiles(_ context.Context, orgID uuid.UUID) ([]Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Profile{}
	for _, p := range f.profiles {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeStore) DeleteProfileWithDelivery(_ context.Context, orgID, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.profiles[id]
	if !ok || p.OrgID != orgID {
		return ErrProfileNotFound
	}
	delete(f.profiles, id)
	f.deliveries = append(f.deliveries, Delivery{
		ID: uuid.New(), OrgID: orgID, EngineID: p.EngineID, ProfileID: &id,
		SecretRef: p.SecretRef, AuthType: p.AuthType, Kind: DeliveryDelete, Status: "queued",
	})
	return nil
}

func (f *fakeStore) ClaimNextDelivery(_ context.Context, engineID uuid.UUID) (Delivery, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, d := range f.deliveries {
		if d.EngineID == engineID && d.Status == "queued" {
			f.deliveries[i].Status = "claimed"
			now := time.Now().UTC()
			f.deliveries[i].ClaimedAt = &now
			return f.deliveries[i], true, nil
		}
	}
	return Delivery{}, false, nil
}

func (f *fakeStore) AckDelivery(_ context.Context, id uuid.UUID, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, d := range f.deliveries {
		if d.ID == id {
			if d.Status == "acked" || d.Status == "failed" {
				return ErrDeliveryAlreadyAcked
			}
			if errMsg != "" {
				f.deliveries[i].Status = "failed"
				f.deliveries[i].Error = errMsg
			} else {
				f.deliveries[i].Status = "acked"
			}
			return nil
		}
	}
	return ErrDeliveryAlreadyAcked
}

func (f *fakeStore) ReclaimStaleDeliveries(_ context.Context, _ time.Time) error { return nil }

func (f *fakeStore) CreateTestJob(_ context.Context, t TestJob) (TestJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t.Status = "queued"
	t.RequestedAt = time.Now().UTC()
	f.tests[t.ID] = t
	return t, nil
}

func (f *fakeStore) GetTestJob(_ context.Context, orgID, id uuid.UUID) (TestJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tests[id]
	if !ok || t.OrgID != orgID {
		return TestJob{}, ErrTestAlreadyTerminal // generic not-found
	}
	return t, nil
}

func (f *fakeStore) ListTestResults(_ context.Context, testID uuid.UUID) ([]TestResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.results[testID], nil
}

func (f *fakeStore) ClaimNextTest(_ context.Context, engineID uuid.UUID) (TestJob, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, t := range f.tests {
		if t.EngineID == engineID && t.Status == "queued" {
			t.Status = "claimed"
			now := time.Now().UTC()
			t.ClaimedAt = &now
			f.tests[id] = t
			return t, true, nil
		}
	}
	return TestJob{}, false, nil
}

func (f *fakeStore) InsertTestResults(_ context.Context, rs []TestResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range rs {
		// Overwrite any existing entry for (test_id, host_id).
		existing := f.results[r.TestID]
		replaced := false
		for i, e := range existing {
			if e.HostID == r.HostID {
				existing[i] = r
				replaced = true
				break
			}
		}
		if !replaced {
			existing = append(existing, r)
		}
		f.results[r.TestID] = existing
	}
	return nil
}

func (f *fakeStore) FinishTestJob(_ context.Context, id uuid.UUID, status, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tests[id]
	if !ok {
		return ErrTestAlreadyTerminal
	}
	if t.Status == "completed" || t.Status == "failed" || t.Status == "cancelled" {
		return ErrTestAlreadyTerminal
	}
	t.Status = status
	t.Error = errMsg
	now := time.Now().UTC()
	t.CompletedAt = &now
	f.tests[id] = t
	return nil
}

func (f *fakeStore) ReclaimStaleTests(_ context.Context, _ time.Time) error { return nil }

func (f *fakeStore) GetEngineEncryptionPubkey(_ context.Context, engineID uuid.UUID) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pubkeys[engineID], nil
}

// fakeUniqueViolation mimics pgconn.PgError{Code:"23505"} so the
// handler's isUniqueViolation returns true without pulling pgx into
// the handler package's test surface. We satisfy the two methods the
// errors.As assertion actually touches.
type fakeUniqueViolation struct{}

func (fakeUniqueViolation) Error() string { return "duplicate key" }

// --- fakeEngineStore --------------------------------------------------------

type fakeEngineStore struct {
	engines map[uuid.UUID]engine.Engine
	pubkeys map[uuid.UUID][]byte
}

func newFakeEngineStore() *fakeEngineStore {
	return &fakeEngineStore{
		engines: map[uuid.UUID]engine.Engine{},
		pubkeys: map[uuid.UUID][]byte{},
	}
}

func (f *fakeEngineStore) seedEngine(orgID uuid.UUID) uuid.UUID {
	id := uuid.Must(uuid.NewV7())
	f.engines[id] = engine.Engine{ID: id, OrgID: orgID, Label: "eng"}
	return id
}

func (f *fakeEngineStore) UpsertCA(context.Context, uuid.UUID, *engine.CA) error { return nil }
func (f *fakeEngineStore) GetCA(context.Context, uuid.UUID) (*engine.CA, error)  { return nil, nil }
func (f *fakeEngineStore) CreateEngine(_ context.Context, e engine.Engine) (engine.Engine, error) {
	f.engines[e.ID] = e
	return e, nil
}
func (f *fakeEngineStore) GetEngine(_ context.Context, orgID, id uuid.UUID) (engine.Engine, error) {
	e, ok := f.engines[id]
	if !ok || e.OrgID != orgID {
		return engine.Engine{}, engine.ErrEngineNotFound
	}
	return e, nil
}
func (f *fakeEngineStore) GetEngineByFingerprint(context.Context, string) (engine.Engine, error) {
	return engine.Engine{}, engine.ErrEngineNotFound
}
func (f *fakeEngineStore) ListEngines(context.Context, uuid.UUID) ([]engine.Engine, error) {
	return nil, nil
}
func (f *fakeEngineStore) RecordFirstSeen(context.Context, uuid.UUID, string) (bool, error) {
	return false, nil
}
func (f *fakeEngineStore) RecordPoll(context.Context, uuid.UUID) error { return nil }
func (f *fakeEngineStore) SetStatus(context.Context, uuid.UUID, string) error {
	return nil
}
func (f *fakeEngineStore) Revoke(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (f *fakeEngineStore) MarkStaleOffline(context.Context, time.Time) error  { return nil }
func (f *fakeEngineStore) ListAllCAs(context.Context) ([][]byte, error)       { return nil, nil }
func (f *fakeEngineStore) SetEncryptionPubkey(_ context.Context, id uuid.UUID, pk []byte) error {
	f.pubkeys[id] = append([]byte(nil), pk...)
	return nil
}
func (f *fakeEngineStore) GetEncryptionPubkey(_ context.Context, id uuid.UUID) ([]byte, error) {
	return f.pubkeys[id], nil
}

// --- fakeInventoryLister ----------------------------------------------------

type fakeInventory struct {
	hosts []hostmatch.HostSummary
	full  []inventory.Host
}

func (f *fakeInventory) ListHostSummaries(context.Context, uuid.UUID) ([]hostmatch.HostSummary, error) {
	return f.hosts, nil
}

func (f *fakeInventory) GetHostsByIDs(_ context.Context, _ uuid.UUID, ids []uuid.UUID) ([]inventory.Host, error) {
	set := map[uuid.UUID]struct{}{}
	for _, id := range ids {
		set[id] = struct{}{}
	}
	out := []inventory.Host{}
	for _, h := range f.full {
		if _, ok := set[h.ID]; ok {
			out = append(out, h)
		}
	}
	return out, nil
}

// --- helpers ----------------------------------------------------------------

func buildAdminRouter(h *AdminHandlers) http.Handler {
	r := chi.NewRouter()
	r.Route("/credentials", func(r chi.Router) {
		MountAdminRoutes(r, h)
	})
	return r
}

func buildGatewayRouter(h *GatewayHandlers, eng *engine.Engine) http.Handler {
	r := chi.NewRouter()
	r.Route("/credentials", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if eng != nil {
					ctx := engine.ContextWithEngine(req.Context(), eng)
					req = req.WithContext(ctx)
				}
				next.ServeHTTP(w, req)
			})
		})
		MountGatewayRoutes(r, h)
	})
	return r
}

func withClaims(r *http.Request, role, orgID string) *http.Request {
	claims := &auth.UserClaims{Sub: uuid.New().String(), Org: orgID, Role: role}
	return r.WithContext(server.ContextWithClaimsForTesting(r.Context(), claims))
}

// --- tests ------------------------------------------------------------------

func TestCreateProfile_EngineerSuccess(t *testing.T) {
	fs := newFakeStore()
	fes := newFakeEngineStore()
	orgID := uuid.Must(uuid.NewV7())
	engID := fes.seedEngine(orgID)
	fes.pubkeys[engID] = make([]byte, 32)

	h := NewAdminHandlers(fs, fes, &fakeInventory{}, nil)
	router := buildAdminRouter(h)

	body := createProfilePayload{
		Name: "prod-ssh", AuthType: AuthSSHPassword, EngineID: engID,
		Matcher:         Matcher{OS: "linux"},
		EncryptedSecret: base64.StdEncoding.EncodeToString(make([]byte, 80)),
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/credentials/", bytes.NewReader(buf))
	req = withClaims(req, server.RoleEngineer, orgID.String())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var got Profile
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "prod-ssh", got.Name)
	assert.Equal(t, engID, got.EngineID)
}

func TestCreateProfile_OfficerForbidden(t *testing.T) {
	fs := newFakeStore()
	fes := newFakeEngineStore()
	orgID := uuid.Must(uuid.NewV7())
	engID := fes.seedEngine(orgID)
	fes.pubkeys[engID] = make([]byte, 32)

	h := NewAdminHandlers(fs, fes, &fakeInventory{}, nil)
	router := buildAdminRouter(h)

	body := createProfilePayload{
		Name: "p", AuthType: AuthSSHPassword, EngineID: engID,
		EncryptedSecret: base64.StdEncoding.EncodeToString(make([]byte, 80)),
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/credentials/", bytes.NewReader(buf))
	req = withClaims(req, server.RoleOfficer, orgID.String())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateProfile_NoPubkeyConflict(t *testing.T) {
	fs := newFakeStore()
	fes := newFakeEngineStore()
	orgID := uuid.Must(uuid.NewV7())
	engID := fes.seedEngine(orgID) // no pubkey registered

	h := NewAdminHandlers(fs, fes, &fakeInventory{}, nil)
	router := buildAdminRouter(h)

	body := createProfilePayload{
		Name: "p", AuthType: AuthSSHPassword, EngineID: engID,
		EncryptedSecret: base64.StdEncoding.EncodeToString(make([]byte, 80)),
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/credentials/", bytes.NewReader(buf))
	req = withClaims(req, server.RoleEngineer, orgID.String())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestDeleteProfile_EngineerOK_OfficerForbidden(t *testing.T) {
	fs := newFakeStore()
	fes := newFakeEngineStore()
	orgID := uuid.Must(uuid.NewV7())
	engID := fes.seedEngine(orgID)
	fes.pubkeys[engID] = make([]byte, 32)

	// seed a profile directly
	pid := uuid.New()
	fs.profiles[pid] = Profile{ID: pid, OrgID: orgID, EngineID: engID, Name: "x",
		AuthType: AuthSSHPassword, SecretRef: uuid.New()}

	h := NewAdminHandlers(fs, fes, &fakeInventory{}, nil)
	router := buildAdminRouter(h)

	// officer → 403
	req := httptest.NewRequest(http.MethodDelete, "/credentials/"+pid.String(), nil)
	req = withClaims(req, server.RoleOfficer, orgID.String())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// engineer → 204
	req = httptest.NewRequest(http.MethodDelete, "/credentials/"+pid.String(), nil)
	req = withClaims(req, server.RoleEngineer, orgID.String())
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestStartTest_ResolvesAndCreatesJob(t *testing.T) {
	fs := newFakeStore()
	fes := newFakeEngineStore()
	orgID := uuid.Must(uuid.NewV7())
	engID := fes.seedEngine(orgID)
	fes.pubkeys[engID] = make([]byte, 32)

	// seed a profile that matches linux hosts
	pid := uuid.New()
	fs.profiles[pid] = Profile{ID: pid, OrgID: orgID, EngineID: engID,
		Name: "p", AuthType: AuthSSHPassword,
		Matcher: Matcher{OS: "linux"}, SecretRef: uuid.New()}

	inv := &fakeInventory{
		hosts: []hostmatch.HostSummary{
			{ID: uuid.New(), GroupID: uuid.New(), OS: "linux"},
			{ID: uuid.New(), GroupID: uuid.New(), OS: "windows"},
		},
	}

	h := NewAdminHandlers(fs, fes, inv, nil)
	router := buildAdminRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/credentials/"+pid.String()+"/test",
		bytes.NewBufferString(`{"max_hosts":5}`))
	req = withClaims(req, server.RoleEngineer, orgID.String())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var tj TestJob
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tj))
	assert.Len(t, tj.HostIDs, 1, "only the linux host matches")
}

func TestStartTest_ZeroHostsReturns400(t *testing.T) {
	fs := newFakeStore()
	fes := newFakeEngineStore()
	orgID := uuid.Must(uuid.NewV7())
	engID := fes.seedEngine(orgID)
	fes.pubkeys[engID] = make([]byte, 32)

	pid := uuid.New()
	fs.profiles[pid] = Profile{ID: pid, OrgID: orgID, EngineID: engID,
		Name: "p", AuthType: AuthSSHPassword,
		Matcher: Matcher{OS: "aix"}, SecretRef: uuid.New()}

	inv := &fakeInventory{
		hosts: []hostmatch.HostSummary{{ID: uuid.New(), OS: "linux"}},
	}

	h := NewAdminHandlers(fs, fes, inv, nil)
	router := buildAdminRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/credentials/"+pid.String()+"/test", nil)
	req = withClaims(req, server.RoleEngineer, orgID.String())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- gateway handler tests --------------------------------------------------

func TestPollDelivery_ReturnsQueued(t *testing.T) {
	fs := newFakeStore()
	orgID := uuid.Must(uuid.NewV7())
	engID := uuid.Must(uuid.NewV7())
	fs.deliveries = append(fs.deliveries, Delivery{
		ID: uuid.New(), OrgID: orgID, EngineID: engID,
		SecretRef: uuid.New(), AuthType: AuthSSHPassword,
		Kind: DeliveryPush, Ciphertext: []byte("ct"), Status: "queued",
	})

	gh := &GatewayHandlers{Store: fs, InventoryStore: &fakeInventory{}, PollTimeout: 100 * time.Millisecond, PollInterval: 10 * time.Millisecond}
	router := buildGatewayRouter(gh, &engine.Engine{ID: engID, OrgID: orgID})

	req := httptest.NewRequest(http.MethodGet, "/credentials/deliveries/poll", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got Delivery
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "claimed", got.Status)
}

func TestAckDelivery_TerminalReturns409(t *testing.T) {
	fs := newFakeStore()
	engID := uuid.Must(uuid.NewV7())
	d := Delivery{
		ID: uuid.New(), EngineID: engID, SecretRef: uuid.New(),
		AuthType: AuthSSHPassword, Kind: DeliveryPush, Status: "queued",
	}
	fs.deliveries = append(fs.deliveries, d)

	gh := NewGatewayHandlers(fs, &fakeInventory{})
	gh.PollTimeout = 50 * time.Millisecond
	gh.PollInterval = 10 * time.Millisecond
	router := buildGatewayRouter(gh, &engine.Engine{ID: engID})

	// First ack succeeds.
	req := httptest.NewRequest(http.MethodPost, "/credentials/deliveries/"+d.ID.String()+"/ack",
		bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)

	// Second ack → 409.
	req = httptest.NewRequest(http.MethodPost, "/credentials/deliveries/"+d.ID.String()+"/ack",
		bytes.NewBufferString(`{}`))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestPollTest_EnrichesHosts(t *testing.T) {
	fs := newFakeStore()
	orgID := uuid.Must(uuid.NewV7())
	engID := uuid.Must(uuid.NewV7())
	pid := uuid.New()
	secretRef := uuid.New()
	hostID := uuid.New()

	fs.profiles[pid] = Profile{
		ID: pid, OrgID: orgID, EngineID: engID,
		Name: "p", AuthType: AuthSSHPassword, SecretRef: secretRef,
	}
	tj := TestJob{
		ID: uuid.New(), OrgID: orgID, EngineID: engID, ProfileID: pid,
		HostIDs: []uuid.UUID{hostID}, Status: "queued",
	}
	fs.tests[tj.ID] = tj

	inv := &fakeInventory{
		full: []inventory.Host{{ID: hostID, OrgID: orgID, Hostname: "host-a"}},
	}

	gh := &GatewayHandlers{Store: fs, InventoryStore: inv, PollTimeout: 100 * time.Millisecond, PollInterval: 10 * time.Millisecond}
	router := buildGatewayRouter(gh, &engine.Engine{ID: engID, OrgID: orgID})

	req := httptest.NewRequest(http.MethodGet, "/credentials/tests/poll", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var payload TestJobPayload
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &payload))
	assert.Equal(t, secretRef, payload.SecretRef)
	require.Len(t, payload.Hosts, 1)
	assert.Equal(t, 22, payload.Hosts[0].Port, "ssh default port")
	assert.Equal(t, "host-a", payload.Hosts[0].Address)
}

func TestSubmitTest_InsertsAndFinishes(t *testing.T) {
	fs := newFakeStore()
	orgID := uuid.Must(uuid.NewV7())
	engID := uuid.Must(uuid.NewV7())
	tj := TestJob{
		ID: uuid.New(), OrgID: orgID, EngineID: engID,
		ProfileID: uuid.New(), Status: "claimed",
	}
	fs.tests[tj.ID] = tj

	gh := NewGatewayHandlers(fs, &fakeInventory{})
	gh.PollTimeout = 50 * time.Millisecond
	gh.PollInterval = 10 * time.Millisecond
	router := buildGatewayRouter(gh, &engine.Engine{ID: engID})

	body := submitResultsPayload{
		Results: []TestResult{{HostID: uuid.New(), Success: true, LatencyMs: 12}},
	}
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/credentials/tests/"+tj.ID.String()+"/submit", bytes.NewReader(buf))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	got := fs.tests[tj.ID]
	assert.Equal(t, "completed", got.Status)
	assert.Len(t, fs.results[tj.ID], 1)
	assert.Equal(t, tj.ID, fs.results[tj.ID][0].TestID, "handler must overwrite test_id from URL")
}

