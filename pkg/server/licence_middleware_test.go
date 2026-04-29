package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// licenceMockStore is a minimal store.Store stub for TenantLicenceGate
// unit tests. Only GetTenantLicence is implemented; all other methods
// panic to surface accidental calls during testing.
type licenceMockStore struct {
	// getTenantLicenceFn controls GetTenantLicence behaviour. When nil,
	// GetTenantLicence returns ErrNotFound.
	getTenantLicenceFn func(ctx context.Context, orgID string) (*store.TenantLicence, error)
}

func (m *licenceMockStore) GetTenantLicence(ctx context.Context, orgID string) (*store.TenantLicence, error) {
	if m.getTenantLicenceFn != nil {
		return m.getTenantLicenceFn(ctx, orgID)
	}
	return nil, &store.ErrNotFound{Resource: "tenant_licence", ID: orgID}
}

// --- store.Store methods not exercised by TenantLicenceGate ---
// Each panics so that accidental invocations are caught immediately.

func (m *licenceMockStore) SaveScan(_ context.Context, _ *model.ScanResult) error {
	panic("licenceMockStore: SaveScan not implemented")
}
func (m *licenceMockStore) GetScan(_ context.Context, _, _ string) (*model.ScanResult, error) {
	panic("licenceMockStore: GetScan not implemented")
}
func (m *licenceMockStore) ListScans(_ context.Context, _ store.ScanFilter) ([]store.ScanSummary, error) {
	panic("licenceMockStore: ListScans not implemented")
}
func (m *licenceMockStore) ListScansOrderedByTime(_ context.Context, _ string) ([]store.ScanSummary, error) {
	panic("licenceMockStore: ListScansOrderedByTime not implemented")
}
func (m *licenceMockStore) DeleteScan(_ context.Context, _, _ string) error {
	panic("licenceMockStore: DeleteScan not implemented")
}
func (m *licenceMockStore) GetFileHash(_ context.Context, _ string) (string, time.Time, error) {
	panic("licenceMockStore: GetFileHash not implemented")
}
func (m *licenceMockStore) SetFileHash(_ context.Context, _, _ string) error {
	panic("licenceMockStore: SetFileHash not implemented")
}
func (m *licenceMockStore) PruneStaleHashes(_ context.Context, _ time.Time) error {
	panic("licenceMockStore: PruneStaleHashes not implemented")
}
func (m *licenceMockStore) FileHashStats(_ context.Context) (int, time.Time, time.Time, error) {
	panic("licenceMockStore: FileHashStats not implemented")
}
func (m *licenceMockStore) CreateOrg(_ context.Context, _ *store.Organization) error {
	panic("licenceMockStore: CreateOrg not implemented")
}
func (m *licenceMockStore) GetOrg(_ context.Context, _ string) (*store.Organization, error) {
	panic("licenceMockStore: GetOrg not implemented")
}
func (m *licenceMockStore) ListOrgs(_ context.Context) ([]store.Organization, error) {
	panic("licenceMockStore: ListOrgs not implemented")
}
func (m *licenceMockStore) UpdateOrg(_ context.Context, _ *store.Organization) error {
	panic("licenceMockStore: UpdateOrg not implemented")
}
func (m *licenceMockStore) DeleteOrg(_ context.Context, _ string) error {
	panic("licenceMockStore: DeleteOrg not implemented")
}
func (m *licenceMockStore) CreateUser(_ context.Context, _ *store.User) error {
	panic("licenceMockStore: CreateUser not implemented")
}
func (m *licenceMockStore) GetUser(_ context.Context, _ string) (*store.User, error) {
	panic("licenceMockStore: GetUser not implemented")
}
func (m *licenceMockStore) GetUserByEmail(_ context.Context, _ string) (*store.User, error) {
	panic("licenceMockStore: GetUserByEmail not implemented")
}
func (m *licenceMockStore) ListUsers(_ context.Context, _ store.UserFilter) ([]store.User, error) {
	panic("licenceMockStore: ListUsers not implemented")
}
func (m *licenceMockStore) UpdateUser(_ context.Context, _ store.UserUpdate) error {
	panic("licenceMockStore: UpdateUser not implemented")
}
func (m *licenceMockStore) DeleteUser(_ context.Context, _ string) error {
	panic("licenceMockStore: DeleteUser not implemented")
}
func (m *licenceMockStore) CountUsersByOrg(_ context.Context, _ string) (int, error) {
	panic("licenceMockStore: CountUsersByOrg not implemented")
}
func (m *licenceMockStore) ResendInvite(_ context.Context, _, _ string) error {
	panic("licenceMockStore: ResendInvite not implemented")
}
func (m *licenceMockStore) CreateSession(_ context.Context, _ *store.Session) error {
	panic("licenceMockStore: CreateSession not implemented")
}
func (m *licenceMockStore) GetSessionByHash(_ context.Context, _ string) (*store.Session, error) {
	panic("licenceMockStore: GetSessionByHash not implemented")
}
func (m *licenceMockStore) DeleteSession(_ context.Context, _ string) error {
	panic("licenceMockStore: DeleteSession not implemented")
}
func (m *licenceMockStore) DeleteExpiredSessions(_ context.Context) error {
	panic("licenceMockStore: DeleteExpiredSessions not implemented")
}
func (m *licenceMockStore) WriteAudit(_ context.Context, _ *store.AuditEvent) error {
	panic("licenceMockStore: WriteAudit not implemented")
}
func (m *licenceMockStore) ListAudit(_ context.Context, _ store.AuditFilter) ([]store.AuditEvent, error) {
	panic("licenceMockStore: ListAudit not implemented")
}
func (m *licenceMockStore) UpsertAgent(_ context.Context, _ *store.AgentRecord) error {
	panic("licenceMockStore: UpsertAgent not implemented")
}
func (m *licenceMockStore) GetAgent(_ context.Context, _, _ string) (*store.AgentRecord, error) {
	panic("licenceMockStore: GetAgent not implemented")
}
func (m *licenceMockStore) ListAgentsByTenant(_ context.Context, _ string, _ int) ([]store.AgentRecord, error) {
	panic("licenceMockStore: ListAgentsByTenant not implemented")
}
func (m *licenceMockStore) SetAgentPausedUntil(_ context.Context, _, _ string, _ time.Time) error {
	panic("licenceMockStore: SetAgentPausedUntil not implemented")
}
func (m *licenceMockStore) ClearAgentPausedUntil(_ context.Context, _, _ string) error {
	panic("licenceMockStore: ClearAgentPausedUntil not implemented")
}
func (m *licenceMockStore) EnqueueAgentCommand(_ context.Context, _ *store.AgentCommand) (*store.AgentCommand, error) {
	panic("licenceMockStore: EnqueueAgentCommand not implemented")
}
func (m *licenceMockStore) ClaimPendingCommandsForAgent(_ context.Context, _, _ string) ([]store.AgentCommand, error) {
	panic("licenceMockStore: ClaimPendingCommandsForAgent not implemented")
}
func (m *licenceMockStore) SetAgentCommandResult(_ context.Context, _, _, _, _ string, _ json.RawMessage) error {
	panic("licenceMockStore: SetAgentCommandResult not implemented")
}
func (m *licenceMockStore) ListAgentCommands(_ context.Context, _, _ string, _ int) ([]store.AgentCommand, error) {
	panic("licenceMockStore: ListAgentCommands not implemented")
}
func (m *licenceMockStore) ExpireStaleAgentCommands(_ context.Context) (int, error) {
	panic("licenceMockStore: ExpireStaleAgentCommands not implemented")
}
func (m *licenceMockStore) GetOrCreateInstance(_ context.Context) (*store.ReportInstance, error) {
	panic("licenceMockStore: GetOrCreateInstance not implemented")
}
func (m *licenceMockStore) UpsertTenantLicence(_ context.Context, _ *store.TenantLicence) error {
	panic("licenceMockStore: UpsertTenantLicence not implemented")
}
func (m *licenceMockStore) ListTenantLicences(_ context.Context) ([]store.TenantLicence, error) {
	panic("licenceMockStore: ListTenantLicences not implemented")
}
func (m *licenceMockStore) DeleteTenantLicence(_ context.Context, _ string) error {
	panic("licenceMockStore: DeleteTenantLicence not implemented")
}
func (m *licenceMockStore) SaveScanWithFindings(_ context.Context, _ *model.ScanResult, _ []store.Finding) error {
	panic("licenceMockStore: SaveScanWithFindings not implemented")
}
func (m *licenceMockStore) ListInventory(_ context.Context, _ string, _ store.FilterParams) ([]store.InventoryRow, error) {
	panic("licenceMockStore: ListInventory not implemented")
}
func (m *licenceMockStore) ListExpiringCertificates(_ context.Context, _ string, _ time.Duration, _ store.FilterParams) ([]store.ExpiringCertRow, error) {
	panic("licenceMockStore: ListExpiringCertificates not implemented")
}
func (m *licenceMockStore) ListTopPriorityFindings(_ context.Context, _ string, _ int, _ store.FilterParams) ([]store.PriorityRow, error) {
	panic("licenceMockStore: ListTopPriorityFindings not implemented")
}
func (m *licenceMockStore) ListFilterOptions(_ context.Context, _ string) (store.FilterOptions, error) {
	panic("licenceMockStore: ListFilterOptions not implemented")
}
func (m *licenceMockStore) RefreshHostSummary(_ context.Context, _, _ string) error {
	panic("licenceMockStore: RefreshHostSummary not implemented")
}
func (m *licenceMockStore) RefreshOrgSnapshot(_ context.Context, _ string) error {
	panic("licenceMockStore: RefreshOrgSnapshot not implemented")
}
func (m *licenceMockStore) ListHostSummaries(_ context.Context, _, _ string) ([]store.HostSummary, error) {
	panic("licenceMockStore: ListHostSummaries not implemented")
}
func (m *licenceMockStore) GetOrgSnapshot(_ context.Context, _ string) (*store.OrgSnapshot, error) {
	panic("licenceMockStore: GetOrgSnapshot not implemented")
}
func (m *licenceMockStore) ListStaleHosts(_ context.Context) ([]store.PipelineJob, error) {
	panic("licenceMockStore: ListStaleHosts not implemented")
}
func (m *licenceMockStore) SetFindingStatus(_ context.Context, _ *store.FindingStatusEntry) error {
	panic("licenceMockStore: SetFindingStatus not implemented")
}
func (m *licenceMockStore) GetFindingHistory(_ context.Context, _, _ string) ([]store.FindingStatusEntry, error) {
	panic("licenceMockStore: GetFindingHistory not implemented")
}
func (m *licenceMockStore) GetRemediationSummary(_ context.Context, _ string) (*store.RemediationSummary, error) {
	panic("licenceMockStore: GetRemediationSummary not implemented")
}
func (m *licenceMockStore) ListRemediationFindings(_ context.Context, _, _, _, _ string) ([]store.RemediationRow, error) {
	panic("licenceMockStore: ListRemediationFindings not implemented")
}
func (m *licenceMockStore) GetFindingByID(_ context.Context, _, _ string) (*store.Finding, error) {
	panic("licenceMockStore: GetFindingByID not implemented")
}
func (m *licenceMockStore) ListFindingStatusLog(_ context.Context, _ string, _ int) ([]store.FindingStatusEntry, error) {
	panic("licenceMockStore: ListFindingStatusLog not implemented")
}
func (m *licenceMockStore) GetOnboardingMetrics(_ context.Context, _ string) (*store.OnboardingMetrics, error) {
	panic("licenceMockStore: GetOnboardingMetrics not implemented")
}
func (m *licenceMockStore) GetNacsaSummary(_ context.Context, _ string, _ store.NacsaScopeFilter) (store.NacsaSummary, error) {
	panic("licenceMockStore: GetNacsaSummary not implemented")
}
func (m *licenceMockStore) ListNacsaServers(_ context.Context, _ string) ([]store.NacsaServerRow, error) {
	panic("licenceMockStore: ListNacsaServers not implemented")
}
func (m *licenceMockStore) ListNacsaHosts(_ context.Context, _, _ string) ([]store.NacsaHostRow, error) {
	panic("licenceMockStore: ListNacsaHosts not implemented")
}
func (m *licenceMockStore) ListNacsaCBOM(_ context.Context, _, _ string, _ []string) ([]store.NacsaCBOMRow, error) {
	panic("licenceMockStore: ListNacsaCBOM not implemented")
}
func (m *licenceMockStore) ListNacsaRisk(_ context.Context, _, _, _ string) ([]store.NacsaRiskRow, error) {
	panic("licenceMockStore: ListNacsaRisk not implemented")
}
func (m *licenceMockStore) GetNacsaMigration(_ context.Context, _ string) (store.NacsaMigResponse, error) {
	panic("licenceMockStore: GetNacsaMigration not implemented")
}
func (m *licenceMockStore) Close() error { return nil }

// newServerWithMockStore builds a minimal *Server wired to the given store stub.
// No auth, no session cache, no licence guard — only the store field is populated,
// which is all TenantLicenceGate needs.
func newServerWithMockStore(t *testing.T, ms store.Store) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &Server{
		config:               &Config{},
		store:                ms,
		auditSem:             make(chan struct{}, 1),
		licenceValidatorDone: make(chan struct{}),
		ctx:                  ctx,
		cancel:               cancel,
	}
	return srv
}

// withOrgID injects an org ID into the request context using the same
// key that UnifiedAuth uses, so TenantFromContext sees it.
func withOrgID(r *http.Request, orgID string) *http.Request {
	tc := &TenantContext{OrgID: orgID}
	ctx := context.WithValue(r.Context(), tenantContextKey, tc)
	return r.WithContext(ctx)
}

// --- Tests ---

func TestTenantLicenceGate_AllowsActive(t *testing.T) {
	ms := &licenceMockStore{
		getTenantLicenceFn: func(_ context.Context, _ string) (*store.TenantLicence, error) {
			return &store.TenantLicence{
				OrgID:     "org-1",
				LicenceID: "lic-1",
				Status:    "active",
				ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
			}, nil
		},
	}
	srv := newServerWithMockStore(t, ms)
	h := srv.TenantLicenceGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = withOrgID(req, "org-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("X-Licence-Grace"))
}

func TestTenantLicenceGate_BlocksExpired(t *testing.T) {
	ms := &licenceMockStore{
		getTenantLicenceFn: func(_ context.Context, _ string) (*store.TenantLicence, error) {
			return &store.TenantLicence{
				OrgID:     "org-2",
				LicenceID: "lic-2",
				Status:    "expired",
				ExpiresAt: time.Now().Add(-60 * 24 * time.Hour),
			}, nil
		},
	}
	srv := newServerWithMockStore(t, ms)
	h := srv.TenantLicenceGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler must not be called for expired licence")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = withOrgID(req, "org-2")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "licence expired", body["error"])
}

func TestTenantLicenceGate_AddsGraceHeader(t *testing.T) {
	ms := &licenceMockStore{
		getTenantLicenceFn: func(_ context.Context, _ string) (*store.TenantLicence, error) {
			return &store.TenantLicence{
				OrgID:     "org-3",
				LicenceID: "lic-3",
				Status:    "grace",
				ExpiresAt: time.Now().Add(-5 * 24 * time.Hour),
			}, nil
		},
	}
	srv := newServerWithMockStore(t, ms)
	h := srv.TenantLicenceGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = withOrgID(req, "org-3")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "true", rec.Header().Get("X-Licence-Grace"))
}

func TestTenantLicenceGate_AllowsMissingRow(t *testing.T) {
	// Default getTenantLicenceFn is nil → ErrNotFound.
	ms := &licenceMockStore{}
	srv := newServerWithMockStore(t, ms)
	h := srv.TenantLicenceGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = withOrgID(req, "org-4")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTenantLicenceGate_AllowsNilTenant(t *testing.T) {
	// No org ID in context — middleware must pass through without touching the store.
	ms := &licenceMockStore{
		getTenantLicenceFn: func(_ context.Context, _ string) (*store.TenantLicence, error) {
			panic("licenceMockStore: GetTenantLicence must not be called when org ID is empty")
		},
	}
	srv := newServerWithMockStore(t, ms)
	h := srv.TenantLicenceGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request with no tenant context.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTenantLicenceGate_FailsOpenOnDBError(t *testing.T) {
	// Store returns a generic error (not ErrNotFound) — middleware must fail open
	// with HTTP 200 and no X-Licence-Grace header.
	ms := &licenceMockStore{
		getTenantLicenceFn: func(_ context.Context, _ string) (*store.TenantLicence, error) {
			return nil, fmt.Errorf("connection reset")
		},
	}
	srv := newServerWithMockStore(t, ms)
	h := srv.TenantLicenceGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = withOrgID(req, "org-5")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("X-Licence-Grace"))
}
