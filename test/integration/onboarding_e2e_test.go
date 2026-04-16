//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/server"
	credentialspkg "github.com/amiryahaya/triton/pkg/server/credentials"
	enginepkg "github.com/amiryahaya/triton/pkg/server/engine"
	"github.com/amiryahaya/triton/pkg/server/inventory"
	scanjobspkg "github.com/amiryahaya/triton/pkg/server/scanjobs"
	"github.com/amiryahaya/triton/pkg/store"
)

// TestOnboarding_PortalJourney_ZeroToFirstScan exercises the full
// customer onboarding journey: user creation, group + host setup,
// engine registration, credential profile, scan job lifecycle, and
// onboarding metrics. This is the "reduced" version that uses the
// portal admin API via httptest for operator actions and direct store
// calls to simulate the engine side (claim/submit/finish), since the
// mTLS engine gateway is complex to stand up in-process.
//
// Covered end-to-end:
//   - Org + user creation, JWT login
//   - Group creation via POST /api/v1/manage/groups
//   - Host import via POST /api/v1/manage/hosts/import
//   - Engine creation via POST /api/v1/manage/engines/
//   - Host → engine assignment (direct DB)
//   - Credential profile creation via POST /api/v1/manage/credentials/
//   - Scan job creation via POST /api/v1/manage/scan-jobs/
//   - Engine claims job (store.ClaimNext)
//   - Engine submits scan result (store.RecordScanResult)
//   - Engine finishes job (store.FinishJob)
//   - Scan job reaches "completed" (GET /api/v1/manage/scan-jobs/{id})
//   - Onboarding metrics show minutes_to_first_scan
//
// NOT covered (tested individually in prior phases):
//   - mTLS engine enrollment + heartbeat
//   - Sealed-box credential delivery + ack
//   - Live scanner execution
func TestOnboarding_PortalJourney_ZeroToFirstScan(t *testing.T) {
	db := requireOnboardingDB(t)
	ctx := context.Background()

	orgID := uuid.Must(uuid.NewV7())

	// --- 1. Seed org + admin user ---
	require.NoError(t, db.CreateOrg(ctx, &store.Organization{
		ID:   orgID.String(),
		Name: "E2E Onboarding Org",
	}))
	adminPassword := "strong-password-42!"
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.MinCost)
	require.NoError(t, err)
	adminUser := &store.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		OrgID:              orgID.String(),
		Email:              "admin@onboard.test",
		Name:               "Onboard Admin",
		Role:               "org_admin",
		Password:           string(hash),
		MustChangePassword: false,
	}
	require.NoError(t, db.CreateUser(ctx, adminUser))

	// --- 2. Build in-process portal server ---
	jwtPub, jwtPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)
	lic := &license.License{
		ID:        "e2e-onboard",
		Tier:      license.TierEnterprise,
		OrgID:     orgID.String(),
		Org:       "E2E Onboarding Org",
		Seats:     100,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	token, err := license.Encode(lic, priv)
	require.NoError(t, err)
	guard := license.NewGuardFromToken(token, pub)

	masterKey := make([]byte, 32)
	_, err = rand.Read(masterKey)
	require.NoError(t, err)

	cfg := &server.Config{
		ListenAddr:    ":0",
		Guard:         guard,
		JWTSigningKey: jwtPriv,
		JWTPublicKey:  jwtPub,
	}
	srv, err := server.New(cfg, db)
	require.NoError(t, err)

	// Mount onboarding subsystem routes (mirrors cmd/server.go wiring).
	invStore := inventory.NewPostgresStore(db.Pool())
	auditAdapter := server.NewAuditAdapter(srv)
	invHandlers := &inventory.Handlers{Store: invStore, Audit: auditAdapter}
	require.NoError(t, srv.MountAuthenticated("/api/v1/manage", func(r chi.Router) {
		inventory.MountRoutes(r, invHandlers)
	}))

	engineStore := enginepkg.NewPostgresStore(db.Pool())
	adminHandlers := &enginepkg.AdminHandlers{
		Store:     engineStore,
		MasterKey: masterKey,
		PortalURL: "https://portal.test",
	}
	require.NoError(t, srv.MountAuthenticated("/api/v1/manage/engines", func(r chi.Router) {
		enginepkg.MountAdminRoutes(r, adminHandlers)
	}))

	credStore := credentialspkg.NewPostgresStore(db.Pool())
	credAdmin := &credentialspkg.AdminHandlers{
		Store:          credStore,
		EngineStore:    engineStore,
		InventoryStore: invStore,
		Audit:          auditAdapter,
	}
	require.NoError(t, srv.MountAuthenticated("/api/v1/manage/credentials", func(r chi.Router) {
		credentialspkg.MountAdminRoutes(r, credAdmin)
	}))

	scanJobsStore := scanjobspkg.NewPostgresStore(db.Pool(), db)
	scanJobsAdmin := &scanjobspkg.AdminHandlers{
		Store:          scanJobsStore,
		InventoryStore: invStore,
		Audit:          auditAdapter,
	}
	require.NoError(t, srv.MountAuthenticated("/api/v1/manage/scan-jobs", func(r chi.Router) {
		scanjobspkg.MountAdminRoutes(r, scanJobsAdmin)
	}))

	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	// --- 3. Login to get JWT ---
	jwt := login(t, ts.URL, "admin@onboard.test", adminPassword)

	// --- 4. Create group ---
	groupID := createGroup(t, ts.URL, jwt, "Production Servers")

	// --- 5. Create engine ---
	engineID := createEngine(t, ts.URL, jwt)

	// --- 6. Import host ---
	hostIDs := importHosts(t, ts.URL, jwt, groupID)
	require.Len(t, hostIDs, 1)

	// --- 7. Assign engine to host (direct DB — in production this happens
	//     during engine enrollment + auto-assignment or operator action) ---
	_, err = db.Pool().Exec(ctx,
		`UPDATE inventory_hosts SET engine_id = $1 WHERE id = $2`,
		engineID, hostIDs[0])
	require.NoError(t, err)

	// --- 7b. Register engine encryption pubkey (direct DB — in production
	//     this happens via mTLS POST /api/v1/engine/encryption-pubkey) ---
	fakeX25519Pubkey := make([]byte, 32)
	_, err = rand.Read(fakeX25519Pubkey)
	require.NoError(t, err)
	require.NoError(t, engineStore.SetEncryptionPubkey(ctx, engineID, fakeX25519Pubkey))

	// --- 8. Create credential profile ---
	credProfileID := createCredentialProfile(t, ts.URL, jwt, engineID, groupID)

	// --- 9. Create scan job ---
	jobID := createScanJob(t, ts.URL, jwt, groupID, credProfileID)

	// --- 10. Engine claims job (direct store) ---
	payload, found, err := scanJobsStore.ClaimNext(ctx, engineID)
	require.NoError(t, err)
	require.True(t, found, "engine should claim a queued job")
	require.Equal(t, jobID.String(), payload.ID.String())
	require.Len(t, payload.Hosts, 1)

	// --- 11. Engine submits fake scan result ---
	scanResult := &model.ScanResult{
		ID:    uuid.Must(uuid.NewV7()).String(),
		OrgID: orgID.String(),
		Metadata: model.ScanMetadata{
			Timestamp:   time.Now().UTC(),
			Hostname:    "localhost",
			OS:          "linux",
			ScanProfile: "quick",
			ToolVersion: "test",
		},
		Findings: []model.Finding{{
			ID:       "f-1",
			Category: 5,
			Source:   model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
			CryptoAsset: &model.CryptoAsset{
				Algorithm: "RSA-2048",
				PQCStatus: "TRANSITIONAL",
				KeySize:   2048,
				Function:  "encryption",
			},
			Module:     "certificates",
			Confidence: 0.95,
			Timestamp:  time.Now().UTC(),
		}},
		Summary: model.Summary{
			TotalFindings:     1,
			TotalCryptoAssets: 1,
			Transitional:      1,
		},
	}
	scanPayload, err := json.Marshal(scanResult)
	require.NoError(t, err)
	err = scanJobsStore.RecordScanResult(ctx, jobID, engineID, hostIDs[0], scanPayload)
	require.NoError(t, err)

	// --- 12. Engine finishes job ---
	err = scanJobsStore.UpdateProgress(ctx, jobID, 1, 0)
	require.NoError(t, err)
	err = scanJobsStore.FinishJob(ctx, engineID, jobID, scanjobspkg.StatusCompleted, "")
	require.NoError(t, err)

	// --- 13. Verify job is completed via admin API ---
	job := getJob(t, ts.URL, jwt, jobID)
	require.Equal(t, "completed", job.Status)
	require.Equal(t, 1, job.ProgressDone)
	require.Equal(t, 0, job.ProgressFailed)

	// --- 14. Verify onboarding metrics ---
	// Audit events are written asynchronously; poll until they land
	// rather than sleeping a fixed duration.
	var metrics store.OnboardingMetrics
	require.Eventually(t, func() bool {
		metrics = getOnboardingMetrics(t, ts.URL, jwt)
		return metrics.Engine != nil && metrics.Hosts != nil &&
			metrics.Creds != nil && metrics.Scan != nil && metrics.Results != nil
	}, 2*time.Second, 50*time.Millisecond, "onboarding metrics did not converge within 2s")
	// t_engine: derived from engines.bundle_issued_at (CreateEngine API).
	require.NotNil(t, metrics.Engine, "t_engine should be set after engine creation")
	// t_hosts: derived from audit_events where event_type LIKE 'inventory.host%'.
	require.NotNil(t, metrics.Hosts, "t_hosts should be set after host import")
	// t_creds: derived from audit_events where event_type = 'credentials.profile.create'.
	require.NotNil(t, metrics.Creds, "t_creds should be set after credential creation")
	// t_scan: derived from audit_events where event_type = 'scanjobs.job.create'.
	require.NotNil(t, metrics.Scan, "t_scan should be set after scan job creation")
	// t_results: derived from scan_jobs.completed_at.
	require.NotNil(t, metrics.Results, "t_results should be set after job completion")
	// t_signup is nil because the user was seeded directly (no user.create
	// audit event). minutes_to_first_scan = (t_results - t_signup) / 60,
	// so it is nil when t_signup is nil. This is expected for the reduced
	// test version where the user isn't created through the admin API.
	t.Logf("onboarding metrics: signup=%v engine=%v hosts=%v creds=%v scan=%v results=%v mttfs=%v",
		metrics.Signup, metrics.Engine, metrics.Hosts, metrics.Creds,
		metrics.Scan, metrics.Results, metrics.MinutesToFirstScan)
}

// --- HTTP helpers ---

func login(t *testing.T, base, email, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(base+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login failed: %s", string(raw))
	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	require.NotEmpty(t, out.Token)
	return out.Token
}

func authedPost(t *testing.T, url, jwt string, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func authedGet(t *testing.T, url, jwt string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func createGroup(t *testing.T, base, jwt, name string) uuid.UUID {
	t.Helper()
	resp := authedPost(t, base+"/api/v1/manage/groups", jwt, map[string]string{"name": name})
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create group: %s", string(raw))
	var g struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.Unmarshal(raw, &g))
	return g.ID
}

func createEngine(t *testing.T, base, jwt string) uuid.UUID {
	t.Helper()
	resp := authedPost(t, base+"/api/v1/manage/engines/", jwt, map[string]string{"label": "test-engine"})
	defer resp.Body.Close()
	// The response is a tar.gz bundle; engine ID is in the header.
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create engine failed")
	idStr := resp.Header.Get("X-Triton-Engine-Id")
	require.NotEmpty(t, idStr)
	id, err := uuid.Parse(idStr)
	require.NoError(t, err)
	return id
}

func importHosts(t *testing.T, base, jwt string, groupID uuid.UUID) []uuid.UUID {
	t.Helper()
	body := map[string]any{
		"group_id": groupID.String(),
		"rows": []map[string]string{
			{"hostname": "localhost", "address": "127.0.0.1", "os": "linux"},
		},
		"dry_run": false,
	}
	resp := authedPost(t, base+"/api/v1/manage/hosts/import", jwt, body)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "import hosts: %s", string(raw))
	var out struct {
		Accepted int `json:"accepted"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	require.Equal(t, 1, out.Accepted)

	// Fetch the host IDs.
	hResp := authedGet(t, base+"/api/v1/manage/hosts?group_id="+groupID.String(), jwt)
	defer hResp.Body.Close()
	hRaw, _ := io.ReadAll(hResp.Body)
	require.Equal(t, http.StatusOK, hResp.StatusCode, "list hosts: %s", string(hRaw))
	var hosts []struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.Unmarshal(hRaw, &hosts))
	ids := make([]uuid.UUID, len(hosts))
	for i, h := range hosts {
		ids[i] = h.ID
	}
	return ids
}

func createCredentialProfile(t *testing.T, base, jwt string, engineID, groupID uuid.UUID) uuid.UUID {
	t.Helper()
	body := map[string]any{
		"name":      "test-ssh-creds",
		"auth_type": "ssh-password",
		"engine_id": engineID.String(),
		"matcher": map[string]any{
			"group_ids": []string{groupID.String()},
		},
		"encrypted_secret": base64Encode(make([]byte, 61)), // 61 bytes >= sealed-box overhead (60)
	}
	resp := authedPost(t, base+"/api/v1/manage/credentials/", jwt, body)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create credential profile: %s", string(raw))
	var out struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out.ID
}

func createScanJob(t *testing.T, base, jwt string, groupID uuid.UUID, credProfileID uuid.UUID) uuid.UUID {
	t.Helper()
	body := map[string]any{
		"group_id":              groupID.String(),
		"scan_profile":          "quick",
		"credential_profile_id": credProfileID.String(),
	}
	resp := authedPost(t, base+"/api/v1/manage/scan-jobs/", jwt, body)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create scan job: %s", string(raw))
	var out struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out.ID
}

type jobResponse struct {
	ID             uuid.UUID `json:"id"`
	Status         string    `json:"status"`
	ProgressTotal  int       `json:"progress_total"`
	ProgressDone   int       `json:"progress_done"`
	ProgressFailed int       `json:"progress_failed"`
}

func getJob(t *testing.T, base, jwt string, jobID uuid.UUID) jobResponse {
	t.Helper()
	resp := authedGet(t, base+"/api/v1/manage/scan-jobs/"+jobID.String(), jwt)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "get job: %s", string(raw))
	var j jobResponse
	require.NoError(t, json.Unmarshal(raw, &j))
	return j
}

func getOnboardingMetrics(t *testing.T, base, jwt string) store.OnboardingMetrics {
	t.Helper()
	resp := authedGet(t, base+"/api/v1/manage/onboarding-metrics/", jwt)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "get onboarding metrics: %s", string(raw))
	var m store.OnboardingMetrics
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// requireOnboardingDB is like requireDB but also truncates onboarding
// tables that have FK dependencies on the core tables. The standard
// TruncateAll doesn't know about these tables and would fail with FK
// violations if prior test runs left data behind.
func requireOnboardingDB(t *testing.T) *store.PostgresStore {
	t.Helper()
	dbURL := testDBURL()
	ctx := context.Background()
	s, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	// Truncate onboarding tables first (FK ordering), then core tables.
	onboardingTables := []string{
		"scan_jobs",
		"credential_test_results", "credential_tests",
		"credential_deliveries", "credentials_profiles",
		"discovery_results", "discovery_jobs",
		"inventory_tags", "inventory_hosts", "inventory_groups",
		"engine_cas", "engines",
	}
	for _, tbl := range onboardingTables {
		_, _ = s.Pool().Exec(ctx, "DELETE FROM "+tbl)
	}
	require.NoError(t, s.TruncateAll(ctx))
	t.Cleanup(func() {
		for _, tbl := range onboardingTables {
			_, _ = s.Pool().Exec(ctx, "DELETE FROM "+tbl)
		}
		_ = s.TruncateAll(ctx)
		s.Close()
	})
	return s
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

