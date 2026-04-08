//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// testUUID returns a deterministic UUID string for use in tests.
// e.g., testUUID(1) => "00000000-0000-0000-0000-000000000001"
func testUUID(n int) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", n)
}

// zeroUUID is a nil UUID for "not found" test cases.
const zeroUUID = "00000000-0000-0000-0000-000000000000"

// testGuardForOrg builds a *license.Guard backed by a freshly-issued
// license token bound to the given orgID. Used by testServer to give
// every test handler a non-empty TenantContext via the Guard fallback
// path of UnifiedAuth, so RequireTenant doesn't reject unauthenticated
// test requests.
func testGuardForOrg(t *testing.T, orgID string) *license.Guard {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	lic := &license.License{
		ID:        "test-license",
		Tier:      license.TierEnterprise,
		OrgID:     orgID,
		Org:       "test-org",
		Seats:     100,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token, err := license.Encode(lic, priv)
	require.NoError(t, err)
	return license.NewGuardFromToken(token, pub)
}

func testServer(t *testing.T) (*Server, *store.PostgresStore) {
	t.Helper()
	dbUrl := os.Getenv("TRITON_TEST_DB_URL")
	if dbUrl == "" {
		dbUrl = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	db, err := store.NewPostgresStore(ctx, dbUrl)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	// Truncate at start to handle stale data from parallel package tests
	require.NoError(t, db.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = db.TruncateAll(ctx)
		db.Close()
	})

	cfg := &Config{
		ListenAddr: ":0",
		// Install a test Guard with testOrgID so RequireTenant on /api/v1
		// is satisfied via the Guard fallback path. testScanResult also
		// stamps OrgID = testOrgID, so seeded scans are visible through
		// the test server's tenant filter.
		Guard: testGuardForOrg(t, testOrgID),
	}
	srv, err := New(cfg, db)
	require.NoError(t, err)
	return srv, db
}

// testServerWithServiceKey builds a server configured for service-to-service
// auth (used by the license server → report server provisioning endpoint).
// Returns the server, store, and the configured service key.
func testServerWithServiceKey(t *testing.T) (*Server, *store.PostgresStore, string) {
	t.Helper()
	dbUrl := os.Getenv("TRITON_TEST_DB_URL")
	if dbUrl == "" {
		dbUrl = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	db, err := store.NewPostgresStore(ctx, dbUrl)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	require.NoError(t, db.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = db.TruncateAll(ctx)
		db.Close()
	})

	const serviceKey = "test-service-key-shared-secret"
	cfg := &Config{
		ListenAddr: ":0",
		ServiceKey: serviceKey,
	}
	srv, err := New(cfg, db)
	require.NoError(t, err)
	return srv, db, serviceKey
}

// testServerWithJWT builds a server configured for user JWT auth (login,
// logout, refresh, change-password). Generates a fresh Ed25519 keypair
// per test for isolation.
func testServerWithJWT(t *testing.T) (*Server, *store.PostgresStore) {
	t.Helper()
	dbUrl := os.Getenv("TRITON_TEST_DB_URL")
	if dbUrl == "" {
		dbUrl = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	db, err := store.NewPostgresStore(ctx, dbUrl)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	require.NoError(t, db.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = db.TruncateAll(ctx)
		db.Close()
	})

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cfg := &Config{
		ListenAddr:    ":0",
		JWTSigningKey: priv,
		JWTPublicKey:  pub,
	}
	srv, err := New(cfg, db)
	require.NoError(t, err)
	return srv, db
}

// createTestUserInOrg adds a user to an EXISTING org. Use when a test
// needs multiple users in the same org (e.g., peer-admin scenarios).
// For a fresh-org-plus-user, use createOrgUser instead.
func createTestUserInOrg(t *testing.T, db *store.PostgresStore, orgID, role, password string, mcp bool) (*store.Organization, *store.User) {
	t.Helper()
	ctx := context.Background()
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	user := &store.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		OrgID:              orgID,
		Email:              uuid.Must(uuid.NewV7()).String() + "@auth.test",
		Name:               "Auth Test User",
		Role:               role,
		Password:           string(hashed),
		MustChangePassword: mcp,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	require.NoError(t, db.CreateUser(ctx, user))
	org, err := db.GetOrg(ctx, orgID)
	require.NoError(t, err)
	return org, user
}

// createOrgUser inserts a user directly into the store for auth tests.
// Bypasses the provisioning endpoint to keep auth tests independent.
func createOrgUser(t *testing.T, db *store.PostgresStore, role, password string, mcp bool) (*store.Organization, *store.User) {
	t.Helper()
	ctx := context.Background()

	org := &store.Organization{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Name:      "Auth Test Org " + uuid.Must(uuid.NewV7()).String()[:8],
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, db.CreateOrg(ctx, org))

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &store.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		OrgID:              org.ID,
		Email:              uuid.Must(uuid.NewV7()).String() + "@auth.test",
		Name:               "Auth Test User",
		Role:               role,
		Password:           string(hashed),
		MustChangePassword: mcp,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	require.NoError(t, db.CreateUser(ctx, user))
	return org, user
}

// testOrgID is the default tenant org ID stamped onto scans seeded
// directly via the store and into the test server's Guard. Tests that
// need a different org should override OrgID after calling
// testScanResult and configure their own server.
const testOrgID = "00000000-0000-0000-0000-000000000abc"

func testScanResult(id, hostname string) *model.ScanResult {
	return &model.ScanResult{
		ID:    id,
		OrgID: testOrgID,
		Metadata: model.ScanMetadata{
			Timestamp:   time.Now().UTC().Truncate(time.Microsecond),
			Hostname:    hostname,
			ScanProfile: "quick",
			ToolVersion: "2.0.0-test",
		},
		Findings: []model.Finding{
			{
				ID:     "f1",
				Source: model.FindingSource{Type: "file", Path: "/test"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "RSA-2048",
					PQCStatus: "TRANSITIONAL",
				},
				Module: "certificates",
			},
		},
		Summary: model.Summary{
			TotalFindings: 1,
			Transitional:  1,
		},
	}
}

// --- Health ---

func TestHealth(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/health", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

// --- Auth ---

// API key auth was removed in Phase 4. Agents now authenticate via
// license tokens (X-Triton-License-Token), and human users via JWT
// (Authorization: Bearer). See tenant_context_test.go for the
// UnifiedAuth coverage that replaces TestAuth_*.

func TestHealth_NoAuthRequired(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/health", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Scan CRUD ---

func TestSubmitScan(t *testing.T) {
	srv, _ := testServer(t)
	id := testUUID(1)
	scan := testScanResult(id, "host-a")
	body, _ := json.Marshal(scan)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), id)
}

func TestSubmitScan_InvalidJSON(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader([]byte("invalid")))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSubmitScan_MissingID(t *testing.T) {
	srv, _ := testServer(t)
	scan := &model.ScanResult{}
	body, _ := json.Marshal(scan)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetScan(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	scan := testScanResult(id, "host-a")
	require.NoError(t, db.SaveScan(context.Background(), scan))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/"+id, nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var got model.ScanResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, id, got.ID)
}

func TestGetScan_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/"+zeroUUID, nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListScans(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(1), "host-a")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(2), "host-b")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var summaries []store.ScanSummary
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &summaries))
	assert.Len(t, summaries, 2)
}

func TestListScans_FilterHostname(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(1), "host-a")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(2), "host-b")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans?hostname=host-a", nil)
	srv.Router().ServeHTTP(w, r)

	var summaries []store.ScanSummary
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &summaries))
	assert.Len(t, summaries, 1)
}

func TestDeleteScan(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/scans/"+id, nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify deleted
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/v1/scans/"+id, nil)
	srv.Router().ServeHTTP(w2, r2)
	assert.Equal(t, http.StatusNotFound, w2.Code)
}

// --- Findings ---

func TestGetFindings(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/"+id+"/findings", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var findings []model.Finding
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &findings))
	assert.Len(t, findings, 1)
}

func TestGetFindings_FilterPQCStatus(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	scan := testScanResult(id, "host-a")
	scan.Findings = append(scan.Findings, model.Finding{
		ID:     "f2",
		Source: model.FindingSource{Type: "file", Path: "/safe"},
		CryptoAsset: &model.CryptoAsset{
			Algorithm: "AES-256",
			PQCStatus: "SAFE",
		},
		Module: "libraries",
	})
	require.NoError(t, db.SaveScan(context.Background(), scan))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/"+id+"/findings?pqc_status=SAFE", nil)
	srv.Router().ServeHTTP(w, r)

	var findings []model.Finding
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &findings))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SAFE", findings[0].CryptoAsset.PQCStatus)
}

// --- Diff ---

func TestDiff(t *testing.T) {
	srv, db := testServer(t)
	baseID := testUUID(1)
	compareID := testUUID(2)
	s1 := testScanResult(baseID, "host-a")
	s2 := testScanResult(compareID, "host-a")
	s2.Findings = append(s2.Findings, model.Finding{
		ID:          "new-f",
		Source:      model.FindingSource{Type: "file", Path: "/new"},
		CryptoAsset: &model.CryptoAsset{Algorithm: "ML-KEM", PQCStatus: "SAFE"},
		Module:      "certificates",
	})
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base="+baseID+"&compare="+compareID, nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "addedCount")
}

// --- Trend ---

func TestTrend(t *testing.T) {
	srv, db := testServer(t)
	for i := 0; i < 3; i++ {
		s := testScanResult(testUUID(i+1), "host-a")
		s.Metadata.Timestamp = time.Now().Add(time.Duration(i) * time.Hour)
		require.NoError(t, db.SaveScan(context.Background(), s))
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/trend?hostname=host-a&last=5", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "points")
}

// --- Machines ---

func TestListMachines(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(1), "host-a")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(2), "host-b")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(3), "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/machines", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var machines []store.ScanSummary
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &machines))
	assert.Len(t, machines, 2) // host-a and host-b
}

// --- Aggregate ---

func TestAggregate(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(1), "host-a")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(2), "host-b")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/aggregate", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var agg map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &agg))
	assert.Equal(t, float64(2), agg["machineCount"])
}

// --- Policy Evaluate ---

func TestPolicyEvaluate_Builtin(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	scan := testScanResult(id, "host-a")
	scan.Findings[0].CryptoAsset.PQCStatus = "UNSAFE"
	scan.Summary.Unsafe = 1
	require.NoError(t, db.SaveScan(context.Background(), scan))

	body := fmt.Sprintf(`{"scanID":"%s","policyName":"nacsa-2030"}`, id)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader([]byte(body)))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "FAIL")
}

// --- Web UI ---

func TestUIRedirect(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "/ui/index.html")
}

func TestUIServeIndex(t *testing.T) {
	srv, _ := testServer(t)

	// http.FileServer redirects /index.html to /, so request the directory
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ui/", nil)
	srv.Router().ServeHTTP(w, r)

	// FileServer serves index.html for directory requests
	if w.Code == http.StatusOK {
		assert.Contains(t, w.Body.String(), "Triton Dashboard")
	} else {
		// If served from /ui/index.html, follow redirect
		assert.Equal(t, http.StatusMovedPermanently, w.Code)
	}
}

func TestUIServeCSS(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ui/style.css", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "--bg-primary")
}

func TestUIServeJS(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ui/app.js", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "renderOverview")
}

// --- Delete Scan Not Found ---

func TestDeleteScan_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/scans/"+zeroUUID, nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Findings Edge Cases ---

func TestGetFindings_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/"+zeroUUID+"/findings", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetFindings_FilterByModule(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	scan := testScanResult(id, "host-a")
	scan.Findings = append(scan.Findings, model.Finding{
		ID:     "f2",
		Source: model.FindingSource{Type: "file", Path: "/lib"},
		CryptoAsset: &model.CryptoAsset{
			Algorithm: "AES-256",
			PQCStatus: "SAFE",
		},
		Module: "libraries",
	})
	require.NoError(t, db.SaveScan(context.Background(), scan))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/"+id+"/findings?module=libraries", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var findings []model.Finding
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &findings))
	assert.Len(t, findings, 1)
	assert.Equal(t, "libraries", findings[0].Module)
}

func TestGetFindings_FilterBothPQCAndModule(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	scan := testScanResult(id, "host-a")
	scan.Findings = append(scan.Findings,
		model.Finding{
			ID:          "f2",
			Source:      model.FindingSource{Type: "file", Path: "/lib"},
			CryptoAsset: &model.CryptoAsset{Algorithm: "AES-256", PQCStatus: "SAFE"},
			Module:      "libraries",
		},
		model.Finding{
			ID:          "f3",
			Source:      model.FindingSource{Type: "file", Path: "/cert"},
			CryptoAsset: &model.CryptoAsset{Algorithm: "ML-KEM", PQCStatus: "SAFE"},
			Module:      "certificates",
		},
	)
	require.NoError(t, db.SaveScan(context.Background(), scan))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/"+id+"/findings?pqc_status=SAFE&module=libraries", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var findings []model.Finding
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &findings))
	assert.Len(t, findings, 1)
	assert.Equal(t, "libraries", findings[0].Module)
}

// --- Diff Edge Cases ---

func TestDiff_MissingParams(t *testing.T) {
	srv, _ := testServer(t)

	// No params at all
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff", nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Only base
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/diff?base="+testUUID(1), nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Only compare
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/diff?compare="+testUUID(2), nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDiff_BaseNotFound(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base="+zeroUUID+"&compare="+testUUID(99), nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "base scan not found")
}

func TestDiff_CompareNotFound(t *testing.T) {
	srv, db := testServer(t)
	existID := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(existID, "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base="+existID+"&compare="+zeroUUID, nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "compare scan not found")
}

// --- ListScans Query Params ---

func TestListScans_WithLimit(t *testing.T) {
	srv, db := testServer(t)
	for i := 0; i < 5; i++ {
		s := testScanResult(testUUID(i+1), "host-a")
		s.Metadata.Timestamp = time.Now().Add(time.Duration(i) * time.Hour)
		require.NoError(t, db.SaveScan(context.Background(), s))
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans?limit=2", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var summaries []store.ScanSummary
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &summaries))
	assert.Len(t, summaries, 2)
}

func TestListScans_WithTimeRange(t *testing.T) {
	srv, db := testServer(t)
	baseTime := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s := testScanResult(testUUID(i+1), "host-a")
		s.Metadata.Timestamp = baseTime.Add(time.Duration(i) * 24 * time.Hour)
		require.NoError(t, db.SaveScan(context.Background(), s))
	}

	after := baseTime.Add(24 * time.Hour).Format(time.RFC3339)
	before := baseTime.Add(3 * 24 * time.Hour).Format(time.RFC3339)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans?after="+after+"&before="+before, nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var summaries []store.ScanSummary
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &summaries))
	assert.Len(t, summaries, 3)
}

func TestListScans_WithProfile(t *testing.T) {
	srv, db := testServer(t)
	s1 := testScanResult(testUUID(1), "host-a")
	s1.Metadata.ScanProfile = "comprehensive"
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(2), "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans?profile=comprehensive", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var summaries []store.ScanSummary
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &summaries))
	assert.Len(t, summaries, 1)
}

func TestListScans_EmptyResult(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	// Should return empty array, not null
	assert.Equal(t, "[]\n", w.Body.String())
}

// --- Machine History ---

func TestMachineHistory(t *testing.T) {
	srv, db := testServer(t)
	for i := 0; i < 3; i++ {
		s := testScanResult(testUUID(i+1), "target-host")
		s.Metadata.Timestamp = time.Now().Add(time.Duration(i) * time.Hour)
		require.NoError(t, db.SaveScan(context.Background(), s))
	}
	// Different host — should not appear
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(10), "other-host")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/machines/target-host", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var summaries []store.ScanSummary
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &summaries))
	assert.Len(t, summaries, 3)
	for _, s := range summaries {
		assert.Equal(t, "target-host", s.Hostname)
	}
}

func TestMachineHistory_Empty(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/machines/no-such-host", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "[]\n", w.Body.String())
}

// --- Report Generation ---

func TestGenerateReport_ScanNotFound(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/"+zeroUUID+"/json", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGenerateReport_UnsupportedFormat(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/"+id+"/xml", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unsupported format")
}

func TestGenerateReport_JSON(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/"+id+"/json", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "result")
}

func TestGenerateReport_SARIF(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/"+id+"/sarif", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "$schema")
}

func TestGenerateReport_HTML(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/"+id+"/html", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<!DOCTYPE html>")
}

func TestGenerateReport_CycloneDX(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/"+id+"/cyclonedx", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "bomFormat")
}

// --- Policy Evaluate Edge Cases ---

func TestPolicyEvaluate_InvalidJSON(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader([]byte("bad")))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPolicyEvaluate_MissingScanID(t *testing.T) {
	srv, _ := testServer(t)
	body := `{"policyName":"nacsa-2030"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader([]byte(body)))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "scanID is required")
}

func TestPolicyEvaluate_ScanNotFound(t *testing.T) {
	srv, _ := testServer(t)
	body := fmt.Sprintf(`{"scanID":"%s","policyName":"nacsa-2030"}`, zeroUUID)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader([]byte(body)))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPolicyEvaluate_NoPolicySpecified(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	body := fmt.Sprintf(`{"scanID":"%s"}`, id)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader([]byte(body)))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "policyName or policyYAML required")
}

func TestPolicyEvaluate_InvalidPolicyName(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	body := fmt.Sprintf(`{"scanID":"%s","policyName":"no-such-policy"}`, id)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader([]byte(body)))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid policy")
}

func TestPolicyEvaluate_CustomYAML(t *testing.T) {
	srv, db := testServer(t)
	id := testUUID(1)
	scan := testScanResult(id, "host-a")
	require.NoError(t, db.SaveScan(context.Background(), scan))

	policyYAML := `name: test-policy
version: "1.0"
description: Test policy
rules:
  - id: no-unsafe
    description: No unsafe algorithms
    severity: high
    condition:
      field: pqc_status
      operator: not_equals
      value: UNSAFE`

	reqBody := map[string]string{
		"scanID":     id,
		"policyYAML": policyYAML,
	}
	body, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader(body))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Trend Edge Cases ---

func TestTrend_DefaultLast(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(testUUID(1), "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/trend", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTrend_Empty(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/trend?hostname=nobody", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Aggregate Edge Cases ---

func TestAggregate_Empty(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/aggregate", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var agg map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &agg))
	assert.Equal(t, float64(0), agg["machineCount"])
}

// --- Licence Middleware ---

func testServerWithGuard(t *testing.T, tier license.Tier) (*Server, *store.PostgresStore) {
	t.Helper()
	dbUrl := os.Getenv("TRITON_TEST_DB_URL")
	if dbUrl == "" {
		dbUrl = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	db, err := store.NewPostgresStore(ctx, dbUrl)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	require.NoError(t, db.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = db.TruncateAll(ctx)
		db.Close()
	})

	// Generate ephemeral keypair and a license with both tier AND
	// orgID set, so the Guard satisfies both LicenceGate (tier check)
	// and UnifiedAuth's guard fallback path (non-empty org_id).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	lic := &license.License{
		ID:        "test-tier-license",
		Tier:      tier,
		OrgID:     testOrgID,
		Org:       "Test Org",
		Seats:     1,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	token, err := license.Encode(lic, priv)
	require.NoError(t, err)
	guard := license.NewGuardFromToken(token, pub)

	cfg := &Config{
		ListenAddr: ":0",
		Guard:      guard,
	}
	srv, err := New(cfg, db)
	require.NoError(t, err)
	return srv, db
}

func TestLicenceMiddleware_BlocksDiffForFreeTier(t *testing.T) {
	srv, _ := testServerWithGuard(t, license.TierFree)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base="+testUUID(1)+"&compare="+testUUID(2), nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestLicenceMiddleware_AllowsDiffForEnterprise(t *testing.T) {
	srv, db := testServerWithGuard(t, license.TierEnterprise)
	id1 := testUUID(1)
	id2 := testUUID(2)
	s1 := testScanResult(id1, "host-a")
	s2 := testScanResult(id2, "host-a")
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base="+id1+"&compare="+id2, nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLicenceMiddleware_NilGuardAllowsAll(t *testing.T) {
	srv, db := testServer(t) // testServer has no Guard → nil
	id1 := testUUID(1)
	id2 := testUUID(2)
	s1 := testScanResult(id1, "host-a")
	s2 := testScanResult(id2, "host-a")
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base="+id1+"&compare="+id2, nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code, "nil guard should allow all requests")
}

func TestLicenceMiddleware_BlocksSarifReportForPro(t *testing.T) {
	srv, db := testServerWithGuard(t, license.TierPro)
	id := testUUID(1)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult(id, "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/"+id+"/sarif", nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// --- Start / Shutdown ---

func TestStartAndShutdown(t *testing.T) {
	srv, _ := testServer(t)
	// Override to use random port
	srv.http.Addr = "127.0.0.1:0"

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Poll the health endpoint to wait for server readiness instead of sleeping
	var err error
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		resp, httpErr := http.Get("http://" + srv.http.Addr + "/api/v1/health")
		if httpErr == nil {
			_ = resp.Body.Close()
			break
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = srv.Shutdown(ctx)
	assert.NoError(t, err)

	// Start should return http.ErrServerClosed
	startErr := <-errCh
	assert.ErrorIs(t, startErr, http.ErrServerClosed)
}

// --- ListScans validation ---

func TestListScans_InvalidLimit(t *testing.T) {
	srv, _ := testServer(t)

	// Negative limit should return 400.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans?limit=-1", nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Zero limit should return 400.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/v1/scans?limit=0", nil)
	srv.Router().ServeHTTP(w2, r2)
	assert.Equal(t, http.StatusBadRequest, w2.Code)
}

func TestListScans_InvalidTimestamp(t *testing.T) {
	srv, _ := testServer(t)

	// Invalid after timestamp.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans?after=not-a-date", nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Invalid before timestamp.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/v1/scans?before=invalid", nil)
	srv.Router().ServeHTTP(w2, r2)
	assert.Equal(t, http.StatusBadRequest, w2.Code)
}

// --- Security headers ---

func TestSecurityHeaders(t *testing.T) {
	srv, _ := testServer(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/health", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.NotEmpty(t, w.Header().Get("Permissions-Policy"))
}

// --- latestByHostname unit test ---

func TestLatestByHostname(t *testing.T) {
	// Empty input.
	assert.Empty(t, latestByHostname(nil))
	assert.Empty(t, latestByHostname([]store.ScanSummary{}))

	// Single entry.
	single := []store.ScanSummary{{Hostname: "host1", ID: "a"}}
	result := latestByHostname(single)
	assert.Len(t, result, 1)
	assert.Equal(t, "a", result[0].ID)

	// Multiple scans same host — keep first (latest since ListScans is DESC).
	multi := []store.ScanSummary{
		{Hostname: "host1", ID: "a"},
		{Hostname: "host1", ID: "b"},
		{Hostname: "host2", ID: "c"},
	}
	result = latestByHostname(multi)
	assert.Len(t, result, 2)
	// First entry for host1 should be "a" (the newest).
	ids := map[string]string{}
	for _, r := range result {
		ids[r.Hostname] = r.ID
	}
	assert.Equal(t, "a", ids["host1"])
	assert.Equal(t, "c", ids["host2"])
}

// --- writeJSON error path ---

func TestWriteJSON_MarshalError(t *testing.T) {
	w := httptest.NewRecorder()
	// math.NaN() causes json.Marshal to fail.
	writeJSON(w, http.StatusOK, map[string]float64{"val": math.NaN()})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
