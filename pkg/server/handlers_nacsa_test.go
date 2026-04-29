//go:build integration

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// --- handleNacsaSummary (GET /api/v1/nacsa/summary) ---

func TestHandleNacsaSummary_ReturnsOK(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/summary", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var got store.NacsaSummary
	require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
	// Empty org: readiness 0, no blockers, no phases.
	assert.Equal(t, 0.0, got.ReadinessPct)
	assert.Equal(t, 80.0, got.TargetPct)
	assert.Equal(t, 2030, got.TargetYear)
	assert.Empty(t, got.TopBlockers)
	assert.Empty(t, got.MigrationPhases)
}

func TestHandleNacsaSummary_PopulatedReturnsReadiness(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID(200), "host-nacsa-1")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		cryptoFinding("certificate", "/safe.crt", &model.CryptoAsset{
			Algorithm: "CRYSTALS-Kyber", KeySize: 768, PQCStatus: "SAFE",
		}),
		cryptoFinding("key", "/unsafe.key", &model.CryptoAsset{
			Algorithm: "RSA", KeySize: 1024, PQCStatus: "UNSAFE", MigrationPriority: 90,
		}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/summary", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var got store.NacsaSummary
	require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
	// 1 safe out of 2 total → 50%
	assert.Equal(t, 50.0, got.ReadinessPct)
	assert.Equal(t, int64(2), got.TotalAssets)
	assert.Equal(t, int64(1), got.Safe)
	// UNSAFE finding produces a top blocker.
	assert.NotEmpty(t, got.TopBlockers)
}

func TestHandleNacsaSummary_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/summary", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- handleNacsaServers (GET /api/v1/nacsa/servers) ---

func TestHandleNacsaServers_ReturnsArray(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/servers", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	// Must decode as an array, never null.
	var rows []store.NacsaServerRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.NotNil(t, rows)
}

func TestHandleNacsaServers_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/servers", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- handleNacsaHosts (GET /api/v1/nacsa/servers/{serverID}/hosts) ---

func TestHandleNacsaHosts_ReturnsArray(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/servers/nonexistent-server/hosts", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.NacsaHostRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.NotNil(t, rows)
	// No hosts for unknown server.
	assert.Empty(t, rows)
}

func TestHandleNacsaHosts_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/servers/some-server/hosts", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- handleNacsaCBOM (GET /api/v1/nacsa/hosts/{hostname}/cbom) ---

func TestHandleNacsaCBOM_EmptyHostReturnsArray(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/hosts/unknown-host/cbom", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.NacsaCBOMRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.NotNil(t, rows)
	assert.Empty(t, rows)
}

func TestHandleNacsaCBOM_StatusFilterApplied(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID(201), "host-cbom-1")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/safe.key", &model.CryptoAsset{
			Algorithm: "Ed25519", PQCStatus: "SAFE",
		}),
		cryptoFinding("key", "/unsafe.key", &model.CryptoAsset{
			Algorithm: "RSA", KeySize: 1024, PQCStatus: "UNSAFE",
		}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	// Filter to UNSAFE only.
	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/hosts/host-cbom-1/cbom?status=UNSAFE", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.NacsaCBOMRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.NotEmpty(t, rows)
	for _, r := range rows {
		assert.Equal(t, "UNSAFE", r.PQCStatus)
	}
}

func TestHandleNacsaCBOM_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/hosts/some-host/cbom", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- handleNacsaRisk (GET /api/v1/nacsa/hosts/{hostname}/risk) ---

func TestHandleNacsaRisk_EmptyHostReturnsArray(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/hosts/unknown-host/risk", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.NacsaRiskRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.NotNil(t, rows)
	assert.Empty(t, rows)
}

func TestHandleNacsaRisk_PopulatedReturnsScores(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID(202), "host-risk-1")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/bad.key", &model.CryptoAsset{
			Algorithm: "DES", KeySize: 56, PQCStatus: "UNSAFE", MigrationPriority: 90,
		}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/hosts/host-risk-1/risk", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.NacsaRiskRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	require.NotEmpty(t, rows)
	// UNSAFE findings must produce a non-zero score and a risk band.
	assert.Greater(t, rows[0].Score, 0)
	assert.NotEmpty(t, rows[0].RiskBand)
}

func TestHandleNacsaRisk_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/hosts/some-host/risk", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- handleNacsaMigration (GET /api/v1/nacsa/migration) ---

func TestHandleNacsaMigration_EmptyPhasesArray(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/migration", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var got store.NacsaMigResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
	// Empty org: phases must be a non-nil empty array, not null.
	assert.NotNil(t, got.Phases)
	assert.Empty(t, got.Phases)
}

func TestHandleNacsaMigration_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/migration", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Tenant isolation ---

func TestHandleNacsaSummary_TenantIsolation(t *testing.T) {
	srv, db := testServerWithJWT(t)
	orgA, userA := createOrgUser(t, db, "org_admin", "correct-horse-battery-a", false)
	_, userB := createOrgUser(t, db, "org_admin", "correct-horse-battery-b", false)
	tokenA := loginAndExtractToken(t, srv, userA.Email, "correct-horse-battery-a")
	tokenB := loginAndExtractToken(t, srv, userB.Email, "correct-horse-battery-b")

	// Seed a scan with an UNSAFE finding in org A only.
	scan := testScanResult(testUUID(203), "host-isolation-nacsa")
	scan.OrgID = orgA.ID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/bad.key", &model.CryptoAsset{
			Algorithm: "RC4", PQCStatus: "UNSAFE", MigrationPriority: 95,
		}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	// Org A sees its data.
	wA := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/summary", tokenA, nil)
	require.Equal(t, http.StatusOK, wA.Code)
	var gotA store.NacsaSummary
	require.NoError(t, json.NewDecoder(wA.Body).Decode(&gotA))
	assert.Equal(t, int64(1), gotA.TotalAssets)

	// Org B sees empty.
	wB := authReq(t, srv, http.MethodGet, "/api/v1/nacsa/summary", tokenB, nil)
	require.Equal(t, http.StatusOK, wB.Code)
	var gotB store.NacsaSummary
	require.NoError(t, json.NewDecoder(wB.Body).Decode(&gotB))
	assert.Equal(t, int64(0), gotB.TotalAssets)
}
