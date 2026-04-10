//go:build integration

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// cryptoFinding is a test helper that builds a file-sourced crypto
// finding for handler tests. Lives here rather than in pkg/store
// because handler tests don't depend on store internals.
func cryptoFinding(module, path string, ca *model.CryptoAsset) model.Finding {
	return model.Finding{
		Module:      module,
		Source:      model.FindingSource{Type: "file", Path: path},
		CryptoAsset: ca,
	}
}

// --- handleInventory (Analytics Phase 1, Task 2.1) ---

func TestHandleInventory_EmptyReturns200(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.InventoryRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Empty(t, rows)
}

func TestHandleInventory_PopulatedReturnsRows(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID(1), "host-1")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.InventoryRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	require.Len(t, rows, 1)
	assert.Equal(t, "RSA", rows[0].Algorithm)
	assert.Equal(t, 2048, rows[0].KeySize)
	assert.Equal(t, "DEPRECATED", rows[0].PQCStatus)
}

func TestHandleInventory_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleInventory_BackfillHeaderWhenInProgress(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	srv.BackfillInProgress().Store(true)
	defer srv.BackfillInProgress().Store(false)

	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", token, nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true", w.Header().Get("X-Backfill-In-Progress"))
}

// --- handleExpiringCertificates (Analytics Phase 1, Task 3.1) ---

func TestHandleExpiringCerts_DefaultWindow(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	in30 := time.Now().UTC().Add(30 * 24 * time.Hour)
	in200 := time.Now().UTC().Add(200 * 24 * time.Hour)

	scan := testScanResult(testUUID(2), "host-1")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		cryptoFinding("certificate", "/soon.crt", &model.CryptoAsset{
			Algorithm: "RSA", KeySize: 2048, NotAfter: &in30, Subject: "CN=soon",
		}),
		cryptoFinding("certificate", "/later.crt", &model.CryptoAsset{
			Algorithm: "RSA", KeySize: 2048, NotAfter: &in200, Subject: "CN=later",
		}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/certificates/expiring", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.ExpiringCertRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 1, "default 90-day window excludes the 200-day cert")
	assert.Equal(t, "CN=soon", rows[0].Subject)
}

func TestHandleExpiringCerts_WithinAll(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	in500 := time.Now().UTC().Add(500 * 24 * time.Hour)
	scan := testScanResult(testUUID(3), "host-1")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		cryptoFinding("certificate", "/far.crt", &model.CryptoAsset{
			Algorithm: "RSA", KeySize: 2048, NotAfter: &in500, Subject: "CN=far",
		}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/certificates/expiring?within=all", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.ExpiringCertRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 1)
	assert.Equal(t, "CN=far", rows[0].Subject)
}

func TestHandleExpiringCerts_InvalidWithin(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	for _, param := range []string{"abc", "-1", "5000"} {
		t.Run(param, func(t *testing.T) {
			w := authReq(t, srv, http.MethodGet,
				"/api/v1/certificates/expiring?within="+param, token, nil)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestHandleExpiringCerts_EmptyReturns200(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/certificates/expiring", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.ExpiringCertRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Empty(t, rows)
}

// --- handlePriorityFindings (Analytics Phase 1, Task 4.1) ---

func TestHandlePriority_DefaultLimit(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID(4), "host-1")
	scan.OrgID = org.ID
	scan.Findings = nil
	for i := 0; i < 25; i++ {
		scan.Findings = append(scan.Findings,
			cryptoFinding("key", "/k", &model.CryptoAsset{
				Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i,
			}))
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/priority", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.PriorityRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 20, "default limit must be 20")
}

func TestHandlePriority_CustomLimit(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID(5), "host-1")
	scan.OrgID = org.ID
	scan.Findings = nil
	for i := 0; i < 10; i++ {
		scan.Findings = append(scan.Findings,
			cryptoFinding("key", "/k", &model.CryptoAsset{
				Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i,
			}))
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/priority?limit=5", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.PriorityRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 5)
}

func TestHandlePriority_InvalidLimit(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	for _, param := range []string{"0", "-1", "1001", "abc"} {
		t.Run(param, func(t *testing.T) {
			w := authReq(t, srv, http.MethodGet,
				"/api/v1/priority?limit="+param, token, nil)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestHandlePriority_EmptyReturns200(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/priority", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.PriorityRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Empty(t, rows)
}

// --- handleExecutiveSummary (Analytics Phase 2) ---

func TestHandleExecutive_EmptyOrgReturnsZeroes(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/executive", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var got store.ExecutiveSummary
	require.NoError(t, json.NewDecoder(w.Body).Decode(&got))

	assert.Equal(t, 0.0, got.Readiness.Percent)
	assert.Equal(t, 0, got.Readiness.TotalFindings)
	assert.Equal(t, "insufficient-history", got.Trend.Direction)
	assert.Equal(t, "insufficient-history", got.Projection.Status)
	assert.Equal(t, 80.0, got.Projection.TargetPercent, "empty org uses default target")
	assert.Equal(t, 2030, got.Projection.DeadlineYear, "empty org uses default deadline")
	assert.Len(t, got.PolicyVerdicts, 2, "both NACSA-2030 and CNSA-2.0 present")
	assert.Empty(t, got.TopBlockers)
	assert.Equal(t, 0, got.MachineHealth.Total)
}

func TestHandleExecutive_PopulatedReturnsFullSummary(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	// Seed two scans in different months to make the trend and
	// projection computable.
	scan1 := testScanResult(testUUID(10), "host-1")
	scan1.OrgID = org.ID
	scan1.Metadata.Timestamp = time.Now().UTC().AddDate(0, -2, 0) // 2 months ago
	scan1.Summary = model.Summary{TotalFindings: 100, Safe: 30, Transitional: 20, Deprecated: 30, Unsafe: 20}
	scan1.Findings = []model.Finding{
		cryptoFinding("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan1, store.ExtractFindings(scan1)))

	scan2 := testScanResult(testUUID(11), "host-1")
	scan2.OrgID = org.ID
	scan2.Metadata.Timestamp = time.Now().UTC()
	scan2.Summary = model.Summary{TotalFindings: 100, Safe: 50, Transitional: 20, Deprecated: 20, Unsafe: 10}
	scan2.Findings = []model.Finding{
		cryptoFinding("key", "/b", &model.CryptoAsset{Algorithm: "RSA", KeySize: 4096, PQCStatus: "SAFE", MigrationPriority: 0}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan2, store.ExtractFindings(scan2)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/executive", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var got store.ExecutiveSummary
	require.NoError(t, json.NewDecoder(w.Body).Decode(&got))

	// Readiness computed from LATEST per host summary.
	assert.Greater(t, got.Readiness.Percent, 0.0)
	assert.Greater(t, got.Readiness.TotalFindings, 0)

	// Trend should have 2 monthly points.
	assert.Len(t, got.Trend.MonthlyPoints, 2)

	// Machine health: host-1 has unsafe > 0 in latest → red=1, total=1.
	assert.Equal(t, 1, got.MachineHealth.Red)
	assert.Equal(t, 1, got.MachineHealth.Total)

	// Policy verdicts: always 2 entries regardless of data.
	require.Len(t, got.PolicyVerdicts, 2)
	assert.Equal(t, "nacsa-2030", got.PolicyVerdicts[0].PolicyName)
	assert.Equal(t, "cnsa-2.0", got.PolicyVerdicts[1].PolicyName)
}

func TestHandleExecutive_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/executive", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleExecutive_BackfillHeaderWhenInProgress(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	srv.BackfillInProgress().Store(true)
	defer srv.BackfillInProgress().Store(false)

	w := authReq(t, srv, http.MethodGet, "/api/v1/executive", token, nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true", w.Header().Get("X-Backfill-In-Progress"))
}

func TestHandleExecutive_UsesOrgTargetPercent(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	// Override the org's target percent via direct SQL.
	_, err := db.Pool().Exec(context.Background(),
		`UPDATE organizations SET executive_target_percent = $1 WHERE id = $2`,
		60.0, org.ID)
	require.NoError(t, err)

	w := authReq(t, srv, http.MethodGet, "/api/v1/executive", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var got store.ExecutiveSummary
	require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
	assert.Equal(t, 60.0, got.Projection.TargetPercent, "custom target from DB must propagate")
	assert.Equal(t, 2030, got.Projection.DeadlineYear, "deadline still default")
}

func TestHandleExecutive_UsesOrgDeadlineYear(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	_, err := db.Pool().Exec(context.Background(),
		`UPDATE organizations SET executive_deadline_year = $1 WHERE id = $2`,
		2035, org.ID)
	require.NoError(t, err)

	w := authReq(t, srv, http.MethodGet, "/api/v1/executive", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var got store.ExecutiveSummary
	require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
	assert.Equal(t, 2035, got.Projection.DeadlineYear)
	assert.Equal(t, 80.0, got.Projection.TargetPercent)
}

func TestHandleExecutive_PolicyVerdictsIncludeBothBuiltins(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/executive", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var got store.ExecutiveSummary
	require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
	require.Len(t, got.PolicyVerdicts, 2)

	names := []string{got.PolicyVerdicts[0].PolicyName, got.PolicyVerdicts[1].PolicyName}
	assert.Contains(t, names, "nacsa-2030")
	assert.Contains(t, names, "cnsa-2.0")

	// Labels must be human-readable, not the raw policy name.
	for _, v := range got.PolicyVerdicts {
		assert.NotEmpty(t, v.PolicyLabel)
		assert.Contains(t, []string{"PASS", "WARN", "FAIL"}, v.Verdict)
	}
}

func TestHandleExecutive_TenantIsolation(t *testing.T) {
	srv, db := testServerWithJWT(t)
	orgA, userA := createOrgUser(t, db, "org_admin", "correct-horse-battery-a", false)
	_, userB := createOrgUser(t, db, "org_admin", "correct-horse-battery-b", false)
	tokenA := loginAndExtractToken(t, srv, userA.Email, "correct-horse-battery-a")
	tokenB := loginAndExtractToken(t, srv, userB.Email, "correct-horse-battery-b")

	// Seed a scan in org A only.
	scan := testScanResult(testUUID(20), "host-a")
	scan.OrgID = orgA.ID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED"}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	// Org A sees its data.
	wA := authReq(t, srv, http.MethodGet, "/api/v1/executive", tokenA, nil)
	var gotA store.ExecutiveSummary
	require.NoError(t, json.NewDecoder(wA.Body).Decode(&gotA))
	assert.Greater(t, gotA.Readiness.TotalFindings, 0)

	// Org B sees empty.
	wB := authReq(t, srv, http.MethodGet, "/api/v1/executive", tokenB, nil)
	var gotB store.ExecutiveSummary
	require.NoError(t, json.NewDecoder(wB.Body).Decode(&gotB))
	assert.Equal(t, 0, gotB.Readiness.TotalFindings)
}
