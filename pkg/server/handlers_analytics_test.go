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
