//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

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
	}
	srv := New(cfg, db)
	return srv, db
}

func testServerWithAuth(t *testing.T) (*Server, *store.PostgresStore) {
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
		APIKeys:    []string{"test-key-123"},
	}
	srv := New(cfg, db)
	return srv, db
}

func testScanResult(id, hostname string) *model.ScanResult {
	return &model.ScanResult{
		ID: id,
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

func TestAuth_MissingKey(t *testing.T) {
	srv, _ := testServerWithAuth(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_InvalidKey(t *testing.T) {
	srv, _ := testServerWithAuth(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	r.Header.Set("X-Triton-API-Key", "wrong-key")
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAuth_ValidKey(t *testing.T) {
	srv, _ := testServerWithAuth(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	r.Header.Set("X-Triton-API-Key", "test-key-123")
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHealth_NoAuthRequired(t *testing.T) {
	srv, _ := testServerWithAuth(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/health", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Scan CRUD ---

func TestSubmitScan(t *testing.T) {
	srv, _ := testServer(t)
	scan := testScanResult("submit-1", "host-a")
	body, _ := json.Marshal(scan)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "submit-1")
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
	scan := testScanResult("get-1", "host-a")
	require.NoError(t, db.SaveScan(context.Background(), scan))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/get-1", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var got model.ScanResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "get-1", got.ID)
}

func TestGetScan_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/nonexistent", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListScans(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("list-1", "host-a")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("list-2", "host-b")))

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
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("filt-1", "host-a")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("filt-2", "host-b")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans?hostname=host-a", nil)
	srv.Router().ServeHTTP(w, r)

	var summaries []store.ScanSummary
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &summaries))
	assert.Len(t, summaries, 1)
}

func TestDeleteScan(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("del-1", "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/scans/del-1", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify deleted
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/v1/scans/del-1", nil)
	srv.Router().ServeHTTP(w2, r2)
	assert.Equal(t, http.StatusNotFound, w2.Code)
}

// --- Findings ---

func TestGetFindings(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("find-1", "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/find-1/findings", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var findings []model.Finding
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &findings))
	assert.Len(t, findings, 1)
}

func TestGetFindings_FilterPQCStatus(t *testing.T) {
	srv, db := testServer(t)
	scan := testScanResult("fpqc-1", "host-a")
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
	r := httptest.NewRequest("GET", "/api/v1/scans/fpqc-1/findings?pqc_status=SAFE", nil)
	srv.Router().ServeHTTP(w, r)

	var findings []model.Finding
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &findings))
	assert.Len(t, findings, 1)
	assert.Equal(t, "SAFE", findings[0].CryptoAsset.PQCStatus)
}

// --- Diff ---

func TestDiff(t *testing.T) {
	srv, db := testServer(t)
	s1 := testScanResult("diff-base", "host-a")
	s2 := testScanResult("diff-compare", "host-a")
	s2.Findings = append(s2.Findings, model.Finding{
		ID:          "new-f",
		Source:      model.FindingSource{Type: "file", Path: "/new"},
		CryptoAsset: &model.CryptoAsset{Algorithm: "ML-KEM", PQCStatus: "SAFE"},
		Module:      "certificates",
	})
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base=diff-base&compare=diff-compare", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "addedCount")
}

// --- Trend ---

func TestTrend(t *testing.T) {
	srv, db := testServer(t)
	for i := 0; i < 3; i++ {
		s := testScanResult("trend-"+string(rune('a'+i)), "host-a")
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
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("m-1", "host-a")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("m-2", "host-b")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("m-3", "host-a")))

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
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("agg-1", "host-a")))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("agg-2", "host-b")))

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
	scan := testScanResult("pol-1", "host-a")
	scan.Findings[0].CryptoAsset.PQCStatus = "UNSAFE"
	scan.Summary.Unsafe = 1
	require.NoError(t, db.SaveScan(context.Background(), scan))

	body := `{"scanID":"pol-1","policyName":"nacsa-2030"}`
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
	assert.Contains(t, w.Body.String(), "--primary")
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
	r := httptest.NewRequest("DELETE", "/api/v1/scans/nonexistent", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Findings Edge Cases ---

func TestGetFindings_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/scans/nonexistent/findings", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetFindings_FilterByModule(t *testing.T) {
	srv, db := testServer(t)
	scan := testScanResult("fmod-1", "host-a")
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
	r := httptest.NewRequest("GET", "/api/v1/scans/fmod-1/findings?module=libraries", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var findings []model.Finding
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &findings))
	assert.Len(t, findings, 1)
	assert.Equal(t, "libraries", findings[0].Module)
}

func TestGetFindings_FilterBothPQCAndModule(t *testing.T) {
	srv, db := testServer(t)
	scan := testScanResult("fboth-1", "host-a")
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
	r := httptest.NewRequest("GET", "/api/v1/scans/fboth-1/findings?pqc_status=SAFE&module=libraries", nil)
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
	r = httptest.NewRequest("GET", "/api/v1/diff?base=scan-1", nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Only compare
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/diff?compare=scan-2", nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDiff_BaseNotFound(t *testing.T) {
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base=nonexistent&compare=also-missing", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "base scan not found")
}

func TestDiff_CompareNotFound(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("diff-exist", "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base=diff-exist&compare=nonexistent", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "compare scan not found")
}

// --- ListScans Query Params ---

func TestListScans_WithLimit(t *testing.T) {
	srv, db := testServer(t)
	for i := 0; i < 5; i++ {
		s := testScanResult("lim-"+string(rune('a'+i)), "host-a")
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
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s := testScanResult("tr-"+string(rune('a'+i)), "host-a")
		s.Metadata.Timestamp = base.Add(time.Duration(i) * 24 * time.Hour)
		require.NoError(t, db.SaveScan(context.Background(), s))
	}

	after := base.Add(24 * time.Hour).Format(time.RFC3339)
	before := base.Add(3 * 24 * time.Hour).Format(time.RFC3339)

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
	s1 := testScanResult("prof-1", "host-a")
	s1.Metadata.ScanProfile = "comprehensive"
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("prof-2", "host-a")))

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
		s := testScanResult("mh-"+string(rune('a'+i)), "target-host")
		s.Metadata.Timestamp = time.Now().Add(time.Duration(i) * time.Hour)
		require.NoError(t, db.SaveScan(context.Background(), s))
	}
	// Different host — should not appear
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("mh-other", "other-host")))

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
	r := httptest.NewRequest("GET", "/api/v1/reports/nonexistent/json", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGenerateReport_UnsupportedFormat(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("rpt-1", "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/rpt-1/xml", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unsupported format")
}

func TestGenerateReport_JSON(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("rpt-json", "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/rpt-json/json", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "result")
}

func TestGenerateReport_SARIF(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("rpt-sarif", "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/rpt-sarif/sarif", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "$schema")
}

func TestGenerateReport_HTML(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("rpt-html", "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/rpt-html/html", nil)
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<!DOCTYPE html>")
}

func TestGenerateReport_CycloneDX(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("rpt-cdx", "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/rpt-cdx/cyclonedx", nil)
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
	body := `{"scanID":"nonexistent","policyName":"nacsa-2030"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader([]byte(body)))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPolicyEvaluate_NoPolicySpecified(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("pol-nop", "host-a")))

	body := `{"scanID":"pol-nop"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader([]byte(body)))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "policyName or policyYAML required")
}

func TestPolicyEvaluate_InvalidPolicyName(t *testing.T) {
	srv, db := testServer(t)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("pol-bad", "host-a")))

	body := `{"scanID":"pol-bad","policyName":"no-such-policy"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/policy/evaluate", bytes.NewReader([]byte(body)))
	srv.Router().ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid policy")
}

func TestPolicyEvaluate_CustomYAML(t *testing.T) {
	srv, db := testServer(t)
	scan := testScanResult("pol-yaml", "host-a")
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
		"scanID":     "pol-yaml",
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
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("trend-def", "host-a")))

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

	// Generate ephemeral keypair and token for the given tier
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)
	token, err := license.IssueTokenWithOptions(priv, tier, "Test Org", 1, 365, false)
	require.NoError(t, err)
	guard := license.NewGuardFromToken(token, pub)

	cfg := &Config{
		ListenAddr: ":0",
		Guard:      guard,
	}
	srv := New(cfg, db)
	return srv, db
}

func TestLicenceMiddleware_BlocksDiffForFreeTier(t *testing.T) {
	srv, _ := testServerWithGuard(t, license.TierFree)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base=a&compare=b", nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestLicenceMiddleware_AllowsDiffForEnterprise(t *testing.T) {
	srv, db := testServerWithGuard(t, license.TierEnterprise)
	s1 := testScanResult("diff-lic-1", "host-a")
	s2 := testScanResult("diff-lic-2", "host-a")
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base=diff-lic-1&compare=diff-lic-2", nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLicenceMiddleware_NilGuardAllowsAll(t *testing.T) {
	srv, db := testServer(t) // testServer has no Guard → nil
	s1 := testScanResult("nilg-1", "host-a")
	s2 := testScanResult("nilg-2", "host-a")
	require.NoError(t, db.SaveScan(context.Background(), s1))
	require.NoError(t, db.SaveScan(context.Background(), s2))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/diff?base=nilg-1&compare=nilg-2", nil)
	srv.Router().ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code, "nil guard should allow all requests")
}

func TestLicenceMiddleware_BlocksSarifReportForPro(t *testing.T) {
	srv, db := testServerWithGuard(t, license.TierPro)
	require.NoError(t, db.SaveScan(context.Background(), testScanResult("rpt-lic", "host-a")))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/reports/rpt-lic/sarif", nil)
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
