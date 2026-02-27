package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testServer(t *testing.T) (*Server, *store.SQLiteStore) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := store.NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cfg := &Config{
		ListenAddr: ":0",
	}
	srv := New(cfg, db)
	return srv, db
}

func testServerWithAuth(t *testing.T) (*Server, *store.SQLiteStore) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := store.NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

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
			Timestamp:   time.Now().UTC().Truncate(time.Second),
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
