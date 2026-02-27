package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testScanResult() *model.ScanResult {
	return &model.ScanResult{
		ID: "agent-test-1",
		Metadata: model.ScanMetadata{
			Timestamp:   time.Now().UTC().Truncate(time.Second),
			Hostname:    "agent-host",
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

func TestSubmit_Success(t *testing.T) {
	var receivedScan model.ScanResult

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/scans", r.URL.Path)
		assert.Equal(t, "test-key", r.Header.Get("X-Triton-API-Key"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		err := json.NewDecoder(r.Body).Decode(&receivedScan)
		require.NoError(t, err)

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(SubmitResponse{ID: receivedScan.ID, Status: "saved"})
	}))
	defer server.Close()

	client := New(server.URL, "test-key")
	resp, err := client.Submit(testScanResult())
	require.NoError(t, err)

	assert.Equal(t, "agent-test-1", resp.ID)
	assert.Equal(t, "saved", resp.Status)
	assert.Equal(t, "agent-test-1", receivedScan.ID)
}

func TestSubmit_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := New(server.URL, "")
	_, err := client.Submit(testScanResult())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestSubmit_NoAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("X-Triton-API-Key"))
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(SubmitResponse{ID: "test", Status: "saved"})
	}))
	defer server.Close()

	client := New(server.URL, "")
	resp, err := client.Submit(testScanResult())
	require.NoError(t, err)
	assert.Equal(t, "saved", resp.Status)
}

func TestHealthcheck_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := New(server.URL, "")
	err := client.Healthcheck()
	assert.NoError(t, err)
}

func TestHealthcheck_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := New(server.URL, "")
	err := client.Healthcheck()
	assert.Error(t, err)
}

func TestSubmit_ConnectionRefused(t *testing.T) {
	client := New("http://127.0.0.1:1", "")
	_, err := client.Submit(testScanResult())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sending request")
}
