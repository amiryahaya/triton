package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
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
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		err := json.NewDecoder(r.Body).Decode(&receivedScan)
		require.NoError(t, err)

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(SubmitResponse{ID: receivedScan.ID, Status: "saved"})
	}))
	defer server.Close()

	// This test uses a manual httptest handler that decodes the body
	// as plaintext JSON — opt out of compression so it doesn't have
	// to decode gzip. Compression has its own dedicated tests below.
	client := New(server.URL)
	client.CompressSubmissions = false
	resp, err := client.Submit(context.Background(), testScanResult())
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

	// Use fast-retry tuning — 5xx is retryable, so the default
	// 1s/4s backoff would make this test take ~5 seconds.
	client := fastRetryClient(server.URL)
	_, err := client.Submit(context.Background(), testScanResult())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestSubmit_NoAuth(t *testing.T) {
	// Agent with no license token set — submit goes through
	// unauthenticated (single-tenant deployments use this path).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("X-Triton-License-Token"))
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(SubmitResponse{ID: "test", Status: "saved"})
	}))
	defer server.Close()

	// This test doesn't decode the body so compression would work
	// too — but opt out for consistency with the other header-only
	// tests. The dedicated compression tests cover the on-path.
	client := New(server.URL)
	client.CompressSubmissions = false
	resp, err := client.Submit(context.Background(), testScanResult())
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

	client := New(server.URL)
	err := client.Healthcheck()
	assert.NoError(t, err)
}

func TestHealthcheck_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := New(server.URL)
	err := client.Healthcheck()
	assert.Error(t, err)
}

func TestSubmit_ConnectionRefused(t *testing.T) {
	// Use fast-retry tuning so the test exercises the 3-attempt
	// retry path without the 1s/4s production backoff schedule.
	client := fastRetryClient("http://127.0.0.1:1")
	_, err := client.Submit(context.Background(), testScanResult())
	assert.Error(t, err)
	// Connection refused is retryable, so the error is wrapped with the
	// attempt count after the final attempt.
	assert.Contains(t, err.Error(), "after 3 attempts")
}

// fastRetryClient is a test helper that collapses the retry backoff
// to near-zero so retry-path tests don't take tens of seconds. Tests
// must assert on attempt counts / outcomes, not on wall-clock timing.
//
// Also disables CompressSubmissions so tests using manual httptest
// handlers don't have to decode gzip. A dedicated compression test
// covers the on-path; every OTHER test is testing retry logic,
// headers, or status codes, not the wire format.
func fastRetryClient(serverURL string) *Client {
	c := New(serverURL)
	c.RetryInitialBackoff = 1 * time.Millisecond
	c.RetryMaxAttempts = 3
	c.CompressSubmissions = false
	return c
}

func TestSubmit_RetriesOn500ThenSucceeds(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(SubmitResponse{ID: "r1", Status: "saved"})
	}))
	defer server.Close()

	resp, err := fastRetryClient(server.URL).Submit(context.Background(), testScanResult())
	require.NoError(t, err)
	assert.Equal(t, "saved", resp.Status)
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts), "should have made 3 attempts")
}

func TestSubmit_DoesNotRetryOn400(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad input"}`))
	}))
	defer server.Close()

	_, err := fastRetryClient(server.URL).Submit(context.Background(), testScanResult())
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attempts), "4xx must not retry")
	assert.Contains(t, err.Error(), "400")
}

func TestSubmit_DoesNotRetryOn401(t *testing.T) {
	// Auth errors are terminal — retrying a bad token just wastes
	// attempts and can trigger rate limiters on the server side.
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := fastRetryClient(server.URL).Submit(context.Background(), testScanResult())
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attempts))
}

func TestSubmit_GivesUpAfterMaxAttempts(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := fastRetryClient(server.URL).Submit(context.Background(), testScanResult())
	require.Error(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts))
	assert.Contains(t, err.Error(), "after 3 attempts")
}

func TestSubmit_HonorsRetryAfter(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			// Retry-After "0" means "retry immediately" — tests
			// whether the header is parsed at all, without making
			// the test slow.
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(SubmitResponse{ID: "r2", Status: "saved"})
	}))
	defer server.Close()

	resp, err := fastRetryClient(server.URL).Submit(context.Background(), testScanResult())
	require.NoError(t, err)
	assert.Equal(t, "saved", resp.Status)
	assert.Equal(t, int32(2), atomic.LoadInt32(&attempts))
}

func TestSubmit_RespectsContextCancellation(t *testing.T) {
	// Server always 500s; context is canceled after the first attempt
	// so the retry loop exits early instead of burning all 3 attempts.
	var attempts int32
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		cancel() // trigger cancellation mid-retry
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := fastRetryClient(server.URL)
	// Give the retry loop a visible backoff window so the cancel beats it.
	client.RetryInitialBackoff = 200 * time.Millisecond
	_, err := client.Submit(ctx, testScanResult())
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.LessOrEqual(t, atomic.LoadInt32(&attempts), int32(2),
		"should have stopped retrying when ctx was canceled")
}
