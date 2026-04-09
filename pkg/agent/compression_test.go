package agent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// TestSubmit_CompressionDefault verifies that a fresh Client from
// New() has CompressSubmissions enabled and sends gzipped bodies
// with Content-Encoding: gzip. This is the production default and
// the reason the feature exists — smaller wire payloads.
func TestSubmit_CompressionDefault(t *testing.T) {
	var gotEncoding string
	var gotContentType string
	var decoded model.ScanResult

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		gotContentType = r.Header.Get("Content-Type")

		// Must be able to decode the body as gzip — if the client
		// advertised gzip but sent plaintext, this fails loudly.
		gz, err := gzip.NewReader(r.Body)
		require.NoError(t, err, "request body must be a valid gzip stream")
		defer func() { _ = gz.Close() }()

		require.NoError(t, json.NewDecoder(gz).Decode(&decoded))

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(SubmitResponse{ID: decoded.ID, Status: "saved"})
	}))
	defer server.Close()

	// Default-constructed Client: compression should be ON.
	client := New(server.URL)
	require.True(t, client.CompressSubmissions, "New() must default to compression enabled")

	_, err := client.Submit(context.Background(), testScanResult())
	require.NoError(t, err)

	assert.Equal(t, "gzip", gotEncoding, "Content-Encoding must be gzip")
	assert.Equal(t, "application/json", gotContentType, "Content-Type must stay application/json")
	assert.Equal(t, "agent-test-1", decoded.ID, "decoded body must match the original scan result")
}

// TestSubmit_CompressionDisabledBackwardCompat verifies that
// CompressSubmissions=false preserves the pre-A10 wire format:
// plain JSON body, no Content-Encoding header. This is the
// backward-compatibility escape hatch for servers that can't
// handle gzip.
func TestSubmit_CompressionDisabledBackwardCompat(t *testing.T) {
	var gotEncoding string
	var decoded model.ScanResult

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")

		// With compression disabled, body must decode as plain JSON.
		require.NoError(t, json.NewDecoder(r.Body).Decode(&decoded))

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(SubmitResponse{ID: decoded.ID, Status: "saved"})
	}))
	defer server.Close()

	client := New(server.URL)
	client.CompressSubmissions = false

	_, err := client.Submit(context.Background(), testScanResult())
	require.NoError(t, err)

	assert.Empty(t, gotEncoding, "Content-Encoding must be absent when compression is disabled")
	assert.Equal(t, "agent-test-1", decoded.ID)
}

// TestSubmit_CompressionShrinksPayload is a sanity check that
// compression actually reduces the on-wire byte count for a
// realistic scan result with repetitive fields. The exact ratio
// varies by content but a typical scan with 100+ findings should
// compress to under 30% of its plain-JSON size.
func TestSubmit_CompressionShrinksPayload(t *testing.T) {
	// Build a scan with enough repetitive content that gzip has
	// something to work with. Pure-random bytes wouldn't compress.
	findings := make([]model.Finding, 200)
	for i := range findings {
		findings[i] = model.Finding{
			ID: "finding-shared-id-for-test-compression",
			Source: model.FindingSource{
				Type:            "file",
				Path:            "/usr/lib/libcrypto.so.1.1",
				DetectionMethod: "library-linkage",
			},
			CryptoAsset: &model.CryptoAsset{
				Algorithm: "RSA-2048",
				PQCStatus: "TRANSITIONAL",
				Purpose:   "TLS handshake — web server identity binding",
			},
			Module: "library",
		}
	}
	scan := &model.ScanResult{
		ID:       "compression-test",
		Metadata: model.ScanMetadata{Hostname: "compress-host", ScanProfile: "comprehensive"},
		Findings: findings,
	}

	var plainSize, gzipSize int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") == "gzip" {
			b, _ := io.ReadAll(r.Body)
			gzipSize = len(b)
		} else {
			b, _ := io.ReadAll(r.Body)
			plainSize = len(b)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"compression-test","status":"saved"}`))
	}))
	defer server.Close()

	// First: plaintext submission measures the baseline size.
	plainClient := New(server.URL)
	plainClient.CompressSubmissions = false
	_, err := plainClient.Submit(context.Background(), scan)
	require.NoError(t, err)

	// Second: gzip submission measures the compressed size.
	gzipClient := New(server.URL)
	// CompressSubmissions=true by default
	_, err = gzipClient.Submit(context.Background(), scan)
	require.NoError(t, err)

	require.Greater(t, plainSize, 0, "plaintext request must have been observed")
	require.Greater(t, gzipSize, 0, "gzip request must have been observed")

	t.Logf("plain=%d bytes, gzip=%d bytes, ratio=%.1f%%",
		plainSize, gzipSize, float64(gzipSize)/float64(plainSize)*100)

	// Repetitive content compresses hard. Assert gzip is less
	// than half the plaintext size as a conservative floor —
	// in practice it's 5-10% for this fixture.
	assert.Less(t, gzipSize, plainSize/2,
		"gzip should shrink repetitive scan payloads by >50%%")
}
