package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoHandler is a minimal handler that reads the whole request
// body and writes it back. Gzip middleware tests use it to verify
// the body that reaches the handler matches the original plaintext
// regardless of whether the client sent gzip or not.
var echoHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
})

func TestGzipDecode_DecodesGzippedRequest(t *testing.T) {
	original := []byte(`{"hello":"world","count":42,"repeated":"this string is repeated here and here and here for compression"}`)

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, err := gz.Write(original)
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	req := httptest.NewRequest(http.MethodPost, "/test", &compressed)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler := GzipDecodeMiddleware(echoHandler)
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, string(original), rec.Body.String(),
		"handler must see the decompressed body exactly as the client sent it")

	// Content-Encoding header must be stripped so downstream code
	// doesn't think the body is still gzipped.
	assert.Empty(t, req.Header.Get("Content-Encoding"))
}

func TestGzipDecode_PassesThroughPlaintextRequest(t *testing.T) {
	original := []byte(`{"hello":"world"}`)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(original))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler := GzipDecodeMiddleware(echoHandler)
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, string(original), rec.Body.String(),
		"plaintext requests must reach the handler unchanged")
}

func TestGzipDecode_CaseInsensitiveEncodingHeader(t *testing.T) {
	// HTTP headers are case-insensitive; the middleware should
	// handle GZIP, Gzip, gZIP, etc.
	cases := []string{"gzip", "GZIP", "Gzip", "gZiP"}
	for _, enc := range cases {
		t.Run(enc, func(t *testing.T) {
			original := []byte(`{"enc":"` + enc + `"}`)

			var compressed bytes.Buffer
			gz := gzip.NewWriter(&compressed)
			_, _ = gz.Write(original)
			_ = gz.Close()

			req := httptest.NewRequest(http.MethodPost, "/test", &compressed)
			req.Header.Set("Content-Encoding", enc)
			rec := httptest.NewRecorder()

			GzipDecodeMiddleware(echoHandler).ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, string(original), rec.Body.String())
		})
	}
}

func TestGzipDecode_MalformedGzipReturns400(t *testing.T) {
	// Send a body that is NOT valid gzip — we claim gzip in the
	// header so the middleware tries to decode and fails.
	req := httptest.NewRequest(http.MethodPost, "/test",
		strings.NewReader("this is not a gzip stream at all"))
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()

	GzipDecodeMiddleware(echoHandler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"malformed gzip must return 400 — it's a client error")
	assert.Contains(t, rec.Body.String(), "invalid gzip")
}

func TestGzipDecode_EmptyBody(t *testing.T) {
	// Some request types (GET, HEAD) have no body. The middleware
	// should pass them through without attempting decode even if
	// Content-Encoding happens to be set.
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	rec := httptest.NewRecorder()

	GzipDecodeMiddleware(echoHandler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code,
		"empty body requests should pass through cleanly")
}

// TestGzipDecode_OtherEncodingPassesThrough confirms that a
// Content-Encoding header set to something other than "gzip"
// (e.g. "br" for brotli) causes the middleware to leave the
// request alone. The handler then receives the body as-is and
// must handle the encoding itself — we don't claim to decode
// every encoding, only gzip.
func TestGzipDecode_OtherEncodingPassesThrough(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test",
		strings.NewReader("opaque payload"))
	req.Header.Set("Content-Encoding", "br")
	rec := httptest.NewRecorder()

	GzipDecodeMiddleware(echoHandler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "opaque payload", rec.Body.String(),
		"non-gzip Content-Encoding must pass through without modification")
	assert.Equal(t, "br", req.Header.Get("Content-Encoding"),
		"non-gzip encoding header must be preserved so the handler can act on it")
}
