//go:build integration

package agents_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
)

// mountEnrol wires MountAdminRoutes + MountEnrolRoutes for handler
// tests. Mirrors the production wiring in server.go.
func mountEnrol(t *testing.T, h *agents.AdminHandlers) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	r.Route("/api/v1/admin/agents", func(r chi.Router) {
		agents.MountAdminRoutes(r, h)
	})
	r.Route("/api/v1/admin/enrol", func(r chi.Router) {
		agents.MountEnrolRoutes(r, h)
	})
	return r
}

func TestAgentsAdmin_Enrol_Returns_Gzip(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)

	// Bootstrap the CA so Enrol can load + sign.
	_, err := caStore.Bootstrap(context.Background(), "inst-test")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second)
	srv := mountEnrol(t, h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":"edge-01"}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	assert.Equal(t, "application/x-gzip", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "agent-")
	assert.Contains(t, rec.Header().Get("Content-Disposition"), ".tar.gz")

	// Unpack the bundle to prove it's real — not just a length check.
	gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	require.NoError(t, err)
	tr := tar.NewReader(gz)

	found := map[string]bool{}
	var clientCert []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		body, err := io.ReadAll(tr)
		require.NoError(t, err)
		found[hdr.Name] = true
		if hdr.Name == "client.crt" {
			clientCert = body
		}
	}
	assert.True(t, found["client.crt"], "bundle must contain client.crt")
	assert.True(t, found["client.key"], "bundle must contain client.key")
	assert.True(t, found["ca.crt"], "bundle must contain ca.crt")
	assert.True(t, found["config.yaml"], "bundle must contain config.yaml")

	// The leaf CN must be "agent:<uuid>" — matches what the gateway
	// mTLS middleware expects to see.
	block, _ := pem.Decode(clientCert)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(leaf.Subject.CommonName, "agent:"),
		"leaf CN must have agent: prefix, got %q", leaf.Subject.CommonName)

	// The agent row must be persisted with that serial.
	serial := leaf.SerialNumber.Text(16)
	got, err := agentStore.GetByCertSerial(context.Background(), serial)
	require.NoError(t, err)
	assert.Equal(t, "edge-01", got.Name)
	assert.Equal(t, agents.StatusPending, got.Status)
}

func TestAgentsAdmin_Enrol_MissingName(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second)
	srv := mountEnrol(t, h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":""}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAgentsAdmin_Enrol_CAUnbootstrapped_503(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	// Intentionally skip Bootstrap.

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second)
	srv := mountEnrol(t, h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":"edge-01"}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestAgentsAdmin_List_Empty(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second)
	srv := mountEnrol(t, h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/agents/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `[]`, rec.Body.String())
}

func TestAgentsAdmin_Get_NotFound(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second)
	srv := mountEnrol(t, h)

	id := uuid.Must(uuid.NewV7())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/agents/"+id.String(), nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
