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

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
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

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
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

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
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

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/agents/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `[]`, rec.Body.String())
}

func TestAgentsAdmin_Revoke_EndToEnd(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	// Enrol an agent so we have a row + serial to revoke.
	enrolReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":"edge-01"}`))
	enrolRec := httptest.NewRecorder()
	srv.ServeHTTP(enrolRec, enrolReq)
	require.Equal(t, http.StatusOK, enrolRec.Code)

	// Fish out the agent ID from the persisted row (List returns one).
	list, err := agentStore.List(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	agent := list[0]
	serial := agent.CertSerial

	// Revoke via DELETE.
	revokeReq := httptest.NewRequest(http.MethodDelete,
		"/api/v1/admin/agents/"+agent.ID.String(), nil)
	revokeRec := httptest.NewRecorder()
	srv.ServeHTTP(revokeRec, revokeReq)
	assert.Equal(t, http.StatusNoContent, revokeRec.Code)

	// Agent row must be flipped to revoked.
	got, err := agentStore.Get(context.Background(), agent.ID)
	require.NoError(t, err)
	assert.Equal(t, agents.StatusRevoked, got.Status)

	// CA revocation row must be present + IsRevoked must return true
	// immediately (Revoke invalidates the cache).
	revoked, err := caStore.IsRevoked(context.Background(), serial)
	require.NoError(t, err)
	assert.True(t, revoked, "cert serial must be revoked after DELETE")
}

func TestAgentsAdmin_Revoke_NotFound(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	id := uuid.Must(uuid.NewV7())
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/agents/"+id.String(), nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAgentsAdmin_Get_NotFound(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	id := uuid.Must(uuid.NewV7())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/agents/"+id.String(), nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestAdminHandlers_DispatchCommand_HappyPath asserts that a well-formed
// POST to /admin/agents/{id}/commands returns 202 and the command is
// retrievable via PopCommand.
func TestAdminHandlers_DispatchCommand_HappyPath(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst-dispatch")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	// Enrol an agent first so a valid row exists.
	enrolReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":"dispatch-target"}`))
	enrolRec := httptest.NewRecorder()
	srv.ServeHTTP(enrolRec, enrolReq)
	require.Equal(t, http.StatusOK, enrolRec.Code, "enrol: %s", enrolRec.Body.String())

	list, err := agentStore.List(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	agentID := list[0].ID

	// Dispatch a command.
	body := strings.NewReader(`{"scan_profile":"standard","job_id":"job-123"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/agents/"+agentID.String()+"/commands", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusAccepted, rec.Code, "body=%s", rec.Body.String())

	// Verify the command is stored and poppable.
	cmd, err := agentStore.PopCommand(context.Background(), agentID)
	require.NoError(t, err)
	require.NotNil(t, cmd)
	assert.Equal(t, "standard", cmd.ScanProfile)
	assert.Equal(t, "job-123", cmd.JobID)
}

// TestAdminHandlers_DispatchCommand_MissingProfile asserts 400 when
// scan_profile is absent from the request body.
func TestAdminHandlers_DispatchCommand_MissingProfile(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst-dispatch-badprofile")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	enrolReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":"target-noprofile"}`))
	enrolRec := httptest.NewRecorder()
	srv.ServeHTTP(enrolRec, enrolReq)
	require.Equal(t, http.StatusOK, enrolRec.Code)

	list, err := agentStore.List(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	agentID := list[0].ID

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/agents/"+agentID.String()+"/commands",
		strings.NewReader(`{"job_id":"job-only"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestAdminHandlers_DispatchCommand_NotFound asserts 404 when the agent
// UUID does not exist.
func TestAdminHandlers_DispatchCommand_NotFound(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst-dispatch-notfound")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	id := uuid.Must(uuid.NewV7())
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/agents/"+id.String()+"/commands",
		strings.NewReader(`{"scan_profile":"quick"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestAdminHandlers_DispatchCommand_BadJSON asserts 400 on malformed body.
func TestAdminHandlers_DispatchCommand_BadJSON(t *testing.T) {
	pool := newTestPool(t)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	_, err := caStore.Bootstrap(context.Background(), "inst-dispatch-badjson")
	require.NoError(t, err)

	h := agents.NewAdminHandlers(caStore, agentStore, "https://localhost:8443", 60*time.Second, nil)
	srv := mountEnrol(t, h)

	id := uuid.Must(uuid.NewV7())
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/admin/agents/"+id.String()+"/commands",
		strings.NewReader(`not-json`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
