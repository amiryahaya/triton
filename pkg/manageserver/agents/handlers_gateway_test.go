//go:build integration

package agents_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
)

// bundleFiles holds the three PEM blobs an agent needs after unpacking
// its bundle.tar.gz. Plus the gateway URL the config.yaml advertises,
// so tests don't have to re-derive it.
type bundleFiles struct {
	clientCertPEM []byte
	clientKeyPEM  []byte
	caCertPEM     []byte
}

// unpackBundle reads the tar.gz bytes the enrol endpoint returns and
// extracts the three files the agent cares about. Ignores config.yaml
// since the test already knows the gateway URL.
func unpackBundle(t *testing.T, raw []byte) bundleFiles {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	defer func() { _ = gz.Close() }()

	out := bundleFiles{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		body, err := io.ReadAll(tr)
		require.NoError(t, err)
		switch hdr.Name {
		case "client.crt":
			out.clientCertPEM = body
		case "client.key":
			out.clientKeyPEM = body
		case "ca.crt":
			out.caCertPEM = body
		}
	}
	require.NotEmpty(t, out.clientCertPEM, "bundle must contain client.crt")
	require.NotEmpty(t, out.clientKeyPEM, "bundle must contain client.key")
	require.NotEmpty(t, out.caCertPEM, "bundle must contain ca.crt")
	return out
}

// gatewayFixture spins the :8443 listener on an ephemeral port with the
// given stores and returns (url, closer). All the plumbing — CA
// bootstrap, server leaf, TLS config — is done here so individual
// tests stay focused on their assertion.
type gatewayFixture struct {
	URL          string
	CaStore      *ca.PostgresStore
	AgentStore   *agents.PostgresStore
	ResultsStore scanresults.Store
	Bundle       bundleFiles
	AdminSrv     http.Handler
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	pool := newTestPool(t)

	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)
	resultsStore := scanresults.NewPostgresStore(pool)

	_, err := caStore.Bootstrap(context.Background(), "inst-gw")
	require.NoError(t, err)

	// Server leaf signed for 127.0.0.1 so the loopback TLS handshake's
	// SNI match succeeds without DNS trickery.
	serverCert, err := caStore.IssueServerCert(context.Background(), "127.0.0.1")
	require.NoError(t, err)

	caBundle, err := caStore.Load(context.Background())
	require.NoError(t, err)
	clientPool := x509.NewCertPool()
	require.True(t, clientPool.AppendCertsFromPEM(caBundle.CACertPEM))

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
		Certificates: []tls.Certificate{serverCert},
	}

	gatewayHandlers := agents.NewGatewayHandlers(caStore, agentStore, resultsStore)
	gr := chi.NewRouter()
	gr.Route("/api/v1/gateway", func(r chi.Router) {
		r.Use(agents.MTLSCNAuth("agent:", caStore))
		agents.MountGatewayRoutes(r, gatewayHandlers)
	})

	// Ephemeral port so parallel tests don't clash on :8443.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	require.NoError(t, err)

	srv := &http.Server{Handler: gr, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
	})

	// Admin handler on top of the same stores so tests can enrol + revoke
	// without a second TLS listener. Not the real server — just enough
	// to serve /enrol + /agents/{id}.
	adminHandlers := agents.NewAdminHandlers(caStore, agentStore,
		"https://127.0.0.1"+portFromAddr(ln.Addr()), 60*time.Second)
	ar := chi.NewRouter()
	ar.Route("/api/v1/admin/agents", func(r chi.Router) {
		agents.MountAdminRoutes(r, adminHandlers)
	})
	ar.Route("/api/v1/admin/enrol", func(r chi.Router) {
		agents.MountEnrolRoutes(r, adminHandlers)
	})

	fix := &gatewayFixture{
		URL:          "https://127.0.0.1" + portFromAddr(ln.Addr()),
		CaStore:      caStore,
		AgentStore:   agentStore,
		ResultsStore: resultsStore,
		AdminSrv:     ar,
	}
	return fix
}

// portFromAddr extracts ":12345" from a net.Addr string like
// "127.0.0.1:12345". Used to paste the ephemeral port onto the gateway
// base URL.
func portFromAddr(addr net.Addr) string {
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return ":" + port
}

// enrolAgent uses the admin handler chain to onboard an agent and
// returns the unpacked bundle + admin-side agent ID.
func (f *gatewayFixture) enrolAgent(t *testing.T, name string) bundleFiles {
	t.Helper()
	// httptest.NewRecorder + direct ServeHTTP — no HTTP listener needed
	// for the admin plane here.
	req, err := http.NewRequest(http.MethodPost, "/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":"`+name+`"}`))
	require.NoError(t, err)
	rr := &testRecorder{header: http.Header{}, body: &bytes.Buffer{}, status: 200}
	f.AdminSrv.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.status, "enrol failed: %s", rr.body.String())
	return unpackBundle(t, rr.body.Bytes())
}

// testRecorder is httptest.NewRecorder with an explicit body buffer we
// can hand to unpackBundle. Minimal — only WriteHeader + Write required.
type testRecorder struct {
	header http.Header
	body   *bytes.Buffer
	status int
}

func (r *testRecorder) Header() http.Header        { return r.header }
func (r *testRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *testRecorder) WriteHeader(s int)           { r.status = s }

// mTLSClient returns an http.Client configured with the bundle's
// client cert + trusting the bundle's CA. The agent running in the
// field does exactly this with the unpacked bundle on disk.
func mTLSClient(t *testing.T, b bundleFiles) *http.Client {
	t.Helper()
	clientPair, err := tls.X509KeyPair(b.clientCertPEM, b.clientKeyPEM)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(b.caCertPEM))

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientPair},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}
}

func TestGateway_PhoneHome_ViaBundleCert(t *testing.T) {
	f := newGatewayFixture(t)
	bundle := f.enrolAgent(t, "edge-01")
	client := mTLSClient(t, bundle)

	resp, err := client.Post(f.URL+"/api/v1/gateway/agents/phone-home",
		"application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])

	// Agent should now be active in the DB with last_seen_at populated.
	list, err := f.AgentStore.List(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, agents.StatusActive, list[0].Status)
	require.NotNil(t, list[0].LastSeenAt)
}

func TestGateway_RejectsRevokedCert(t *testing.T) {
	f := newGatewayFixture(t)
	bundle := f.enrolAgent(t, "edge-01")
	client := mTLSClient(t, bundle)

	// Happy-path dial seeds the agent to active state.
	resp1, err := client.Post(f.URL+"/api/v1/gateway/agents/phone-home",
		"application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	_ = resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	// Revoke via admin path.
	list, err := f.AgentStore.List(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	agent := list[0]
	revokeReq, err := http.NewRequest(http.MethodDelete,
		"/api/v1/admin/agents/"+agent.ID.String(), nil)
	require.NoError(t, err)
	rr := &testRecorder{header: http.Header{}, body: &bytes.Buffer{}, status: 200}
	f.AdminSrv.ServeHTTP(rr, revokeReq)
	require.Equal(t, http.StatusNoContent, rr.status)

	// Force cache refresh so the 30s TTL doesn't hide the revocation.
	require.NoError(t, f.CaStore.RefreshRevocationCache(context.Background()))

	// Next dial must 401.
	resp2, err := client.Post(f.URL+"/api/v1/gateway/agents/phone-home",
		"application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestGateway_IngestScan_Enqueues(t *testing.T) {
	f := newGatewayFixture(t)
	bundle := f.enrolAgent(t, "edge-01")
	client := mTLSClient(t, bundle)

	scanBody := []byte(`{
		"id":"00000000-0000-0000-0000-000000000000",
		"metadata":{"hostname":"edge-01","os":"linux","scanProfile":"quick","timestamp":"2026-04-19T00:00:00Z"},
		"systems":[],
		"findings":[],
		"summary":{}
	}`)

	resp, err := client.Post(f.URL+"/api/v1/gateway/agents/scans",
		"application/json", bytes.NewReader(scanBody))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Queue depth should reflect the agent submission.
	depth, err := f.ResultsStore.QueueDepth(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), depth)

	// ClaimDue returns the row with null scan_job_id + agent source.
	rows, err := f.ResultsStore.ClaimDue(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Nil(t, rows[0].ScanJobID, "agent-submitted rows carry NULL scan_job_id")
	assert.Equal(t, "agent", rows[0].SourceType)
}

func TestGateway_IngestFindings_Acks(t *testing.T) {
	f := newGatewayFixture(t)
	bundle := f.enrolAgent(t, "edge-01")
	client := mTLSClient(t, bundle)

	resp, err := client.Post(f.URL+"/api/v1/gateway/agents/findings",
		"application/json", bytes.NewReader([]byte(`[]`)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}
