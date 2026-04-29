//go:build integration

// Manage Server — end-to-end scan flow exercising the Batch I container
// plumbing for the full B2.2 pipeline.
//
// This file is the load-bearing integration gate for Manage Server B2.2:
// it stands up a real manageserver.Server via New() + Run(), backed by
// a dedicated PostgreSQL schema, and drives the setup → auto-enrol →
// agent enrolment → mTLS gateway → scan ingestion → drain pipeline
// end-to-end against stub License + Report servers.
//
// Scope is split across THREE linked subtests so each one can fail in
// isolation and so CI-time cost stays bounded. The alternative — one
// 30-second monolith — hides the failing stage behind a single red X.
//
//   1. TestManageE2E_SetupAndAutoEnrol
//      Setup admin + licence → stub License Server returns a valid
//      Ed25519-signed token → auto-enrol with stub Report → verify
//      manage_push_creds + manage_ca are populated.
//
//   2. TestManageE2E_AgentGatewayMTLS
//      Enrol an agent → download bundle → dial the live :8443 gateway
//      with the bundle's client cert → phone-home returns 200.
//
//   3. TestManageE2E_DrainToReportMTLS
//      Stub Report enforces mTLS with CN=manage:… and asserts the
//      submitted_by.type==manage envelope → manually enqueue a scan
//      result → wait for drain to push → verify queue empty +
//      Report stub received the POST.
//
// Step 10 of the plan (revocation post-enrolment) is covered by
// TestManageE2E_GatewayRevocation in (2) — after the happy phone-home,
// revoke the agent, force RefreshRevocationCache, re-dial, assert 401.
//
// The orchestrator → drain full pipeline (steps 7-9 of the plan) is
// covered at a more focused unit level in the pkg/manageserver/scanjobs
// + pkg/manageserver/scanresults test packages. Running a real
// pkg/scanner scan through Manage's full stack is too slow+flaky for
// this test (several seconds per job + host-environment dependent);
// instead, step (3) above exercises the drain + mTLS push assertion
// by enqueueing directly, which is what the orchestrator would do on
// a successful job.

package integration_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
	"github.com/amiryahaya/triton/pkg/managestore"
	"github.com/amiryahaya/triton/pkg/model"
)

// e2eSchemaSeq monotonically allocates unique schemas so this file can
// run concurrently alongside manage_setup_test.go, manage_boot_test.go,
// and the pkg/manageserver/*_test.go packages without schema collisions.
var e2eSchemaSeq atomic.Int64

// e2eJWTKey is a fixed 32-byte HS256 secret for the E2E tests.
var e2eJWTKey = []byte("manage-e2e-jwt-signing-key-32byt")

// reportEnrolStub extends the auto-enrol stub with an mTLS-enforcing
// /api/v1/scans endpoint. It returns a real bundle signed by a test CA
// so Manage's bundle parser accepts the response, and then enforces mTLS
// on scan submissions so the drain's cert presentation is observable.
//
// The stub is split into TWO listeners deliberately:
//   - httpSrv (plain HTTP) serves /api/v1/admin/enrol/manage during the
//     auto-enrol step, because Manage's ReportServer URL for auto-enrol
//     is unauthenticated by design (service-key header in-band). Using
//     mTLS here would require Manage to already have a client cert
//     which is exactly what auto-enrol mints.
//   - mtlsSrv (TLS + RequireAnyClientCert) serves /api/v1/scans during
//     drain. Manage presents the leaf it got back from auto-enrol, and
//     the stub asserts the CN starts with "manage:".
//
// Both URLs are wired into the bundle Manage receives so auto-enrol
// stamps the mTLS URL into manage_push_creds.report_url.
type reportEnrolStub struct {
	httpSrv      *httptest.Server
	mtlsSrv      *httptest.Server
	serviceKey   string
	caCertPEM    []byte
	caPriv       *ecdsa.PrivateKey
	caCert       *x509.Certificate
	tenantID     string
	reqCount     atomic.Int64 // /admin/enrol/manage calls
	scanReqCount atomic.Int64 // /api/v1/scans calls
	lastScanCN   atomic.Value // string — CN on the last mTLS-verified POST
	lastScanBody atomic.Value // []byte — last JSON body
}

// newReportEnrolStub stands up the two-listener Report stub. The CA in
// memory signs BOTH the mTLS server leaf AND the client leaf Manage
// gets in its bundle — same CA for trust simplicity. In production
// the server and client certs chain to different CAs, but for test
// purposes this is enough to prove the wire contract.
func newReportEnrolStub(t *testing.T, serviceKey, tenantID string) *reportEnrolStub {
	t.Helper()
	s := &reportEnrolStub{serviceKey: serviceKey, tenantID: tenantID}

	// CA keypair that signs the Report mTLS server leaf + the client
	// leaf handed back to Manage via auto-enrol bundle.
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "E2E Report CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	s.caPriv = caPriv
	s.caCert = caCert
	s.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// --- plain HTTP enrol stub ---
	enrolMux := http.NewServeMux()
	enrolMux.HandleFunc("/api/v1/admin/enrol/manage", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Triton-Service-Key") != s.serviceKey {
			http.Error(w, "bad service key", http.StatusForbidden)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		instanceID := body["manage_instance_id"]
		pubPEM := body["public_key_pem"]
		if instanceID == "" || pubPEM == "" {
			http.Error(w, "missing fields", http.StatusBadRequest)
			return
		}
		s.reqCount.Add(1)

		bundle, err := s.buildBundleWithPubPEM(instanceID, pubPEM)
		if err != nil {
			http.Error(w, "bundle: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	})
	s.httpSrv = httptest.NewServer(enrolMux)

	// --- mTLS /api/v1/scans stub ---
	// Server leaf signed by the same CA.
	serverPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serverSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serverTmpl := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "report-server.e2e.local"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverPriv.PublicKey, caPriv)
	require.NoError(t, err)
	serverLeaf := tls.Certificate{
		Certificate: [][]byte{serverDER},
		PrivateKey:  serverPriv,
	}

	mtlsMux := http.NewServeMux()
	mtlsMux.HandleFunc("/api/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		// Peer cert assertion — this is the load-bearing mTLS check for
		// the drain. RequireAnyClientCert makes a cert MANDATORY but
		// doesn't validate the chain; we walk the CN manually.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		if !strings.HasPrefix(cn, "manage:") {
			t.Errorf("stub Report: expected CN prefix 'manage:', got %q", cn)
			http.Error(w, "bad CN", http.StatusForbidden)
			return
		}
		s.lastScanCN.Store(cn)

		body, err := io.ReadAll(io.LimitReader(r.Body, 50<<20))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		s.lastScanBody.Store(body)

		// Assert the envelope shape up front so a schema drift surfaces
		// as a test failure rather than a silent 200.
		var env map[string]any
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		sb, ok := env["submitted_by"].(map[string]any)
		if !ok {
			t.Errorf("stub Report: missing submitted_by envelope: %s", string(body))
			http.Error(w, "bad envelope", http.StatusBadRequest)
			return
		}
		if sb["type"] != "manage" {
			t.Errorf("stub Report: expected submitted_by.type=manage, got %v", sb["type"])
			http.Error(w, "bad envelope type", http.StatusBadRequest)
			return
		}

		s.scanReqCount.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	s.mtlsSrv = httptest.NewUnstartedServer(mtlsMux)
	s.mtlsSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverLeaf},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	s.mtlsSrv.StartTLS()
	return s
}

// buildBundleWithPubPEM signs Manage's ECDSA public key with the stub
// CA and returns a tar.gz containing client.crt + ca.crt + config.yaml.
// config.yaml's report_url must be the mTLS listener — that's what
// Manage stamps into manage_push_creds for the drain to use.
func (s *reportEnrolStub) buildBundleWithPubPEM(instanceID, pubPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("decode public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "manage:e2e-hash:" + instanceID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, s.caCert, pub, s.caPriv)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	cfg := fmt.Sprintf("manage_instance_id: %s\nreport_url: %s\ntenant_id: %s\n",
		instanceID, s.mtlsSrv.URL, s.tenantID)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Size: int64(len(data)), Mode: 0o644, ModTime: time.Now().UTC(),
		}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := add("client.crt", leafPEM); err != nil {
		return nil, err
	}
	if err := add("ca.crt", s.caCertPEM); err != nil {
		return nil, err
	}
	if err := add("config.yaml", []byte(cfg)); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *reportEnrolStub) Close() {
	s.httpSrv.Close()
	s.mtlsSrv.Close()
}

// manageE2EFixture spins a live Manage Server on an isolated PG schema
// with the :8443 gateway bound to an ephemeral port. The caller runs
// the HTTP flow against AdminURL (returned by httptest) and the
// gateway flow against GatewayURL (derived from the ephemeral port).
//
// Lifecycle note: Run() is NOT called by newManageE2EFixture. The
// gateway listener in Server.runGateway checks the CA at startup and
// disables itself if the CA isn't yet bootstrapped; /setup/license
// bootstraps the CA but does NOT re-trigger the listener. So the
// test's ordering has to be:
//
//   1. Construct fixture + complete setup via the admin Router (which
//      is served by httptest.Server wrapping srv.Router() directly —
//      not by Run()).
//   2. Call startRun() to fire srv.Run() AFTER the CA is bootstrapped.
//   3. Wait for gateway to come up.
//
// This matches the "operator restarts the process after first-time
// setup" production recovery path. Future work (outside Batch I scope)
// could make the gateway self-recover post-setup without a restart.
type manageE2EFixture struct {
	Server      *manageserver.Server
	Store       *managestore.PostgresStore
	AdminSrv    *httptest.Server
	AdminURL    string
	GatewayURL  string
	GatewayPort int
	LSStub      *httptest.Server
	ReportStub  *reportEnrolStub
	SignedToken string
	runCancel   context.CancelFunc
	runDone     chan struct{}
}

// newManageE2EFixture stands up the whole rig: Manage Server + admin
// HTTP + gateway mTLS + stub License + stub Report. Parameters that
// callers rarely need to customise are hardcoded; the few that do are
// passed in.
func newManageE2EFixture(t *testing.T) *manageE2EFixture {
	t.Helper()

	// Ed25519 keypair so the stub LS returns a token Manage can parse.
	// startLicence will only activate feature-gating if the token
	// parses cleanly against s.cfg.PublicKey. Tests that don't
	// exercise cap enforcement can tolerate a non-parseable token, but
	// we mint a real one here for realism.
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "e2e-manage-lic",
		Tier:      license.TierPro,
		Org:       "E2E",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	// Stub License Server — same stubLicenseServerConfig shape as
	// manage_setup_test.go. The token field is the pre-signed one
	// above; Manage persists it verbatim and startLicence parses it
	// against the matching pub.
	ls := newManageStubLicenseServer(t, stubLicenseServerConfig{
		signedToken:  signed,
		activationID: "e2e-activation",
		tier:         "pro",
		features:     licensestore.Features{Manage: true, Report: true},
	})

	// Stub Report Server — auto-enrol via plain HTTP + mTLS /scans via
	// TLS. tenantID is echoed back in bundle.yaml → manage_push_creds.
	reportStub := newReportEnrolStub(t, "e2e-service-key", "e2e-tenant")

	// Fresh Manage schema + store.
	schema := fmt.Sprintf("test_manage_e2e_%d", e2eSchemaSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getManageDBURL(), schema)
	if err != nil {
		// Skip — Postgres unavailable is not a test failure.
		t.Skipf("PostgreSQL unavailable: %v", err)
	}

	// Grab an ephemeral port for the gateway. The net.Listen/Close
	// dance is racy with any other process binding the same port in
	// the microsecond window, but in practice it's reliable on
	// loopback and is the standard way to discover a free port
	// without modifying manageserver.Server to accept a listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	gatewayAddr := ln.Addr().String()
	gatewayPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := &manageserver.Config{
		Listen:           ":0", // admin plane; we use httptest below for stable URL
		JWTSigningKey:    e2eJWTKey,
		PublicKey:        pub,
		SessionTTL:       time.Hour,
		GatewayListen:    fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		GatewayHostname:  "127.0.0.1",
		ManageGatewayURL: fmt.Sprintf("https://127.0.0.1:%d", gatewayPort),
		Parallelism:      4,
		ReportServer:     reportStub.httpSrv.URL,
		ReportServiceKey: reportStub.serviceKey,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	// Admin HTTP plane via httptest so the caller has a stable URL.
	// srv.Router() is served directly here — NOT via srv.Run(). This
	// lets the test complete /setup/admin + /setup/license (which
	// bootstraps the CA) BEFORE calling srv.Run(), which is necessary
	// because runGateway is a one-shot that disables the :8443
	// listener if the CA isn't present at startup.
	adminSrv := httptest.NewServer(srv.Router())

	fix := &manageE2EFixture{
		Server:      srv,
		Store:       store,
		AdminSrv:    adminSrv,
		AdminURL:    adminSrv.URL,
		GatewayURL:  fmt.Sprintf("https://%s", gatewayAddr),
		GatewayPort: gatewayPort,
		LSStub:      ls,
		ReportStub:  reportStub,
		SignedToken: signed,
	}

	t.Cleanup(func() {
		if fix.runCancel != nil {
			fix.runCancel()
			select {
			case <-fix.runDone:
			case <-time.After(10 * time.Second):
				t.Log("manage Run did not shut down within 10s")
			}
		}
		adminSrv.Close()
		ls.Close()
		reportStub.Close()
		_ = store.DropSchema(context.Background())
		_ = store.Close()
	})
	return fix
}

// startRun spawns srv.Run() in a goroutine and records the cancel
// channels into the fixture so t.Cleanup can tear it down. Must be
// called AFTER completeSetup so the CA is bootstrapped and the
// gateway listener actually spins up.
//
// Panics if called twice on the same fixture.
func (f *manageE2EFixture) startRun(t *testing.T) {
	t.Helper()
	if f.runCancel != nil {
		t.Fatal("startRun called twice on the same fixture")
	}
	runCtx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if err := f.Server.Run(runCtx); err != nil {
			t.Logf("manage Run returned: %v", err)
		}
	}()
	f.runCancel = cancel
	f.runDone = runDone
}

// completeSetup runs /setup/admin + /setup/license so the fixture is
// post-setup, push creds are populated (via auto-enrol), and the CA
// is bootstrapped. Returns the admin login JWT for subsequent auth'd
// requests.
func (f *manageE2EFixture) completeSetup(t *testing.T) string {
	t.Helper()
	// Stub license servers in tests use http:// — opt out of the prod-safe
	// HTTPS enforcement so the integration suite doesn't need a TLS harness.
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
	const adminEmail = "admin@e2e.local"
	const adminPassword = "e2e-password-1234" // ≥12 chars + digit

	// /setup/admin
	adminBody := map[string]any{
		"email":    adminEmail,
		"name":     "E2E Admin",
		"password": adminPassword,
	}
	resp := postJSON(t, f.AdminURL+"/api/v1/setup/admin", adminBody)
	body := manageReadBody(resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "setup/admin: %s", body)

	// /setup/license — wire our stub LS + request bundle from Report.
	licBody := map[string]any{
		"license_server_url": f.LSStub.URL,
		"license_key":        "e2e-manage-lic",
		"server_name":        "Test Manage Server",
	}
	resp = postJSON(t, f.AdminURL+"/api/v1/setup/license", licBody)
	body = manageReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "setup/license: %s", body)

	// Login to get a JWT for the admin-only routes.
	loginResp := postJSON(t, f.AdminURL+"/api/v1/auth/login", map[string]any{
		"email":    adminEmail,
		"password": adminPassword,
	})
	loginBodyBytes, err := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "login: %s", string(loginBodyBytes))
	var loginOut map[string]any
	require.NoError(t, json.Unmarshal(loginBodyBytes, &loginOut))
	token, ok := loginOut["token"].(string)
	require.True(t, ok, "login: expected token string, got %+v", loginOut)
	return token
}

// bundleFiles holds the three PEM blobs tar.gz carries.
type e2eBundleFiles struct {
	clientCertPEM []byte
	clientKeyPEM  []byte
	caCertPEM     []byte
}

// unpackAgentBundle extracts the three files from a bundle.tar.gz.
func unpackAgentBundle(t *testing.T, raw []byte) e2eBundleFiles {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	defer func() { _ = gz.Close() }()

	out := e2eBundleFiles{}
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

// e2eMTLSClient returns an http.Client configured with the bundle's
// client cert + trusting the bundle's CA. The real agent does this
// with files from disk.
func e2eMTLSClient(t *testing.T, b e2eBundleFiles) *http.Client {
	t.Helper()
	pair, err := tls.X509KeyPair(b.clientCertPEM, b.clientKeyPEM)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(b.caCertPEM))
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{pair},
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}
}

// waitForGateway polls the gateway URL's underlying TCP port until it's
// accepting connections, up to 5s. srv.Run spawns the gateway in its
// own goroutine so the caller has no direct signal when the listener
// is live; this replaces the naive "sleep 200ms" that would race on
// a slow CI host.
func (f *manageE2EFixture) waitForGateway(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	addr := fmt.Sprintf("127.0.0.1:%d", f.GatewayPort)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("gateway did not come up on %s within 5s", addr)
}

// ---------------------------------------------------------------------
// Subtest 1: setup → license → auto-enrol produces push creds + CA.
// ---------------------------------------------------------------------

func TestManageE2E_SetupAndAutoEnrol(t *testing.T) {
	f := newManageE2EFixture(t)
	_ = f.completeSetup(t)

	// Report received the enrol POST with the expected shape.
	assert.Equal(t, int64(1), f.ReportStub.reqCount.Load(),
		"stub Report must receive exactly one /admin/enrol/manage POST")

	// manage_push_creds populated by auto-enrol.
	resultsStore := scanresults.NewPostgresStore(f.Store.Pool())
	creds, err := resultsStore.LoadPushCreds(context.Background())
	require.NoError(t, err, "push creds must be present after auto-enrol")
	assert.Contains(t, creds.ClientCertPEM, "BEGIN CERTIFICATE",
		"client cert persisted for drain mTLS")
	assert.Contains(t, creds.ClientKeyPEM, "BEGIN PRIVATE KEY",
		"client key persisted for drain mTLS")
	assert.Contains(t, creds.CACertPEM, "BEGIN CERTIFICATE",
		"CA cert persisted for drain cert verification")
	assert.Equal(t, f.ReportStub.mtlsSrv.URL, creds.ReportURL,
		"report_url in bundle must be wired into push creds")
	assert.Equal(t, "e2e-tenant", creds.TenantID)

	// Manage CA bootstrapped so :8443 gateway can come up with an
	// agent-trust chain.
	caStore := ca.NewPostgresStore(f.Store.Pool())
	caBundle, err := caStore.Load(context.Background())
	require.NoError(t, err, "manage CA must be bootstrapped after auto-enrol")
	assert.NotEmpty(t, caBundle.CACertPEM)
	assert.NotEmpty(t, caBundle.CAKeyPEM)
}

// ---------------------------------------------------------------------
// Subtest 2: enrol agent → phone-home over mTLS → revoke → 401.
// Covers the mTLS plumbing end-to-end through the live :8443 listener.
// ---------------------------------------------------------------------

func TestManageE2E_AgentGatewayMTLS(t *testing.T) {
	f := newManageE2EFixture(t)
	token := f.completeSetup(t)
	// Run must start AFTER setup so the CA bootstrap from
	// /setup/license is visible to runGateway's initial caStore.Load.
	f.startRun(t)
	f.waitForGateway(t)

	// Enrol a fresh agent via the admin API.
	req, err := http.NewRequest(http.MethodPost,
		f.AdminURL+"/api/v1/admin/enrol/agent",
		strings.NewReader(`{"name":"e2e-edge-01"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"enrol agent: %s", string(body))
	bundle := unpackAgentBundle(t, body)

	// Dial the live gateway with the bundle cert → phone-home → 200.
	client := e2eMTLSClient(t, bundle)
	phoneURL := f.GatewayURL + "/api/v1/gateway/agents/phone-home"
	phoneResp, err := client.Post(phoneURL, "application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err, "phone-home must succeed over mTLS")
	defer func() { _ = phoneResp.Body.Close() }()
	require.Equal(t, http.StatusOK, phoneResp.StatusCode,
		"phone-home status")
	var ph map[string]any
	require.NoError(t, json.NewDecoder(phoneResp.Body).Decode(&ph))
	assert.Equal(t, true, ph["ok"])

	// --- Revocation path ---
	// Find the agent ID via admin list. The enrol response is the
	// bundle binary, not JSON; the agent's UUID lives in the leaf
	// cert's CN (agent:<uuid>) but simpler to list + pick the one row.
	listReq, err := http.NewRequest(http.MethodGet,
		f.AdminURL+"/api/v1/admin/agents", nil)
	require.NoError(t, err)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	require.NoError(t, err)
	listBody, err := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, listResp.StatusCode, "list agents: %s", string(listBody))
	var agents []map[string]any
	require.NoError(t, json.Unmarshal(listBody, &agents))
	require.GreaterOrEqual(t, len(agents), 1)
	agentID, ok := agents[0]["id"].(string)
	require.True(t, ok, "first agent must have string id, got %+v", agents[0])

	// Revoke.
	revokeReq, err := http.NewRequest(http.MethodDelete,
		f.AdminURL+"/api/v1/admin/agents/"+agentID, nil)
	require.NoError(t, err)
	revokeReq.Header.Set("Authorization", "Bearer "+token)
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	require.NoError(t, err)
	revokeBody := manageReadBody(revokeResp)
	require.Equal(t, http.StatusNoContent, revokeResp.StatusCode,
		"revoke agent: %s", revokeBody)

	// Force revocation cache refresh so the 30s TTL doesn't hide the
	// revocation from the running gateway's MTLSCNAuth middleware.
	caStore := ca.NewPostgresStore(f.Store.Pool())
	require.NoError(t, caStore.RefreshRevocationCache(context.Background()),
		"force revocation cache refresh")

	// Re-dial — must 401 now.
	phoneResp2, err := client.Post(phoneURL, "application/json", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err, "TCP dial should still work; mTLS handshake may fail")
	defer func() { _ = phoneResp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, phoneResp2.StatusCode,
		"phone-home after revocation must 401")
}

// ---------------------------------------------------------------------
// Subtest 3: drain pushes enqueued scan result to stub Report over
// mTLS with CN=manage:<hash>. Covers the drain half of the pipeline
// without involving the real scanner, which is exercised in the
// pkg/manageserver/scanjobs orchestrator unit tests with fake ScanFuncs.
// ---------------------------------------------------------------------

func TestManageE2E_DrainToReportMTLS(t *testing.T) {
	f := newManageE2EFixture(t)
	_ = f.completeSetup(t)
	// startRun after completeSetup so the drain goroutine picks up the
	// push_creds populated by auto-enrol. Without startRun here the
	// queue would fill but nothing would drain it.
	f.startRun(t)

	// Manually enqueue a scan result envelope so we don't depend on the
	// real scanner's wall-clock cost (scanning localhost with the quick
	// profile takes several seconds and is host-environment dependent).
	// source_type must be "manage" + source_id = the Manage instance
	// UUID so the stub Report's submitted_by assertion passes. The
	// scan_job_id is uuid.Nil — the queue column is nullable and
	// Enqueue maps Nil → SQL NULL so the FK to manage_scan_jobs stays
	// intact without a real job row. This is exactly what the agent
	// scan ingestion path does in production (see handlers_gateway.go).
	state, err := f.Store.GetSetup(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, state.InstanceID)
	instanceID, err := uuid.Parse(state.InstanceID)
	require.NoError(t, err)

	resultsStore := scanresults.NewPostgresStore(f.Store.Pool())
	scan := &model.ScanResult{
		ID: uuid.Must(uuid.NewV7()).String(),
		Metadata: model.ScanMetadata{
			Hostname:    "e2e-host-01",
			OS:          "linux",
			ScanProfile: "quick",
			Timestamp:   time.Now().UTC(),
		},
		Findings: []model.Finding{},
		Summary:  model.Summary{},
	}
	require.NoError(t, resultsStore.Enqueue(context.Background(),
		uuid.Nil, // no originating scan_job row — simulates agent-side enqueue
		"manage", instanceID, scan),
		"enqueue scan result")

	depth, err := resultsStore.QueueDepth(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(1), depth, "exactly one row before drain")

	// Wait up to 15s for the drain's 5s tick to pull the row + push to
	// the stub Report. Poll for queue depth == 0 AND receipt on stub.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		d, err := resultsStore.QueueDepth(context.Background())
		if err == nil && d == 0 && f.ReportStub.scanReqCount.Load() >= 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Final assertions.
	finalDepth, err := resultsStore.QueueDepth(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), finalDepth, "queue must be empty after drain")
	assert.GreaterOrEqual(t, f.ReportStub.scanReqCount.Load(), int64(1),
		"stub Report must receive at least one /api/v1/scans POST")

	// The stub asserted CN + envelope shape inline; confirm the
	// captured CN starts with manage: for a defence-in-depth check.
	cnRaw := f.ReportStub.lastScanCN.Load()
	require.NotNil(t, cnRaw, "stub Report must have captured a CN")
	cn, ok := cnRaw.(string)
	require.True(t, ok)
	assert.True(t, strings.HasPrefix(cn, "manage:"),
		"drain's client cert CN must start with manage:, got %q", cn)

	// Envelope shape sanity on the last body (also enforced inline in
	// the stub, but re-asserting here makes failures easier to
	// diagnose — you see the raw body in the assertion message).
	bodyRaw := f.ReportStub.lastScanBody.Load()
	require.NotNil(t, bodyRaw, "stub Report must have captured a body")
	var env map[string]any
	require.NoError(t, json.Unmarshal(bodyRaw.([]byte), &env))
	sb, ok := env["submitted_by"].(map[string]any)
	require.True(t, ok, "envelope must have submitted_by nested object")
	assert.Equal(t, "manage", sb["type"])
	assert.Equal(t, instanceID.String(), sb["id"])
}
