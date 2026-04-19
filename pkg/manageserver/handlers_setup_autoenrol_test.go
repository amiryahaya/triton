//go:build integration

package manageserver_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// stubReportServer stands up a minimal Report server that exposes only
// /api/v1/admin/enrol/manage. It captures the last JSON body so tests can
// assert exactly what Manage sent. Set statusCode to non-zero to override
// the default 200 OK (used for failure-mode tests).
type stubReportServer struct {
	srv        *httptest.Server
	serviceKey string
	sawBody    atomic.Value // holds map[string]string
	reqCount   atomic.Int64
	statusCode int
}

func newStubReportServer(t *testing.T, serviceKey string) *stubReportServer {
	t.Helper()
	s := &stubReportServer{serviceKey: serviceKey}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/enrol/manage" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Triton-Service-Key") != s.serviceKey {
			http.Error(w, "bad service key", http.StatusForbidden)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		s.sawBody.Store(body)
		s.reqCount.Add(1)

		status := s.statusCode
		if status == 0 {
			status = http.StatusOK
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}

		// Build a fake bundle — just enough realism for Manage's parser to
		// accept the response. We mint a throwaway CA, sign Manage's
		// public key with it, and tar.gz up client.crt + ca.crt +
		// config.yaml.
		bundle, err := buildFakeBundle(body["manage_instance_id"], body["public_key_pem"])
		if err != nil {
			http.Error(w, "bundle build: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}))
	return s
}

func (s *stubReportServer) Close() { s.srv.Close() }
func (s *stubReportServer) URL() string {
	if s == nil {
		return ""
	}
	return s.srv.URL
}

func buildFakeBundle(instanceID, pubPEM string) ([]byte, error) {
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Fake Report CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("decode pub PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "manage:stubhash:" + instanceID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, pub, caPriv)
	if err != nil {
		return nil, err
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	cfg := fmt.Sprintf("manage_instance_id: %s\nreport_url: https://report.stub/\ntenant_id: stub-tenant\n", instanceID)

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
	if err := add("ca.crt", caPEM); err != nil {
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

// TestSetupLicense_AutoEnrolSucceeds — stubs both License Server + Report
// server; after /setup/license returns 200, manage_push_creds and manage_ca
// must be populated by the auto-enrol flow.
func TestSetupLicense_AutoEnrolSucceeds(t *testing.T) {
	store, cleanup := openStoreForAutoEnrol(t)
	defer cleanup()

	const serviceKey = "stub-service-key"
	report := newStubReportServer(t, serviceKey)
	defer report.Close()

	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token:     "signed-token-xyz",
		ExpiresAt: "2030-01-01T00:00:00Z",
		Features: map[string]any{
			"report": true,
			"manage": true,
		},
		ProductScope: "manage",
	})
	defer ls.Close()

	srv := newSetupServerWithReport(t, store, report.URL(), serviceKey)
	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{
	    "license_server_url": %q,
	    "license_key":        "lic-auto-enrol"
	}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Report captured the correct body.
	assert.Equal(t, int64(1), report.reqCount.Load(), "Report must be called exactly once")
	sawRaw := report.sawBody.Load()
	require.NotNil(t, sawRaw)
	saw, ok := sawRaw.(map[string]string)
	require.True(t, ok)
	assert.Equal(t, "lic-auto-enrol", saw["license_key"])
	_, err = uuid.Parse(saw["manage_instance_id"])
	assert.NoError(t, err)
	assert.Contains(t, saw["public_key_pem"], "-----BEGIN PUBLIC KEY-----")

	// manage_push_creds populated.
	resultsStore := scanresults.NewPostgresStore(store.Pool())
	creds, err := resultsStore.LoadPushCreds(context.Background())
	require.NoError(t, err)
	assert.Contains(t, creds.ClientCertPEM, "BEGIN CERTIFICATE")
	assert.Contains(t, creds.ClientKeyPEM, "BEGIN PRIVATE KEY",
		"private key is locally generated and must be persisted")
	assert.Contains(t, creds.CACertPEM, "BEGIN CERTIFICATE")
	assert.Equal(t, "stub-tenant", creds.TenantID)
	assert.Equal(t, "https://report.stub/", creds.ReportURL)

	// manage_ca populated.
	caStore := ca.NewPostgresStore(store.Pool())
	caBundle, err := caStore.Load(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, caBundle.CACertPEM)
}

// TestSetupLicense_AutoEnrolFailureIsLogged — Report server is unreachable;
// /setup/license still returns 200 (best-effort contract); manage_push_creds
// stays empty.
func TestSetupLicense_AutoEnrolFailureIsLogged(t *testing.T) {
	store, cleanup := openStoreForAutoEnrol(t)
	defer cleanup()

	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token:        "signed-token",
		ExpiresAt:    "2030-01-01T00:00:00Z",
		Features:     map[string]any{"manage": true},
		ProductScope: "manage",
	})
	defer ls.Close()

	// IANA-reserved port 1; TCP connect fails fast.
	srv := newSetupServerWithReport(t, store, "http://127.0.0.1:1", "any-service-key")
	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{
	    "license_server_url": %q,
	    "license_key":        "lic-unreachable-report"
	}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"/setup/license must succeed even when Report auto-enrol fails")

	resultsStore := scanresults.NewPostgresStore(store.Pool())
	_, err = resultsStore.LoadPushCreds(context.Background())
	assert.Error(t, err, "manage_push_creds must NOT be populated on Report failure")
}

// TestSetupLicense_AutoEnrolSkippedWhenUnconfigured — ReportServer + ReportServiceKey
// both empty → auto-enrol is skipped silently; setup succeeds.
func TestSetupLicense_AutoEnrolSkippedWhenUnconfigured(t *testing.T) {
	store, cleanup := openStoreForAutoEnrol(t)
	defer cleanup()

	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token:        "signed-token",
		ExpiresAt:    "2030-01-01T00:00:00Z",
		Features:     map[string]any{"manage": true},
		ProductScope: "manage",
	})
	defer ls.Close()

	srv := newSetupServerWithReport(t, store, "", "")
	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{
	    "license_server_url": %q,
	    "license_key":        "lic-no-auto"
	}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resultsStore := scanresults.NewPostgresStore(store.Pool())
	_, err = resultsStore.LoadPushCreds(context.Background())
	assert.Error(t, err, "manage_push_creds must not be populated when auto-enrol skipped")
}

// Helpers --------------------------------------------------------------

var autoEnrolSeq atomic.Int64

func openStoreForAutoEnrol(t *testing.T) (*managestore.PostgresStore, func()) {
	t.Helper()
	schema := fmt.Sprintf("test_msrv_enrol_%d", autoEnrolSeq.Add(1))
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	}
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), dbURL, schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	return store, func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	}
}

func newSetupServerWithReport(t *testing.T, store *managestore.PostgresStore, reportServer, reportServiceKey string) *manageserver.Server {
	t.Helper()
	cfg := &manageserver.Config{
		Listen:           ":0",
		JWTSigningKey:    []byte("manage-server-enrol-test-key-32b"),
		SessionTTL:       time.Hour,
		ReportServer:     reportServer,
		ReportServiceKey: reportServiceKey,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)
	return srv
}
