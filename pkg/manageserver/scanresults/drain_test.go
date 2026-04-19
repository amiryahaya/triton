//go:build integration

package scanresults_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
)

// generateClientCert builds a throwaway self-signed ECDSA client cert.
// Used for the drain's mTLS tls.Config; the stub server is configured
// with ClientAuth: NoClientCert so the presented cert is never verified.
func generateClientCert(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "triton-manage-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// pemEncodeCert converts a tls.Certificate (as returned by
// httptest.NewTLSServer().Certificate) into a PEM string suitable for
// stashing in manage_push_creds.ca_cert_pem.
func pemEncodeCert(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// setupPushStack builds a complete push test rig: a stub TLS server
// with the provided handler, a scanresults.Store, and an
// mTLS-configured *http.Client ready to push to the stub. The creds
// row is also persisted via SavePushCreds so LoadPushCreds round-trips.
func setupPushStack(t *testing.T, pool *pgxpool.Pool, handler http.Handler) (*httptest.Server, scanresults.Store, *http.Client) {
	t.Helper()
	stub := httptest.NewUnstartedServer(handler)
	stub.TLS = &tls.Config{
		ClientAuth: tls.NoClientCert,
		MinVersion: tls.VersionTLS12,
	}
	stub.StartTLS()
	t.Cleanup(stub.Close)

	clientCertPEM, clientKeyPEM := generateClientCert(t)
	creds := scanresults.PushCreds{
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
		CACertPEM:     pemEncodeCert(t, stub.Certificate()),
		ReportURL:     stub.URL,
		TenantID:      "tenant-1",
	}

	store := scanresults.NewPostgresStore(pool)
	require.NoError(t, store.SavePushCreds(context.Background(), creds))

	client, err := scanresults.BuildHTTPClient(creds)
	require.NoError(t, err)
	return stub, store, client
}

func TestDrain_HappyPath(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	var received atomic.Int32
	stub, store, client := setupPushStack(t, pool, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scans" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	// Seed 100 queue rows against 100 distinct scan jobs. seedJob
	// inserts one zone+host+tenant per call, which is cheap but
	// slow-ish: 100 iterations ~= 2-3 s against local pg. Acceptable
	// for an integration test.
	for i := 0; i < 100; i++ {
		jobID, _ := seedJob(t, pool, uniqueHostname(i))
		require.NoError(t, store.Enqueue(ctx, jobID, "manage", uuid.Must(uuid.NewV7()), sampleScan()))
	}
	depth, err := store.QueueDepth(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(100), depth)

	drain := scanresults.NewDrain(scanresults.DrainConfig{
		Store:     store,
		ReportURL: stub.URL,
		Client:    client,
		Batch:     100,
		Interval:  50 * time.Millisecond,
	})
	runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		drain.Run(runCtx)
		close(done)
	}()

	// Poll until queue is drained or the ctx expires. This is more
	// robust than a fixed sleep: fast machines return early, slow CI
	// machines still have their full budget.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		d, _ := store.QueueDepth(ctx)
		if d == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	<-done

	finalDepth, err := store.QueueDepth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), finalDepth, "drain must empty the queue")
	assert.Equal(t, int32(100), received.Load(), "stub must receive all 100 posts")

	st, err := store.LoadLicenseState(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, st.ConsecutiveFailures)
	require.NotNil(t, st.LastPushedAt, "success path must stamp last_pushed_at")
}

// uniqueHostname is a tiny helper to avoid hostname collisions inside
// a single test. manage_hosts.hostname is UNIQUE, so we need distinct
// names across the 100 seeded rows.
func uniqueHostname(i int) string {
	return "drain-host-" + strint(i)
}

func strint(i int) string {
	if i == 0 {
		return "0"
	}
	const digits = "0123456789"
	s := ""
	for i > 0 {
		s = string(digits[i%10]) + s
		i /= 10
	}
	return s
}
