//go:build integration

package manageserver_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// TestAdminHandlers_GuardRaceFree exercises the race condition the
// GuardProvider refactor was written to close. Pre-refactor,
// startLicence wrote s.hostsAdmin.Guard (and siblings) under s.mu while
// the admin handlers read h.Guard lock-free on every request — a classic
// Go memory-model data race. It didn't surface in existing tests
// because those tests injected the guard synchronously before issuing
// any requests.
//
// The test spins 10 goroutines:
//   - 5 readers: POST /api/v1/admin/hosts/ concurrently via the real
//     Router(). Each request hits the hosts admin Create handler,
//     which in turn invokes GuardProvider() to read the licence
//     snapshot. If the handler were reading a bare field instead of
//     going through the provider closure, it would race the writer
//     goroutines below.
//   - 5 writers: alternate StartLicenceForTest / StopLicenceForTest
//     to rotate s.licenceGuard between populated and nil.
//
// Under `go test -race` any unsynchronised write/read surface trips
// the detector and fails the test. A clean pass is the success
// criterion. Whether the individual POSTs return 201 or 403 or 500 is
// irrelevant — the test is purely about memory-model safety on the
// guard pointer.
func TestAdminHandlers_GuardRaceFree(t *testing.T) {
	// Prepare a fully signed, valid licence token so startLicence
	// produces a non-nil guard. That way the rotation is observable
	// (nil → non-nil → nil) rather than a no-op.
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "test-lic-race",
		Tier:      license.TierPro,
		Org:       "ACME",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	schema := fmt.Sprintf("test_msrv_race_%d", serverTestSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getTestDBURL(), schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	})
	require.NoError(t, store.MarkAdminCreated(context.Background()))
	require.NoError(t, store.SaveLicenseActivation(context.Background(),
		"http://localhost:0", "lic-uuid-race", signed,
		"00000000-0000-0000-0000-0000000000e1", ""))

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	// Seed an admin + obtain a JWT. The POST needs to traverse the
	// full middleware stack (requireOperational → jwtAuth →
	// injectInstanceOrg) to reach the admin handler where the guard
	// is consulted.
	admin := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	// 300ms is plenty for the race detector to trip; longer windows
	// slow the suite without buying meaningful extra coverage.
	const dur = 300 * time.Millisecond
	deadline := time.Now().Add(dur)

	var wg sync.WaitGroup

	// Readers: 5 goroutines hammering POST /api/v1/admin/hosts/ so
	// the hosts admin Create handler (which consults the guard
	// provider) runs concurrently with startLicence/stopLicence
	// mutations on a shared server. Each request uses a unique
	// hostname to avoid 409s — we don't care about the response code,
	// only that the handler completes without the race detector
	// flagging an unsynchronised access.
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; time.Now().Before(deadline); j++ {
				body := fmt.Sprintf(`{"hostname":"race-%d-%d"}`, n, j)
				req, err := http.NewRequest(http.MethodPost,
					ts.URL+"/api/v1/admin/hosts/", strings.NewReader(body))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := client.Do(req)
				if err != nil {
					// Transient connection issues are acceptable; the race
					// detector is what we care about.
					continue
				}
				resp.Body.Close()
			}
		}(i)
	}

	// Writers: 5 goroutines ping-ponging start/stop of the licence.
	// Each iteration rotates s.licenceGuard nil → populated → nil.
	// Start and Stop serialise on s.mu, so they don't race each other;
	// the value is in the reader/writer interleaving.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				manageserver.StopLicenceForTest(srv)
				_ = manageserver.StartLicenceForTest(srv)
			}
		}()
	}

	wg.Wait()
	// If we reach here under `go test -race`, no race was detected.
}
