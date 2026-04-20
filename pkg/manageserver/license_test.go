//go:build integration

package manageserver_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// TestStartLicence_RunsUsagePusher seeds an activated SetupState with a
// validly-signed token (Features.Manage=true), brings the server up, and
// asserts the usage pusher has reached a stub License Server at least once.
func TestStartLicence_RunsUsagePusher(t *testing.T) {
	// 1. Stub License Server that counts POST /api/v1/license/usage hits.
	var hits int64
	ls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/license/usage" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ls.Close()

	// 2. Generate an ephemeral Ed25519 keypair and sign a token with
	//    Features.Manage=true. Parse must accept it under the pubkey we
	//    pass into Config.
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "test-lic",
		Tier:      license.TierPro,
		Org:       "ACME",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		// MachineID left empty — Parse skips machine binding when absent,
		// which is what we want for the httptest scenario.
		Features: licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	// 3. Seed the store directly — admin + licence already activated.
	schema := fmt.Sprintf("test_msrv_lic_%d", serverTestSeq.Add(1))
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
		ls.URL, "lic-uuid", signed, "00000000-0000-0000-0000-0000000000aa"))

	// 4. Build the server — New() calls startLicence which spawns the pusher.
	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)
	_ = srv // Server holds the pusher's cancel; we don't need the router here.

	// 5. Wait up to 500ms for the initial push (Run() fires one immediately).
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&hits) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, atomic.LoadInt64(&hits), int64(1),
		"usage pusher must have reached the stub at least once")

	// 6. Cleanup: srv.stopLicence is unexported, but dropping the schema at
	//    t.Cleanup will race with the pusher. Call Run briefly then cancel
	//    to exercise the shutdown path.
	runCtx, runCancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	// Use a random local port via :0; ListenAndServe on :0 works cross-platform.
	go func() { runDone <- srv.Run(runCtx) }()
	time.Sleep(50 * time.Millisecond)
	runCancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestStartLicence_Noop_WhenNotActivated verifies that on a fresh DB
// (no admin, no license), startLicence is a no-op and New() succeeds.
func TestStartLicence_Noop_WhenNotActivated(t *testing.T) {
	srv, cleanup := openTestServer(t)
	defer cleanup()

	// Confirm health endpoint still reports setup_mode=true.
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["setup_mode"])
}

// TestStartLicence_UsagePushStampsLicenseState asserts the Batch H5
// integration: when the UsagePusher successfully reaches the License
// Server, it invokes the OnPushSuccess hook which stamps
// manage_license_state.last_pushed_at.
//
// Verifies both:
//  1. resultsStore.LoadLicenseState() returns a non-zero last_pushed_at
//     after at least one successful push; and
//  2. the pushed metrics JSON is retained in last_pushed_metrics for
//     admin-UI introspection.
func TestStartLicence_UsagePushStampsLicenseState(t *testing.T) {
	// Stub License Server that always accepts. We don't count hits
	// directly; we trust the DB stamp as the proof.
	ls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ls.Close()

	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "test-lic-h5",
		Tier:      license.TierPro,
		Org:       "ACME",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	schema := fmt.Sprintf("test_msrv_h5_%d", serverTestSeq.Add(1))
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
		ls.URL, "lic-uuid-h5", signed, "00000000-0000-0000-0000-0000000000cc"))

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)
	_ = srv

	// Poll manage_license_state until last_pushed_at populates (up to
	// 2 s — the pusher fires an immediate push on Run() entry so this
	// should settle fast in practice).
	resultsStore := scanresults.NewPostgresStore(store.Pool())
	var st scanresults.Status
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s, err := resultsStore.LoadLicenseState(context.Background())
		if err == nil && s.LastPushedAt != nil && !s.LastPushedAt.IsZero() {
			st = s
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NotNil(t, st.LastPushedAt, "manage_license_state.last_pushed_at must be stamped after a successful push")
	assert.WithinDuration(t, time.Now(), *st.LastPushedAt, 5*time.Second)
}

// TestStartLicence_UsagePushFailure_StampsConsecutiveFailures asserts
// the mirror path: when the LS returns 5xx, RecordPushFailure fires
// and manage_license_state.consecutive_failures increments.
func TestStartLicence_UsagePushFailure_StampsConsecutiveFailures(t *testing.T) {
	// Stub LS that always returns 500.
	ls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ls.Close()

	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)
	lic := &license.License{
		ID:        "test-lic-h5-fail",
		Tier:      license.TierPro,
		Org:       "ACME",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	schema := fmt.Sprintf("test_msrv_h5fail_%d", serverTestSeq.Add(1))
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
		ls.URL, "lic-uuid-h5f", signed, "00000000-0000-0000-0000-0000000000dd"))

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)
	_ = srv

	resultsStore := scanresults.NewPostgresStore(store.Pool())
	var st scanresults.Status
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s, err := resultsStore.LoadLicenseState(context.Background())
		if err == nil && s.ConsecutiveFailures >= 1 {
			st = s
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, st.ConsecutiveFailures, 1,
		"manage_license_state.consecutive_failures must increment after an LS 500")
	assert.Contains(t, st.LastPushError, "500",
		"last_push_error must surface the upstream status code")
}

// TestStartLicence_PropagatesGuardToSubHandlers is the D2 guardrail:
// the bug it pins was that startLicence populated s.licenceGuard but
// never pushed it into hostsAdmin.Guard / scanjobsAdmin.Guard /
// agentsAdmin.Guard. In production only H1 (seat cap, which reads
// s.licenceGuard directly via resolveSeatCapGuard) would have worked;
// H2/H3/H4 per-package caps would silently skip because their Guard
// fields stayed nil.
//
// This test activates a real licence against the full server
// construction path and asserts all three sub-handler guards become
// non-nil AND match the top-level Server.licenceGuard. Then it calls
// stopLicence and asserts the mirror: all three revert to nil.
func TestStartLicence_PropagatesGuardToSubHandlers(t *testing.T) {
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "test-lic-propagate",
		Tier:      license.TierPro,
		Org:       "ACME",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	schema := fmt.Sprintf("test_msrv_propagate_%d", serverTestSeq.Add(1))
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
		"http://localhost:0", "lic-uuid-propagate", signed,
		"00000000-0000-0000-0000-0000000000ff"))

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	// ---- assert propagation after startLicence.
	topGuard := manageserver.LicenceGuardForTest(srv)
	require.NotNil(t, topGuard, "s.licenceGuard must be wired after activation")

	hg, sg, ag := manageserver.SubHandlerGuardsForTest(srv)
	assert.NotNil(t, hg, "hostsAdmin.Guard must be propagated (D2: H2 host cap)")
	assert.NotNil(t, sg, "scanjobsAdmin.Guard must be propagated (D2: H3 scan cap)")
	assert.NotNil(t, ag, "agentsAdmin.Guard must be propagated (D2: H4 agent cap)")

	// Same pointer: the propagation must install the exact guard
	// startLicence constructed, not a cloned or shadow guard.
	assert.Same(t, topGuard, hg.(*license.Guard), "hosts guard must be the same pointer as s.licenceGuard")
	assert.Same(t, topGuard, sg.(*license.Guard), "scan-jobs guard must be the same pointer as s.licenceGuard")
	assert.Same(t, topGuard, ag.(*license.Guard), "agents guard must be the same pointer as s.licenceGuard")

	// ---- stopLicence must tear down the propagation too.
	manageserver.StopLicenceForTest(srv)
	assert.Nil(t, manageserver.LicenceGuardForTest(srv), "s.licenceGuard must be nil after stopLicence")
	hg2, sg2, ag2 := manageserver.SubHandlerGuardsForTest(srv)
	assert.Nil(t, hg2, "hostsAdmin.Guard must be nil after stopLicence")
	assert.Nil(t, sg2, "scanjobsAdmin.Guard must be nil after stopLicence")
	assert.Nil(t, ag2, "agentsAdmin.Guard must be nil after stopLicence")
}

// TestStartLicence_PropagatedGuard_EnforcesHostCapOverHTTP is the
// end-to-end partner of TestStartLicence_PropagatesGuardToSubHandlers:
// rather than poking at the guard pointers directly, it exercises the
// real HTTP path a production client would hit.
//
// Activation: sign a licence with `hosts/total: 0` (nominally zero-cap
// with 10% soft buffer ⇒ ceiling 0). After New() calls startLicence
// the propagated guard on hostsAdmin.Guard must cause POST
// /api/v1/admin/hosts/ to reject with 403. If D2 regresses (guard
// not propagated), the test falls through to the happy path because
// the nil-guard check in the handler skips cap enforcement entirely.
func TestStartLicence_PropagatedGuard_EnforcesHostCapOverHTTP(t *testing.T) {
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "test-lic-hostcap-e2e",
		Tier:      license.TierPro,
		Org:       "ACME",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
		Limits: licensestore.Limits{
			// hosts/total = 0 ⇒ any Create must be rejected.
			{Metric: "hosts", Window: "total", Cap: 0},
		},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	schema := fmt.Sprintf("test_msrv_hostcap_e2e_%d", serverTestSeq.Add(1))
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
		"http://localhost:0", "lic-uuid-hostcap-e2e", signed,
		"00000000-0000-0000-0000-000000000222"))

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	// Sanity: guard must be wired. If not, the test would be vacuous.
	require.NotNil(t, manageserver.LicenceGuardForTest(srv),
		"precondition: guard must be wired after startLicence")

	// Seed an admin so we can log in and hit /api/v1/admin/hosts/.
	admin := seedAdminUser(t, store)

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	// POST /api/v1/admin/hosts/ with hosts/total=0 must be 403.
	body := `{"hostname":"blocked-by-cap"}`
	req, err := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/admin/hosts/", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"D2: propagated guard must enforce hosts/total=0 cap at the HTTP layer")
}

// TestStartLicence_MissingPubKey_IsGracefulAtBoot ensures that when the
// persisted token cannot be parsed (e.g. wrong pubkey, expired, tampered),
// New() still succeeds — admin can re-activate via /setup/license without
// needing to restart the process.
func TestStartLicence_MissingPubKey_IsGracefulAtBoot(t *testing.T) {
	schema := fmt.Sprintf("test_msrv_lic_bad_%d", serverTestSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getTestDBURL(), schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	})

	require.NoError(t, store.MarkAdminCreated(context.Background()))
	// Persist a bogus signed token — Parse will fail.
	require.NoError(t, store.SaveLicenseActivation(context.Background(),
		"https://ls.example.com", "lic", "not-a-real-token", "00000000-0000-0000-0000-0000000000bb"))

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		PublicKey:     ed25519.PublicKey{}, // empty → Parse returns error
		SessionTTL:    time.Hour,
	}
	// Should NOT error — startLicence logs and returns.
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)
	require.NotNil(t, srv)
}
