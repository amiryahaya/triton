//go:build integration

package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// csSchemaSeq allocates unique PG schemas across cross-service tests.
var csSchemaSeq atomic.Int64

// csJWTKey is a fixed 32-byte HS256 secret for cross-service tests.
var csJWTKey = []byte("manage-cs-test-jwt-key-32bytess!")

// csAdminKey is the License Portal admin key used in cross-service tests.
const csAdminKey = "cs-test-admin-key"

// csFixture holds the test rig for cross-service lifecycle tests.
type csFixture struct {
	// License Portal
	LSServer *httptest.Server
	LSPub    ed25519.PublicKey
	OrgID    string
	LicIDA   string // initial license (Pro, 5 seats)
	LicIDB   string // second license (Enterprise, 2 seats) for ReplaceKey test

	// Manage Server
	ManageSrv   *manageserver.Server
	ManageURL   string
	ManageStore *managestore.PostgresStore
	AdminJWT    string
	InstanceID  string
}

// newCSFixture boots a real License Portal (httptest) and a real Manage Server
// (via RunOnListener), drives the full setup flow, and returns the fixture.
func newCSFixture(t *testing.T) *csFixture {
	t.Helper()
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")

	ctx := context.Background()
	f := &csFixture{}

	// --- License Portal ---

	lsStore, err := licensestore.NewPostgresStore(ctx, testDBURL())
	if err != nil {
		t.Skipf("PostgreSQL unavailable (license store): %v", err)
	}
	require.NoError(t, lsStore.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = lsStore.TruncateAll(ctx)
		lsStore.Close()
	})

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	f.LSPub = pub

	lsSrv := licenseserver.New(&licenseserver.Config{
		ListenAddr: ":0",
		AdminKeys:  []string{csAdminKey},
		SigningKey: priv,
		PublicKey:  pub,
	}, lsStore)
	f.LSServer = httptest.NewServer(lsSrv.Router())
	t.Cleanup(f.LSServer.Close)

	// Create org.
	resp := csLSAdminReq(t, f, "POST", "/api/v1/admin/orgs", map[string]string{"name": "CS-Test-Org"})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create org")
	var orgOut map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&orgOut))
	resp.Body.Close()
	f.OrgID = orgOut["id"].(string)

	// License A — Pro, 5 seats.
	resp = csLSAdminReq(t, f, "POST", "/api/v1/admin/licenses", map[string]any{
		"orgID": f.OrgID, "tier": "pro", "seats": 5, "days": 365,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create license A")
	var licAOut map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&licAOut))
	resp.Body.Close()
	f.LicIDA = licAOut["id"].(string)

	// License B — Enterprise, 2 seats (for ReplaceKey test).
	resp = csLSAdminReq(t, f, "POST", "/api/v1/admin/licenses", map[string]any{
		"orgID": f.OrgID, "tier": "enterprise", "seats": 2, "days": 365,
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create license B")
	var licBOut map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&licBOut))
	resp.Body.Close()
	f.LicIDB = licBOut["id"].(string)

	// --- Manage Server ---

	schema := fmt.Sprintf("test_manage_cs_%d", csSchemaSeq.Add(1))
	msStore, err := managestore.NewPostgresStoreInSchema(ctx, testDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable (manage store): %v", err)
	}
	t.Cleanup(func() {
		_ = msStore.DropSchema(ctx)
		_ = msStore.Close()
	})
	f.ManageStore = msStore

	msSrv, err := manageserver.New(&manageserver.Config{
		JWTSigningKey:       csJWTKey,
		PublicKey:           pub,
		SessionTTL:          time.Hour,
		GatewayListen:       "127.0.0.1:0",
		GatewayHostname:     "127.0.0.1",
		WatcherTickInterval: 100 * time.Millisecond,
	}, msStore, msStore.Pool())
	require.NoError(t, err)
	f.ManageSrv = msSrv

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f.ManageURL = "http://" + ln.Addr().String()

	runCtx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		_ = msSrv.RunOnListener(runCtx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-doneCh
	})

	csWaitReady(t, f.ManageURL)
	csSetup(t, f)

	return f
}

// csSetup drives /setup/admin → /setup/license → /auth/login.
func csSetup(t *testing.T, f *csFixture) {
	t.Helper()
	const adminEmail = "admin@cstest.local"
	const adminPassword = "CS-test-password-1"

	resp := postJSON(t, f.ManageURL+"/api/v1/setup/admin", map[string]any{
		"email":    adminEmail,
		"name":     "CS Admin",
		"password": adminPassword,
	})
	body := csReadBody(resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "setup/admin: %s", body)

	resp = postJSON(t, f.ManageURL+"/api/v1/setup/license", map[string]any{
		"license_server_url": f.LSServer.URL,
		"license_key":        f.LicIDA,
	})
	body = csReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "setup/license: %s", body)

	loginResp := postJSON(t, f.ManageURL+"/api/v1/auth/login", map[string]any{
		"email":    adminEmail,
		"password": adminPassword,
	})
	loginBytes, err := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "login: %s", string(loginBytes))

	var loginOut map[string]any
	require.NoError(t, json.Unmarshal(loginBytes, &loginOut))
	tok, ok := loginOut["token"].(string)
	require.True(t, ok, "login must return token, got %+v", loginOut)
	f.AdminJWT = tok

	ctx := context.Background()
	state, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, state.InstanceID, "instance_id must be set after setup")
	f.InstanceID = state.InstanceID
}

// csWaitReady polls GET /api/v1/health until the manage server responds or 5s elapses.
func csWaitReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/api/v1/health") //nolint:noctx
		if err == nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("manage server not ready within 5s")
}

// csManageReq sends an authenticated request to the Manage Server admin plane.
func csManageReq(t *testing.T, f *csFixture, method, path string, body any) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, f.ManageURL+path, bodyReader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+f.AdminJWT)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// csLSAdminReq sends an admin-keyed request to the License Portal.
func csLSAdminReq(t *testing.T, f *csFixture, method, path string, body any) *http.Response {
	t.Helper()
	return licAdminReqWithKey(t, method, f.LSServer.URL+path, csAdminKey, body)
}

// csActivationsForLicense calls GET /api/v1/admin/activations?license={licID}
// on the License Portal and returns the decoded activation list.
func csActivationsForLicense(t *testing.T, f *csFixture, licID string) []map[string]any {
	t.Helper()
	resp := csLSAdminReq(t, f, "GET",
		fmt.Sprintf("/api/v1/admin/activations?license=%s", licID), nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "list activations for %s", licID)
	var acts []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&acts))
	return acts
}

// csReadBody reads and closes the response body, returning it as a string.
func csReadBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

// csDeactivatedAt extracts the deactivated_at field from an activation record.
// Returns empty string if absent or null.
func csDeactivatedAt(act map[string]any) string {
	if v, ok := act["deactivated_at"]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// TestCSLicence_Refresh verifies that POST /admin/licence/refresh calls the
// real License Portal Activate endpoint, stores a new signed token, and keeps
// the guard live.
func TestCSLicence_Refresh(t *testing.T) {
	f := newCSFixture(t)

	ctx := context.Background()
	stateBefore, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	tokenBefore := stateBefore.SignedToken
	require.NotEmpty(t, tokenBefore, "setup must have stored a signed token")

	// Capture activation count before refresh so we can confirm Activate was called.
	actsBefore := csActivationsForLicense(t, f, f.LicIDA)
	activeBefore := 0
	for _, a := range actsBefore {
		if csDeactivatedAt(a) == "" {
			activeBefore++
		}
	}

	resp := csManageReq(t, f, http.MethodPost, "/api/v1/admin/licence/refresh", nil)
	body := csReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh: %s", body)

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Equal(t, true, out["ok"], "refresh must return ok:true, got %v", out)

	stateAfter, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	require.NotEqual(t, tokenBefore, stateAfter.SignedToken,
		"signed_token must change after refresh")
	// Verify the new token is a valid ed25519-signed token from the real License Portal.
	_, err = license.Parse(stateAfter.SignedToken, f.LSPub)
	require.NoError(t, err, "new signed_token must be parseable and valid against LSPub")

	licResp := csManageReq(t, f, http.MethodGet, "/api/v1/admin/licence", nil)
	licBody := csReadBody(licResp)
	require.Equal(t, http.StatusOK, licResp.StatusCode,
		"GET /admin/licence must return 200 after refresh: %s", licBody)

	// Confirm refresh called Activate: activation count must have increased.
	actsAfter := csActivationsForLicense(t, f, f.LicIDA)
	activeAfter := 0
	for _, a := range actsAfter {
		if csDeactivatedAt(a) == "" {
			activeAfter++
		}
	}
	require.Greater(t, activeAfter, activeBefore,
		"activation count must increase after refresh (Activate was called)")
}

// TestCSLicence_ReplaceKey verifies that POST /admin/licence/replace activates
// a new key against the real License Portal and stores the new key in the DB.
// The old key's activation is intentionally NOT deactivated by replace.
func TestCSLicence_ReplaceKey(t *testing.T) {
	f := newCSFixture(t)
	ctx := context.Background()

	// Capture baselines before replace so we can verify nothing was deactivated.
	stateBefore, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	tokenBefore := stateBefore.SignedToken

	actsABefore := csActivationsForLicense(t, f, f.LicIDA)
	activeABefore := 0
	for _, a := range actsABefore {
		if csDeactivatedAt(a) == "" {
			activeABefore++
		}
	}

	resp := csManageReq(t, f, http.MethodPost, "/api/v1/admin/licence/replace",
		map[string]string{"license_key": f.LicIDB})
	body := csReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "replace: %s", body)

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Equal(t, true, out["ok"], "replace must return ok:true, got %v", out)

	// DB: license_key must now be LicIDB; token must have changed to LicIDB's token.
	state, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	require.Equal(t, f.LicIDB, state.LicenseKey,
		"license_key in DB must be LicIDB after replace")
	require.NotEqual(t, tokenBefore, state.SignedToken,
		"signed_token must change after replace (new activation for LicIDB)")
	// New token must be valid and signed by the real License Portal.
	_, err = license.Parse(state.SignedToken, f.LSPub)
	require.NoError(t, err, "signed_token after replace must be parseable with LSPub")

	// License Portal: LicIDB must have an active activation.
	actsB := csActivationsForLicense(t, f, f.LicIDB)
	require.NotEmpty(t, actsB, "License Portal must have an activation for LicIDB")
	activeB := 0
	for _, a := range actsB {
		if csDeactivatedAt(a) == "" {
			activeB++
		}
	}
	require.Greater(t, activeB, 0, "LicIDB must have a non-deactivated activation")

	// License Portal: LicIDA active-activation count must be unchanged (replace does NOT deactivate).
	actsAAfter := csActivationsForLicense(t, f, f.LicIDA)
	activeAAfter := 0
	for _, a := range actsAAfter {
		if csDeactivatedAt(a) == "" {
			activeAAfter++
		}
	}
	require.Equal(t, activeABefore, activeAAfter,
		"LicIDA active-activation count must not change after replace (no deactivation)")

	// Guard still live.
	licResp := csManageReq(t, f, http.MethodGet, "/api/v1/admin/licence", nil)
	licBody := csReadBody(licResp)
	require.Equal(t, http.StatusOK, licResp.StatusCode,
		"GET /admin/licence must return 200 after replace: %s", licBody)
}

// TestCSLicence_Deactivate_Immediate verifies that POST /admin/licence/deactivate
// with no active scan jobs calls the real License Portal Deactivate endpoint,
// clears local activation state, and puts the Manage Server into setup mode.
func TestCSLicence_Deactivate_Immediate(t *testing.T) {
	f := newCSFixture(t)

	// No scan jobs seeded — deactivation must be immediate (200, not 202).
	resp := csManageReq(t, f, http.MethodPost, "/api/v1/admin/licence/deactivate", nil)
	body := csReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"immediate deactivate must return 200: %s", body)

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Equal(t, true, out["ok"], "immediate deactivate: ok must be true, got %v", out)

	// License Portal: activation for LicIDA must now have deactivated_at set.
	acts := csActivationsForLicense(t, f, f.LicIDA)
	require.NotEmpty(t, acts, "License Portal must have an activation for LicIDA")
	deactivated := 0
	for _, a := range acts {
		if csDeactivatedAt(a) != "" {
			deactivated++
		}
	}
	require.Greater(t, deactivated, 0,
		"at least one activation for LicIDA must have deactivated_at set")

	// Manage Server must be in setup mode (503) after deactivation.
	licResp := csManageReq(t, f, http.MethodGet, "/api/v1/admin/licence", nil)
	licBody := csReadBody(licResp)
	require.Equal(t, http.StatusServiceUnavailable, licResp.StatusCode,
		"GET /admin/licence after deactivation must return 503: %s", licBody)
	var licOut map[string]any
	require.NoError(t, json.Unmarshal([]byte(licBody), &licOut))
	require.Equal(t, true, licOut["setup_required"],
		"response must include setup_required:true, got %v", licOut)

	// Manage Store: activation state must be cleared.
	ctx := context.Background()
	state, err := f.ManageStore.GetSetup(ctx)
	require.NoError(t, err)
	require.False(t, state.LicenseActivated, "LicenseActivated must be false after deactivation")
	require.Empty(t, state.LicenseKey, "LicenseKey must be empty after deactivation")
	require.Empty(t, state.SignedToken, "SignedToken must be empty after deactivation")
}
