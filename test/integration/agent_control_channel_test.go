//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
)

// integrationMachineID is a fixed 64-char hex string for the lifecycle test.
const integrationMachineID = "7777777777777777777777777777777777777777777777777777777777777777"

// TestAgentControlChannel_Lifecycle exercises the full vertical slice:
//  1. Agent polls → 204 + row created in agents table.
//  2. Admin pauses for 1h → next poll returns state.pausedUntil.
//  3. Admin enqueues cancel → next poll returns the command, marks dispatched.
//  4. Agent POSTs result → server records executed.
//  5. Admin clears pause → next poll returns 204.
func TestAgentControlChannel_Lifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	ts, adminJWT, licenseToken := setupAgentControlIntegration(t)

	poller := &agent.CommandPoller{
		BaseURL:      ts.URL,
		LicenseToken: licenseToken,
		MachineID:    integrationMachineID,
		Hostname:     "integration-host",
		// Short deadline: each call to Poll returns quickly via ctx timeout
		// when the server has nothing to send. 5s is enough for the DB roundtrip.
		PollDeadline: 5 * time.Second,
	}

	ctx := context.Background()

	// ── Step 1: First poll creates the agent row (204 or ctx timeout; both ok) ──
	ctxFirst, cancelFirst := context.WithTimeout(ctx, 5*time.Second)
	defer cancelFirst()
	_, _ = poller.Poll(ctxFirst) // tolerate 204 or DeadlineExceeded

	// ── Step 2: Admin pauses for 1h ──
	pauseBody, pauseCode := adminHTTPCall(t, ts.URL, adminJWT,
		http.MethodPost,
		"/api/v1/admin/agents/"+integrationMachineID+"/pause",
		map[string]any{"durationSeconds": 3600})
	require.Equal(t, 200, pauseCode, "pause response: %v", pauseBody)
	require.NotEmpty(t, pauseBody["pausedUntil"], "pause response must include pausedUntil")

	// ── Step 3: Agent polls → sees pausedUntil ──
	ctxPause, cancelPause := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPause()
	resp, err := poller.Poll(ctxPause)
	require.NoError(t, err, "poll after pause should succeed")
	require.NotNil(t, resp, "poll after pause should return body (not 204)")
	assert.False(t, resp.State.PausedUntil.IsZero(), "state.pausedUntil must be set")

	// ── Step 4: Admin enqueues a cancel command ──
	cmdBody, cmdCode := adminHTTPCall(t, ts.URL, adminJWT,
		http.MethodPost,
		"/api/v1/admin/agents/"+integrationMachineID+"/commands",
		map[string]any{"type": "cancel"})
	require.Equal(t, 201, cmdCode, "enqueue response: %v", cmdBody)
	require.NotEmpty(t, cmdBody["id"], "enqueue response must include id")
	cmdID, ok := cmdBody["id"].(string)
	require.True(t, ok, "command id must be a string")

	// ── Step 5: Agent polls → sees the command ──
	ctxCmd, cancelCmd := context.WithTimeout(ctx, 5*time.Second)
	defer cancelCmd()
	resp, err = poller.Poll(ctxCmd)
	require.NoError(t, err, "poll after enqueue should succeed")
	require.NotNil(t, resp, "poll after enqueue should return body (not 204)")
	require.Len(t, resp.Commands, 1, "exactly one command must be returned")
	assert.Equal(t, cmdID, resp.Commands[0].ID, "returned command id must match enqueued id")
	assert.Equal(t, "cancel", resp.Commands[0].Type)

	// ── Step 6: Agent POSTs result ──
	require.NoError(t, poller.PostResult(ctx, cmdID, "executed",
		json.RawMessage(`{"findings":5}`)))

	// ── Step 7: Verify result persisted via admin detail endpoint ──
	detail, detailCode := adminHTTPCall(t, ts.URL, adminJWT,
		http.MethodGet,
		"/api/v1/admin/agents/"+integrationMachineID,
		nil)
	require.Equal(t, 200, detailCode, "admin detail response: %v", detail)
	rawCmds, hasCmds := detail["commands"]
	require.True(t, hasCmds, "detail must include commands: %v", detail)
	cmds, ok := rawCmds.([]any)
	require.True(t, ok, "commands must be an array")
	require.Len(t, cmds, 1)
	cmdMap, ok := cmds[0].(map[string]any)
	require.True(t, ok, "command entry must be a map")
	assert.Equal(t, "executed", cmdMap["resultStatus"], "resultStatus must be 'executed'")

	// ── Step 8: Admin clears pause ──
	_, clrCode := adminHTTPCall(t, ts.URL, adminJWT,
		http.MethodDelete,
		"/api/v1/admin/agents/"+integrationMachineID+"/pause",
		nil)
	assert.Equal(t, 200, clrCode)

	// ── Step 9: Final poll → 204 (pause cleared, no more pending commands) ──
	ctxFinal, cancelFinal := context.WithTimeout(ctx, 5*time.Second)
	defer cancelFinal()
	resp, err = poller.Poll(ctxFinal)
	// Acceptable: resp==nil (204) or context timeout (server long-poll expires).
	// Either means no state or commands are queued — the control plane is quiet.
	if err == nil {
		assert.Nil(t, resp, "final poll after clear should be 204 (no state, no commands)")
	}
	// context.DeadlineExceeded is also fine — the server returned nothing.
}

// ============================================================================
// Integration test helper
// ============================================================================

// setupAgentControlIntegration spins up a real httptest.Server backed by the
// test PostgreSQL, creates a tenant org, issues a licence token for agent
// auth, creates an org_admin user, and logs in to get a JWT. Returns the
// httptest.Server, the admin JWT, and the agent licence token.
//
// It mirrors the pattern from pkg/server/handlers_agent_control_test.go
// (newAgentControlServer + newAdminJWTForOrg) but works from the
// integration test package so it can use httptest.NewServer over a real
// TCP port instead of httptest.NewRecorder.
func setupAgentControlIntegration(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	db := requireDB(t)

	// Separate keypairs: JWT (admin user auth) vs licence (agent auth).
	jwtPub, jwtPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	licPub, licPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	orgID := uuid.Must(uuid.NewV7()).String()
	ctx := context.Background()
	require.NoError(t, db.CreateOrg(ctx, &store.Organization{
		ID:        orgID,
		Name:      "agent-control-integration-org",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	cfg := &server.Config{
		ListenAddr:        ":0",
		JWTSigningKey:     jwtPriv,
		JWTPublicKey:      jwtPub,
		TenantPubKey:      licPub,
		DisableSetupGuard: true,
	}
	srv, err := server.New(cfg, db)
	require.NoError(t, err)

	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	// Issue a licence token for the agent (bound to orgID, Pro tier).
	lic := &license.License{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Tier:      license.TierPro,
		OrgID:     orgID,
		Org:       "agent-control-integration-org",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	licToken, err := license.Encode(lic, licPriv)
	require.NoError(t, err)

	// Create an org_admin user and log in to obtain a JWT.
	adminJWT := createAdminAndLogin(t, ts, db, orgID, jwtPub, jwtPriv)

	return ts, adminJWT, licToken
}

// createAdminAndLogin creates an org_admin user in orgID and POSTs to
// /api/v1/auth/login, returning the JWT from the response.
func createAdminAndLogin(
	t *testing.T,
	ts *httptest.Server,
	db *store.PostgresStore,
	orgID string,
	_ ed25519.PublicKey,
	_ ed25519.PrivateKey,
) string {
	t.Helper()
	pw := "correct-horse-battery-staple"
	hashed, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &store.User{
		ID:        uuid.Must(uuid.NewV7()).String(),
		OrgID:     orgID,
		Email:     uuid.Must(uuid.NewV7()).String() + "@agent-control.test",
		Name:      "Agent Control Admin",
		Role:      "org_admin",
		Password:  string(hashed),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, db.CreateUser(context.Background(), user))

	// Log in via the real HTTP server.
	loginBody, _ := json.Marshal(map[string]string{
		"email":    user.Email,
		"password": pw,
	})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json",
		bytes.NewReader(loginBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"login failed for agent-control admin")

	var loginResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&loginResp))
	token, ok := loginResp["token"].(string)
	require.True(t, ok, "login response must include token")
	return token
}

// adminHTTPCall issues an authenticated HTTP request to the test server and
// returns the decoded JSON body + status code. A nil body is marshalled as
// an empty POST body for methods that don't need one.
func adminHTTPCall(t *testing.T, baseURL, jwt, method, path string, body map[string]any) (map[string]any, int) {
	t.Helper()
	var bodyReader *strings.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		bodyReader = strings.NewReader(string(buf))
	} else {
		bodyReader = strings.NewReader("")
	}

	req, err := http.NewRequest(method, baseURL+path, bodyReader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+jwt)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, resp.StatusCode
}
