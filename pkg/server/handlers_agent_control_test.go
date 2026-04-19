//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/store"
)

// testMachineID is a fixed 64-char hex string used across agent-control
// tests when the caller doesn't care about collision isolation. Tests
// that need a second distinct machine use testMachineIDB.
const (
	testMachineID  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testMachineIDB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// shrinkAgentPollTiming tightens the long-poll timing for the duration
// of a test so the 204-path doesn't block for a real 30 seconds. Restores
// the defaults in t.Cleanup. All tests in this file call this helper.
func shrinkAgentPollTiming(t *testing.T) {
	t.Helper()
	origTimeout, origInterval := agentPollTimeout, agentPollInterval
	agentPollTimeout = 300 * time.Millisecond
	agentPollInterval = 20 * time.Millisecond
	t.Cleanup(func() {
		agentPollTimeout = origTimeout
		agentPollInterval = origInterval
	})
}

// newAgentControlServer builds a report server configured with BOTH
// JWT auth (for admin endpoints) and a license-token key (for the
// agent-facing endpoints). Returns the server, store, a pre-minted
// agent license token, and the tenant/org ID that token resolves to.
//
// The tenant org is created in the DB so admin users created against
// it pass the FK constraints on the users table.
func newAgentControlServer(t *testing.T) (*Server, *store.PostgresStore, string, string) {
	t.Helper()
	db := mustTestDB(t)

	// Separate keypairs for JWT (user) vs license (agent) auth — matches
	// the production wiring where the report server signs its own JWTs
	// but verifies licence tokens against the license-server pubkey.
	jwtPub, jwtPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	licPub, licPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Use a valid UUID for the org since the migrations type the
	// agents.tenant_id column as UUID.
	orgID := uuid.Must(uuid.NewV7()).String()
	ctx := context.Background()
	require.NoError(t, db.CreateOrg(ctx, &store.Organization{
		ID:        orgID,
		Name:      "agent-control-test-org",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	cfg := &Config{
		ListenAddr:    ":0",
		JWTSigningKey: jwtPriv,
		JWTPublicKey:  jwtPub,
		TenantPubKey:  licPub,
	}
	srv, err := New(cfg, db)
	require.NoError(t, err)

	lic := &license.License{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Tier:      license.TierPro,
		OrgID:     orgID,
		Org:       "agent-control-test-org",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token, err := license.Encode(lic, licPriv)
	require.NoError(t, err)

	return srv, db, token, orgID
}

// mustTestDB constructs the shared Postgres test store using the
// same env-var pattern as testServer. Skips on connect failure.
func mustTestDB(t *testing.T) *store.PostgresStore {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	db, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	require.NoError(t, db.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = db.TruncateAll(ctx)
		db.Close()
	})
	return db
}

// ============================================================================
// Agent-facing tests — poll + result
// ============================================================================

func TestAgentPoll_EmptyReturns204(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, token, orgID := newAgentControlServer(t)

	code, _ := pollAgent(t, srv, token, testMachineID, "host-a", "linux", "amd64", nil)
	assert.Equal(t, http.StatusNoContent, code, "fresh agent with no state must get 204")

	// Agent row was created.
	agent, err := db.GetAgent(context.Background(), orgID, testMachineID)
	require.NoError(t, err)
	assert.Equal(t, "host-a", agent.Hostname)
	assert.Equal(t, "linux", agent.OS)
	assert.Equal(t, "amd64", agent.Arch)
}

func TestAgentPoll_ReturnsPausedUntil(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, token, orgID := newAgentControlServer(t)

	// First poll registers the agent row.
	code, _ := pollAgent(t, srv, token, testMachineID, "host-a", "linux", "amd64", nil)
	require.Equal(t, http.StatusNoContent, code)

	pausedUntil := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, db.SetAgentPausedUntil(context.Background(), orgID, testMachineID, pausedUntil))

	code, resp := pollAgent(t, srv, token, testMachineID, "host-a", "linux", "amd64", nil)
	require.Equal(t, http.StatusOK, code)

	state, ok := resp["state"].(map[string]any)
	require.True(t, ok, "response must include state: %v", resp)
	rawPU, ok := state["pausedUntil"].(string)
	require.True(t, ok, "state.pausedUntil must be a string: %v", state)

	got, err := time.Parse(time.RFC3339Nano, rawPU)
	require.NoError(t, err)
	assert.WithinDuration(t, pausedUntil, got, time.Second)
}

func TestAgentPoll_ClaimsAndDispatchesCommand(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, token, orgID := newAgentControlServer(t)

	// Register the agent first.
	code, _ := pollAgent(t, srv, token, testMachineID, "host-a", "linux", "amd64", nil)
	require.Equal(t, http.StatusNoContent, code)

	// Enqueue a command directly in the store.
	cmd, err := db.EnqueueAgentCommand(context.Background(), &store.AgentCommand{
		ID:        uuid.Must(uuid.NewV7()).String(),
		TenantID:  orgID,
		MachineID: testMachineID,
		Type:      store.AgentCommandCancel,
		Args:      json.RawMessage(`{}`),
		IssuedBy:  "test",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	code, resp := pollAgent(t, srv, token, testMachineID, "host-a", "linux", "amd64", nil)
	require.Equal(t, http.StatusOK, code)
	cmds, ok := resp["commands"].([]any)
	require.True(t, ok, "response must include commands: %v", resp)
	require.Len(t, cmds, 1)
	first, _ := cmds[0].(map[string]any)
	assert.Equal(t, cmd.ID, first["id"])
	assert.Equal(t, "cancel", first["type"])

	// Second poll returns 204 — the claim already marked it dispatched.
	code2, _ := pollAgent(t, srv, token, testMachineID, "host-a", "linux", "amd64", nil)
	assert.Equal(t, http.StatusNoContent, code2, "already-dispatched command must not be re-claimed")
}

func TestAgentResult_Success(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, token, orgID := newAgentControlServer(t)

	// Register + enqueue + poll to mark as dispatched.
	_, _ = pollAgent(t, srv, token, testMachineID, "host-a", "linux", "amd64", nil)
	cmd, err := db.EnqueueAgentCommand(context.Background(), &store.AgentCommand{
		ID:        uuid.Must(uuid.NewV7()).String(),
		TenantID:  orgID,
		MachineID: testMachineID,
		Type:      store.AgentCommandForceRun,
		Args:      json.RawMessage(`{}`),
		IssuedBy:  "test",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)
	_, _ = pollAgent(t, srv, token, testMachineID, "host-a", "linux", "amd64", nil)

	code := postResult(t, srv, token, testMachineID, cmd.ID, "executed", map[string]any{"ok": true})
	assert.Equal(t, http.StatusOK, code)

	// Verify result persisted.
	cmds, err := db.ListAgentCommands(context.Background(), orgID, testMachineID, 10)
	require.NoError(t, err)
	require.Len(t, cmds, 1)
	require.NotNil(t, cmds[0].ResultStatus)
	assert.Equal(t, "executed", *cmds[0].ResultStatus)
}

func TestAgentResult_CrossAgentRejected(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, token, orgID := newAgentControlServer(t)

	// Two machines in the same tenant.
	_, _ = pollAgent(t, srv, token, testMachineID, "host-a", "linux", "amd64", nil)
	_, _ = pollAgent(t, srv, token, testMachineIDB, "host-b", "linux", "amd64", nil)

	// Enqueue a command for machine A.
	cmd, err := db.EnqueueAgentCommand(context.Background(), &store.AgentCommand{
		ID:        uuid.Must(uuid.NewV7()).String(),
		TenantID:  orgID,
		MachineID: testMachineID,
		Type:      store.AgentCommandCancel,
		Args:      json.RawMessage(`{}`),
		IssuedBy:  "test",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	// Machine B tries to ack machine A's command — must 404.
	code := postResult(t, srv, token, testMachineIDB, cmd.ID, "executed", nil)
	assert.Equal(t, http.StatusNotFound, code, "cross-agent result must be rejected")
}

// ============================================================================
// Admin-facing tests — list / get / pause / enqueue
// ============================================================================

// newAdminJWTForOrg creates an org_admin user in the given org and logs
// in, returning the bearer token. Reuses createTestUserInOrg from the
// existing test infrastructure so we get bcrypt hashing + email uniqueness
// for free.
func newAdminJWTForOrg(t *testing.T, srv *Server, db *store.PostgresStore, orgID string) string {
	t.Helper()
	pw := "correct-horse-battery-staple"
	_, user := createTestUserInOrg(t, db, orgID, "org_admin", pw, false)
	return loginAndExtractToken(t, srv, user.Email, pw)
}

func TestAdminAgents_List(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, licToken, orgID := newAgentControlServer(t)
	adminJWT := newAdminJWTForOrg(t, srv, db, orgID)

	// Agent registers via poll.
	_, _ = pollAgent(t, srv, licToken, testMachineID, "host-a", "linux", "amd64", nil)

	code, resp := adminGet(t, srv, adminJWT, "/api/v1/admin/agents/")
	require.Equal(t, http.StatusOK, code, "body: %v", resp)
	agents, ok := resp["agents"].([]any)
	require.True(t, ok, "response must include agents array: %v", resp)
	require.Len(t, agents, 1)
	first := agents[0].(map[string]any)
	assert.Equal(t, testMachineID, first["machineID"])
	assert.Equal(t, "host-a", first["hostname"])
}

func TestAdminAgents_Pause(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, licToken, orgID := newAgentControlServer(t)
	adminJWT := newAdminJWTForOrg(t, srv, db, orgID)

	_, _ = pollAgent(t, srv, licToken, testMachineID, "host-a", "linux", "amd64", nil)

	code, resp := adminPost(t, srv, adminJWT,
		"/api/v1/admin/agents/"+testMachineID+"/pause",
		map[string]any{"durationSeconds": 3600})
	require.Equal(t, http.StatusOK, code, "body: %v", resp)

	agent, err := db.GetAgent(context.Background(), orgID, testMachineID)
	require.NoError(t, err)
	assert.False(t, agent.PausedUntil.IsZero(), "paused_until must be set")
	assert.True(t, agent.PausedUntil.After(time.Now()), "paused_until must be in the future")
}

func TestAdminAgents_PauseOverCap(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, licToken, orgID := newAgentControlServer(t)
	adminJWT := newAdminJWTForOrg(t, srv, db, orgID)

	_, _ = pollAgent(t, srv, licToken, testMachineID, "host-a", "linux", "amd64", nil)

	// 91 days exceeds the 90-day cap.
	code, resp := adminPost(t, srv, adminJWT,
		"/api/v1/admin/agents/"+testMachineID+"/pause",
		map[string]any{"durationSeconds": 91 * 24 * 3600})
	require.Equal(t, http.StatusBadRequest, code)
	errMsg, _ := resp["error"].(string)
	assert.Contains(t, strings.ToLower(errMsg), "90", "error must mention the 90-day cap: %s", errMsg)
}

func TestAdminAgents_EnqueueCancel(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, licToken, orgID := newAgentControlServer(t)
	adminJWT := newAdminJWTForOrg(t, srv, db, orgID)

	_, _ = pollAgent(t, srv, licToken, testMachineID, "host-a", "linux", "amd64", nil)

	code, resp := adminPost(t, srv, adminJWT,
		"/api/v1/admin/agents/"+testMachineID+"/commands",
		map[string]any{"type": "cancel"})
	require.Equal(t, http.StatusCreated, code, "body: %v", resp)
	assert.Equal(t, "cancel", resp["type"])
	assert.NotEmpty(t, resp["id"])

	// Command is queryable via store.
	cmds, err := db.ListAgentCommands(context.Background(), orgID, testMachineID, 10)
	require.NoError(t, err)
	require.Len(t, cmds, 1)
	assert.Equal(t, store.AgentCommandCancel, cmds[0].Type)
}

func TestAdminAgents_EnqueueInvalidType(t *testing.T) {
	shrinkAgentPollTiming(t)
	srv, db, licToken, orgID := newAgentControlServer(t)
	adminJWT := newAdminJWTForOrg(t, srv, db, orgID)

	_, _ = pollAgent(t, srv, licToken, testMachineID, "host-a", "linux", "amd64", nil)

	code, _ := adminPost(t, srv, adminJWT,
		"/api/v1/admin/agents/"+testMachineID+"/commands",
		map[string]any{"type": "reformat_disk"})
	assert.Equal(t, http.StatusBadRequest, code)
}

// ============================================================================
// HTTP helpers
// ============================================================================

func pollAgent(
	t *testing.T,
	srv *Server,
	licToken, machineID, hostname, os_, arch string,
	extraHeaders map[string]string,
) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/commands/poll", nil)
	req.Header.Set(licenseTokenHeader, licToken)
	req.Header.Set(machineIDHeader, machineID)
	if hostname != "" {
		req.Header.Set("X-Triton-Hostname", hostname)
	}
	if os_ != "" {
		req.Header.Set("X-Triton-Agent-OS", os_)
	}
	if arch != "" {
		req.Header.Set("X-Triton-Agent-Arch", arch)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code == http.StatusNoContent || w.Body.Len() == 0 {
		return w.Code, nil
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("pollAgent decode body (status %d): %v; raw=%s", w.Code, err, w.Body.String())
	}
	return w.Code, resp
}

func postResult(
	t *testing.T,
	srv *Server,
	licToken, machineID, commandID, status string,
	meta map[string]any,
) int {
	t.Helper()
	body := map[string]any{"status": status}
	if meta != nil {
		body["meta"] = meta
	}
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/agent/commands/"+commandID+"/result",
		bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(licenseTokenHeader, licToken)
	req.Header.Set(machineIDHeader, machineID)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	return w.Code
}

func adminGet(t *testing.T, srv *Server, jwt, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Body.Len() == 0 {
		return w.Code, nil
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("adminGet decode body (status %d): %v; raw=%s", w.Code, err, w.Body.String())
	}
	return w.Code, resp
}

func adminPost(t *testing.T, srv *Server, jwt, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Body.Len() == 0 {
		return w.Code, nil
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("adminPost decode body (status %d): %v; raw=%s", w.Code, err, w.Body.String())
	}
	return w.Code, resp
}
