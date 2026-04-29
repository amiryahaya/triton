//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// This file is intentionally self-contained: it does NOT reuse the
// helpers in license_server_test.go / license_flow_test.go because
// those helpers have pre-existing schema and response-shape bugs that
// silently skip their own test groups on main. A teammate PR is
// tracking that infrastructure work; this test avoids modifying those
// helpers to keep the blast radius narrow.

var schedTestSeq atomic.Int64

// newScheduleTestServer spins up a license server backed by an
// isolated PostgreSQL schema and returns the httptest URL and a Bearer
// JWT for an admin user already seeded into the store.
func newScheduleTestServer(t *testing.T) (serverURL, adminJWT string) {
	t.Helper()

	dbURL := "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	schema := fmt.Sprintf("sched_push_test_%d", schedTestSeq.Add(1))
	store, err := licensestore.NewPostgresStoreInSchema(context.Background(), dbURL, schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	})

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "binaries")

	cfg := &licenseserver.Config{
		PublicKey:   pub,
		SigningKey:  priv,
		BinariesDir: storagePath,
	}
	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	// Seed a platform_admin user and obtain a JWT.
	email, password := "sched-admin@test.local", "SchedAdminPass123!"
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	now := time.Now().UTC()
	u := &licensestore.User{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Email:     email,
		Name:      "Schedule Test Admin",
		Role:      "platform_admin",
		Password:  string(hashed),
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, store.CreateUser(context.Background(), u))

	b, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "admin login must succeed")
	var loginResult map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&loginResult))
	token, ok := loginResult["token"].(string)
	require.True(t, ok, "login response must contain token string")

	return ts.URL, token
}

// scheduleAdminReq sends an authenticated admin JSON request using a Bearer JWT.
func scheduleAdminReq(t *testing.T, method, url, jwt string, body any) *http.Response {
	t.Helper()
	var buf []byte
	if body != nil {
		var err error
		buf, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(buf))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// scheduleCreateOrg creates an org via admin API and returns its ID.
// Handles both the legacy flat shape {"id": "..."} and the current
// wrapped shape {"org": {"id": "..."}, ...}.
func scheduleCreateOrg(t *testing.T, serverURL, jwt string) string {
	t.Helper()
	resp := scheduleAdminReq(t, http.MethodPost, serverURL+"/api/v1/admin/orgs", jwt,
		map[string]string{"name": "ScheduleCo-" + uuid.Must(uuid.NewV7()).String()[:8]})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create org")
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	if nested, ok := body["org"].(map[string]any); ok {
		return nested["id"].(string)
	}
	return body["id"].(string)
}

// scheduleCreateLicense creates a license via admin API and returns its ID.
func scheduleCreateLicense(t *testing.T, serverURL, jwt, orgID string) string {
	t.Helper()
	resp := scheduleAdminReq(t, http.MethodPost, serverURL+"/api/v1/admin/licenses", jwt,
		map[string]any{"orgID": orgID, "tier": "pro", "seats": 1, "days": 30})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create license")
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body["id"].(string)
}

// schedulePatchLicense sends PATCH /api/v1/admin/licenses/{id} and
// asserts 200 OK.
func schedulePatchLicense(t *testing.T, serverURL, jwt, licID string, body map[string]any) {
	t.Helper()
	resp := scheduleAdminReq(t, http.MethodPatch, serverURL+"/api/v1/admin/licenses/"+licID, jwt, body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PATCH license %s", licID)
}

// TestPortalScheduleLifecycle exercises the full vertical slice:
// create license → activate machine → validate (no schedule pushed) →
// admin PATCHes a schedule → validate (schedule pushed) → admin
// clears the schedule → validate (schedule absent again).
func TestPortalScheduleLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	serverURL, adminJWT := newScheduleTestServer(t)

	// 1. Create org + license (no schedule initially).
	orgID := scheduleCreateOrg(t, serverURL, adminJWT)
	licID := scheduleCreateLicense(t, serverURL, adminJWT, orgID)

	// 2. Activate a machine.
	sc := license.NewServerClient(serverURL)
	act, err := sc.Activate(licID, license.ActivationTypeAgent)
	require.NoError(t, err, "Activate")
	require.NotEmpty(t, act.Token)

	// 3. Validate — no schedule pushed yet.
	val, err := sc.Validate(licID, act.Token)
	require.NoError(t, err)
	require.True(t, val.Valid)
	assert.Empty(t, val.Schedule, "initial validate should carry no schedule")
	assert.Zero(t, val.ScheduleJitterSeconds, "initial validate should carry no jitter")

	// 4. Admin PATCHes a schedule onto the license.
	schedulePatchLicense(t, serverURL, adminJWT, licID, map[string]any{
		"schedule":              "0 2 * * *",
		"scheduleJitterSeconds": 45,
	})

	// 5. Validate again — schedule now present.
	val, err = sc.Validate(licID, act.Token)
	require.NoError(t, err)
	require.True(t, val.Valid)
	assert.Equal(t, "0 2 * * *", val.Schedule)
	assert.Equal(t, 45, val.ScheduleJitterSeconds)

	// 6. Admin clears the schedule via empty string + zero jitter.
	schedulePatchLicense(t, serverURL, adminJWT, licID, map[string]any{
		"schedule":              "",
		"scheduleJitterSeconds": 0,
	})

	// 7. Validate — schedule absent again.
	val, err = sc.Validate(licID, act.Token)
	require.NoError(t, err)
	require.True(t, val.Valid)
	assert.Empty(t, val.Schedule, "validate after clear should carry no schedule")
	assert.Zero(t, val.ScheduleJitterSeconds, "validate after clear should carry no jitter")

	// 8. Admin rejects invalid cron via PATCH → 400.
	resp := scheduleAdminReq(t, http.MethodPatch, serverURL+"/api/v1/admin/licenses/"+licID, adminJWT,
		map[string]any{"schedule": "not a cron"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "invalid cron should 400")
}
