//go:build integration

package licenseserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// adminRoutes lists the method+path pairs that must all reject
// requests without a valid JWT. Keep in sync with pkg/licenseserver/
// server.go Admin route group.
func adminRoutes() []struct{ Method, Path string } {
	return []struct{ Method, Path string }{
		{http.MethodGet, "/api/v1/admin/orgs"},
		{http.MethodPost, "/api/v1/admin/orgs"},
		{http.MethodGet, "/api/v1/admin/orgs/x"},
		{http.MethodPut, "/api/v1/admin/orgs/x"},
		{http.MethodDelete, "/api/v1/admin/orgs/x"},
		{http.MethodGet, "/api/v1/admin/licenses"},
		{http.MethodPost, "/api/v1/admin/licenses"},
		{http.MethodGet, "/api/v1/admin/licenses/x"},
		{http.MethodPatch, "/api/v1/admin/licenses/x"},
		{http.MethodPost, "/api/v1/admin/licenses/x/revoke"},
		{http.MethodPost, "/api/v1/admin/licenses/x/agent-yaml"},
		{http.MethodPost, "/api/v1/admin/licenses/x/install-token"},
		{http.MethodPost, "/api/v1/admin/licenses/x/bundle"},
		{http.MethodGet, "/api/v1/admin/activations"},
		{http.MethodPost, "/api/v1/admin/activations/x/deactivate"},
		{http.MethodGet, "/api/v1/admin/audit"},
		{http.MethodGet, "/api/v1/admin/stats"},
		{http.MethodPost, "/api/v1/admin/binaries"},
		{http.MethodGet, "/api/v1/admin/binaries"},
		{http.MethodDelete, "/api/v1/admin/binaries/v/os/arch"},
		{http.MethodPost, "/api/v1/admin/superadmins/"},
		{http.MethodGet, "/api/v1/admin/superadmins/"},
		{http.MethodGet, "/api/v1/admin/superadmins/x"},
		{http.MethodPut, "/api/v1/admin/superadmins/x"},
		{http.MethodDelete, "/api/v1/admin/superadmins/x"},
	}
}

// jwtTestServer bundles a test server with its signing key so JWT
// middleware tests can mint tokens with the same key the server uses.
type jwtTestServer struct {
	ts         *httptest.Server
	store      *licensestore.PostgresStore
	signingKey ed25519.PrivateKey
}

// setupJWTTestServer creates a license server and exposes the signing key.
func setupJWTTestServer(t *testing.T) *jwtTestServer {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	schema := fmt.Sprintf("test_jwt_%d", serverTestSeq.Add(1))
	store, err := licensestore.NewPostgresStoreInSchema(ctx, dbURL, schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cfg := &licenseserver.Config{
		ListenAddr:  ":0",
		SigningKey:  priv,
		PublicKey:   pub,
		BinariesDir: t.TempDir(),
	}
	srv := licenseserver.New(cfg, store)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(func() {
		ts.Close()
		_ = store.DropSchema(ctx)
		store.Close()
	})
	return &jwtTestServer{ts: ts, store: store, signingKey: priv}
}

// loginViaAPIJWT logs in via POST /api/v1/auth/login and returns the JWT token.
func loginViaAPIJWT(t *testing.T, ts *httptest.Server, email, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "login must succeed")
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	token, ok := result["token"].(string)
	require.True(t, ok, "token must be a string")
	require.NotEmpty(t, token)
	return token
}

// seedAdminUser creates a platform_admin user directly in the store.
func seedAdminUser(t *testing.T, store *licensestore.PostgresStore, email, password string) *licensestore.User {
	t.Helper()
	ctx := context.Background()
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	user := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Email:    email,
		Name:     "JWT Test Admin",
		Role:     "platform_admin",
		Password: string(hashed),
	}
	require.NoError(t, store.CreateUser(ctx, user))
	return user
}

func TestAdminRoutes_NoToken_All401(t *testing.T) {
	ts, _ := setupTestServer(t)
	for _, rt := range adminRoutes() {
		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			req, err := http.NewRequest(rt.Method, ts.URL+rt.Path, nil)
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			// Must not be 200/403: middleware must reject BEFORE the handler.
			// 401 (no header) is the expected code; 404/405 acceptable for
			// paths that don't match chi's exact routing (method mismatch).
			assert.Contains(t, []int{401, 404, 405}, resp.StatusCode,
				"method=%s path=%s got=%d — admin route without JWT must not succeed",
				rt.Method, rt.Path, resp.StatusCode)
		})
	}
}

func TestJWT_MalformedToken_Returns401(t *testing.T) {
	ts, _ := setupTestServer(t)
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/stats", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer garbage")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWT_ValidToken_Succeeds(t *testing.T) {
	env := setupJWTTestServer(t)
	email := "jwtvalid-" + uuid.Must(uuid.NewV7()).String()[:8] + "@test.com"
	seedAdminUser(t, env.store, email, "pass1234")

	token := loginViaAPIJWT(t, env.ts, email, "pass1234")

	req, err := http.NewRequest(http.MethodGet, env.ts.URL+"/api/v1/admin/stats", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestJWT_ExpiredToken_Returns401(t *testing.T) {
	env := setupJWTTestServer(t)
	email := "jwtexpired-" + uuid.Must(uuid.NewV7()).String()[:8] + "@test.com"
	user := seedAdminUser(t, env.store, email, "pass1234")

	// Mint a JWT that already expired by using a negative TTL.
	// SignJWT sets Exp = now + ttl; a negative ttl puts Exp in the past.
	claims := &auth.UserClaims{
		Sub:  user.ID,
		Role: "platform_admin",
		Name: user.Name,
	}
	token, err := auth.SignJWT(claims, env.signingKey, -time.Hour)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, env.ts.URL+"/api/v1/admin/stats", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWT_RevokedSession_Returns401(t *testing.T) {
	env := setupJWTTestServer(t)
	email := "jwtrevoked-" + uuid.Must(uuid.NewV7()).String()[:8] + "@test.com"
	seedAdminUser(t, env.store, email, "pass1234")

	token := loginViaAPIJWT(t, env.ts, email, "pass1234")

	// Delete the session directly in the store to simulate revocation.
	h := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(h[:])
	ctx := context.Background()
	sess, err := env.store.GetSessionByHash(ctx, hash)
	require.NoError(t, err, "session must exist after login")
	require.NoError(t, env.store.DeleteSession(ctx, sess.ID))

	req, err := http.NewRequest(http.MethodGet, env.ts.URL+"/api/v1/admin/stats", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWT_DeletedUser_Returns401(t *testing.T) {
	env := setupJWTTestServer(t)
	email := "jwtdeleted-" + uuid.Must(uuid.NewV7()).String()[:8] + "@test.com"
	user := seedAdminUser(t, env.store, email, "pass1234")

	token := loginViaAPIJWT(t, env.ts, email, "pass1234")

	// Delete the user directly in the store.
	ctx := context.Background()
	require.NoError(t, env.store.DeleteUser(ctx, user.ID))

	req, err := http.NewRequest(http.MethodGet, env.ts.URL+"/api/v1/admin/stats", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWT_NonPlatformAdmin_Returns401(t *testing.T) {
	env := setupJWTTestServer(t)
	ctx := context.Background()
	email := "jwtorgadmin-" + uuid.Must(uuid.NewV7()).String()[:8] + "@test.com"

	// Create an org_admin user (not platform_admin) directly in the store.
	org := &licensestore.Organization{
		ID:   uuid.Must(uuid.NewV7()).String(),
		Name: "JWT Test Org",
	}
	require.NoError(t, env.store.CreateOrg(ctx, org))
	hashed, err := bcrypt.GenerateFromPassword([]byte("pass1234"), bcrypt.DefaultCost)
	require.NoError(t, err)
	user := &licensestore.User{
		ID:       uuid.Must(uuid.NewV7()).String(),
		OrgID:    org.ID,
		Email:    email,
		Name:     "Org Admin",
		Role:     "org_admin",
		Password: string(hashed),
	}
	require.NoError(t, env.store.CreateUser(ctx, user))

	// The login handler only accepts platform_admin — an org_admin cannot log
	// in to the license server at all. To test that the middleware still
	// rejects a JWT with role=org_admin (e.g., a forged or misrouted token),
	// mint one directly using the server's signing key, then create a matching
	// session so the session-check passes.
	claims := &auth.UserClaims{
		Sub:  user.ID,
		Role: "org_admin",
		Org:  org.ID,
		Name: user.Name,
	}
	token, err := auth.SignJWT(claims, env.signingKey, time.Hour)
	require.NoError(t, err)

	h := sha256.Sum256([]byte(token))
	sess := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: hex.EncodeToString(h[:]),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, env.store.CreateSession(ctx, sess))

	// org_admin JWT must be rejected on platform_admin-only routes.
	req, err := http.NewRequest(http.MethodGet, env.ts.URL+"/api/v1/admin/stats", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
