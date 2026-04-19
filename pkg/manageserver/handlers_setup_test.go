//go:build integration

package manageserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// --- /setup/admin -----------------------------------------------------------

func TestSetupAdmin_CreatesFirstAdminAndTransitions(t *testing.T) {
	srv, store, cleanup := openSetupServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := strings.NewReader(`{
		"email":"admin@example.com",
		"name":"Root Admin",
		"password":"Sup3rStr0ngPw!"
	}`)
	resp, err := http.Post(ts.URL+"/api/v1/setup/admin", "application/json", body)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, true, out["ok"])
	assert.NotEmpty(t, out["user_id"])

	// Setup state flipped AdminCreated=true.
	state, err := store.GetSetup(context.Background())
	require.NoError(t, err)
	assert.True(t, state.AdminCreated)

	// A second call must 409.
	body2 := strings.NewReader(`{
		"email":"other@example.com",
		"name":"Other",
		"password":"AnotherStr0ng!"
	}`)
	resp2, err := http.Post(ts.URL+"/api/v1/setup/admin", "application/json", body2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
}

func TestSetupAdmin_RejectsShortPassword(t *testing.T) {
	srv, _, cleanup := openSetupServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/setup/admin", "application/json",
		strings.NewReader(`{"email":"a@b.com","name":"A","password":"short1"}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, fmt.Sprintf("%v", out["error"]), "12 characters")
}

func TestSetupAdmin_RejectsPasswordWithoutDigit(t *testing.T) {
	srv, _, cleanup := openSetupServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/setup/admin", "application/json",
		strings.NewReader(`{"email":"a@b.com","name":"A","password":"longenoughbutnodigits"}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, fmt.Sprintf("%v", out["error"]), "digit")
}

// openSetupServer returns a fresh-DB Server+Store in setup mode (no admin,
// no licence activated). Mirrors openOperationalServer but skips the
// MarkAdminCreated + SaveLicenseActivation calls.
func openSetupServer(t *testing.T) (*manageserver.Server, *managestore.PostgresStore, func()) {
	t.Helper()
	schema := fmt.Sprintf("test_msrv_setup_%d", serverTestSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getTestDBURL(), schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store)
	require.NoError(t, err)

	cleanup := func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	}
	return srv, store, cleanup
}
