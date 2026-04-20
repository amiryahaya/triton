//go:build integration

package manageserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

var serverTestSeq atomic.Int64

// testJWTKey is a fixed 32-byte key for tests — deterministic, easier to debug.
var testJWTKey = []byte("manage-server-test-jwt-key-32byt")

func getTestDBURL() string {
	if u := os.Getenv("TRITON_TEST_DB_URL"); u != "" {
		return u
	}
	return "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
}

// openTestServer creates a Server wired to an isolated PG schema + fixed JWT key.
// Returns (*manageserver.Server, cleanup func).
func openTestServer(t *testing.T) (*manageserver.Server, func()) {
	t.Helper()
	schema := fmt.Sprintf("test_msrv_%d", serverTestSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getTestDBURL(), schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		SessionTTL:    0, // let New() default to 24h
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err, "New() must succeed on a fresh DB")

	cleanup := func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	}
	return srv, cleanup
}

func TestNew_ValidConfigSucceeds(t *testing.T) {
	_, cleanup := openTestServer(t)
	defer cleanup()
}

func TestNew_RejectsShortJWTKey(t *testing.T) {
	schema := fmt.Sprintf("test_msrv_%d", serverTestSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getTestDBURL(), schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	})

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: []byte("tooshort"),
	}
	_, err = manageserver.New(cfg, store, store.Pool())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "≥32 bytes")
}

func TestNew_SetsSetupMode_FreshDB(t *testing.T) {
	srv, cleanup := openTestServer(t)
	defer cleanup()

	// Fresh DB: no admin, no license → setup mode = true.
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["setup_mode"], "fresh DB should be in setup mode")
}

func TestHealth_ReturnsOK(t *testing.T) {
	srv, cleanup := openTestServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
}

func TestHealth_ReportsSetupMode(t *testing.T) {
	srv, cleanup := openTestServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	// Fresh DB means setup_mode=true.
	assert.Equal(t, true, body["setup_mode"])
}

func TestSetupStatus_FreshDB(t *testing.T) {
	srv, cleanup := openTestServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/setup/status")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["admin_created"], "fresh DB: admin_created=false")
	assert.Equal(t, false, body["license_activated"], "fresh DB: license_activated=false")
	assert.Equal(t, true, body["setup_required"], "fresh DB: setup_required=true")
}
