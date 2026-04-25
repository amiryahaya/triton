//go:build integration

// Network Discovery — HTTP-layer integration tests.
//
// These tests exercise the discovery handlers end-to-end against a real
// PostgreSQL schema without standing up the full Manage Server. Each test
// gets an isolated schema via managestore.NewPostgresStoreInSchema, wires
// the discovery routes onto a plain chi.Router, and fires HTTP requests
// against an httptest.Server.
//
// Tests are skipped automatically when PostgreSQL is unavailable.

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/discovery"
	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// discSchemaSeq monotonically allocates unique PG schemas so parallel test
// runs never collide on the shared triton_test database.
var discSchemaSeq atomic.Int64

// ---------------------------------------------------------------------------
// noopDiscWorker — WorkerRunner that does nothing so tests are synchronous.
// ---------------------------------------------------------------------------

type noopDiscWorker struct{}

func (w *noopDiscWorker) Run(_ context.Context, _ discovery.Job) {}

// ---------------------------------------------------------------------------
// discFixture — per-test server + stores + tenant.
// ---------------------------------------------------------------------------

type discFixture struct {
	pool       *pgxpool.Pool
	discStore  *discovery.PostgresStore
	hostsStore *hosts.PostgresStore
	tenantID   uuid.UUID
	srv        *httptest.Server
	cleanup    func()
}

// newDiscFixture creates an isolated schema, seeds the required manage_orgs
// row (the FK target of manage_discovery_jobs.tenant_id), wires the discovery
// routes onto an httptest.Server, and returns a *discFixture ready to use.
func newDiscFixture(t *testing.T) *discFixture {
	t.Helper()

	schema := fmt.Sprintf("test_discovery_%d", discSchemaSeq.Add(1))
	ms, err := managestore.NewPostgresStoreInSchema(context.Background(), getManageDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}

	pool := ms.Pool()

	// manage_orgs is the FK target of manage_discovery_jobs.tenant_id.
	// It is not created by the manage store migrations (the Manage server uses
	// manage_setup.instance_id as its single-tenant identity), so we create a
	// minimal stub table here to satisfy the FK constraint.
	_, err = pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS manage_orgs (
			id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			name       TEXT        NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	require.NoError(t, err, "create manage_orgs stub")

	tenantID := uuid.New()
	_, err = pool.Exec(context.Background(),
		`INSERT INTO manage_orgs (id, name) VALUES ($1, $2)`,
		tenantID, "test-org",
	)
	require.NoError(t, err, "insert test tenant into manage_orgs")

	hostsStore := hosts.NewPostgresStore(pool)
	discStore := discovery.NewPostgresStore(pool)

	worker := &noopDiscWorker{}
	h := discovery.NewAdminHandlers(discStore, hostsStore, worker, nil)

	r := chi.NewRouter()
	// Inject tenantID into every request context so HandleStart/HandleGet/
	// HandleCancel/HandleImport can call orgctx.InstanceIDFromContext.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(orgctx.WithInstanceID(req.Context(), tenantID)))
		})
	})
	discovery.MountAdminRoutes(r, h)

	srv := httptest.NewServer(r)

	return &discFixture{
		pool:       pool,
		discStore:  discStore,
		hostsStore: hostsStore,
		tenantID:   tenantID,
		srv:        srv,
		cleanup: func() {
			srv.Close()
			_ = ms.DropSchema(context.Background())
			_ = ms.Close()
		},
	}
}

// ---------------------------------------------------------------------------
// HTTP helpers local to this file.
// ---------------------------------------------------------------------------

func discGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	return resp
}

func discPostJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	return resp
}

func discReadBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return b
}

func discDecodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	b := discReadBody(t, resp)
	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out), "parse response body: %s", string(b))
	return out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestDiscoveryIntegration_GetNotFound — fresh schema → GET / returns 404.
func TestDiscoveryIntegration_GetNotFound(t *testing.T) {
	f := newDiscFixture(t)
	defer f.cleanup()

	resp := discGet(t, f.srv.URL+"/")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = discReadBody(t, resp)
}

// TestDiscoveryIntegration_StartAndGet — POST / with a valid CIDR creates a
// queued job; GET / returns that job with an empty candidates slice.
func TestDiscoveryIntegration_StartAndGet(t *testing.T) {
	f := newDiscFixture(t)
	defer f.cleanup()

	// /30 has 2 usable host IPs (network + broadcast removed), satisfying
	// the handler's countHosts logic without hitting the /16 cap.
	startResp := discPostJSON(t, f.srv.URL+"/", map[string]any{
		"cidr": "192.168.1.0/30",
	})
	startBody := discDecodeJSON(t, startResp)
	assert.Equal(t, http.StatusCreated, startResp.StatusCode,
		"POST / must return 201, got %v", startBody)

	assert.Equal(t, "queued", startBody["status"])
	assert.Equal(t, "192.168.1.0/30", startBody["cidr"])

	// GET / returns job + empty candidates.
	getResp := discGet(t, f.srv.URL+"/")
	getBody := discDecodeJSON(t, getResp)
	assert.Equal(t, http.StatusOK, getResp.StatusCode)

	job, ok := getBody["job"].(map[string]any)
	require.True(t, ok, "response must contain a 'job' object")
	assert.Equal(t, "queued", job["status"])

	candidates, ok := getBody["candidates"].([]any)
	require.True(t, ok, "response must contain a 'candidates' array")
	assert.Empty(t, candidates, "no candidates expected for a just-started no-op scan")
}

// TestDiscoveryIntegration_Singleton — a second POST / while a job is queued
// returns 409 Conflict.
func TestDiscoveryIntegration_Singleton(t *testing.T) {
	f := newDiscFixture(t)
	defer f.cleanup()

	first := discPostJSON(t, f.srv.URL+"/", map[string]any{"cidr": "10.0.0.0/30"})
	assert.Equal(t, http.StatusCreated, first.StatusCode)
	_ = discReadBody(t, first)

	second := discPostJSON(t, f.srv.URL+"/", map[string]any{"cidr": "10.0.0.0/30"})
	secondBody := discDecodeJSON(t, second)
	assert.Equal(t, http.StatusConflict, second.StatusCode,
		"second POST / must return 409 while first job is queued, got %v", secondBody)
}

// TestDiscoveryIntegration_NewScanReplacesOld — after marking the current job
// as "completed" directly in the DB, a second POST / creates a new job.
func TestDiscoveryIntegration_NewScanReplacesOld(t *testing.T) {
	f := newDiscFixture(t)
	defer f.cleanup()

	// Start first job.
	first := discPostJSON(t, f.srv.URL+"/", map[string]any{"cidr": "10.0.0.0/30"})
	require.Equal(t, http.StatusCreated, first.StatusCode)
	var firstJob map[string]any
	require.NoError(t, json.Unmarshal(discReadBody(t, first), &firstJob))
	firstID, _ := firstJob["id"].(string)

	// Simulate the worker finishing: update status to "completed" directly.
	now := time.Now().UTC()
	_, err := f.pool.Exec(context.Background(),
		`UPDATE manage_discovery_jobs
		 SET status = 'completed', finished_at = $1
		 WHERE id = $2`,
		now, firstID,
	)
	require.NoError(t, err)

	// Now a second POST / should be accepted (no active job).
	second := discPostJSON(t, f.srv.URL+"/", map[string]any{"cidr": "10.0.1.0/30"})
	secondBody := discDecodeJSON(t, second)
	assert.Equal(t, http.StatusCreated, second.StatusCode,
		"POST / must succeed after previous job completed, got %v", secondBody)

	secondID, _ := secondBody["id"].(string)
	assert.NotEqual(t, firstID, secondID, "new job must have a different ID")

	// GET / now returns the second job only (CreateJob deletes the old one).
	getResp := discGet(t, f.srv.URL+"/")
	getBody := discDecodeJSON(t, getResp)
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	job := getBody["job"].(map[string]any)
	assert.Equal(t, secondID, job["id"])
	assert.Equal(t, "10.0.1.0/30", job["cidr"])
}

// TestDiscoveryIntegration_ImportFlow — inserts a candidate directly into the
// DB, then calls POST /import; verifies the candidate is created in manage_hosts.
func TestDiscoveryIntegration_ImportFlow(t *testing.T) {
	f := newDiscFixture(t)
	defer f.cleanup()

	// Start a job so a job row exists for the candidate FK.
	startResp := discPostJSON(t, f.srv.URL+"/", map[string]any{"cidr": "172.16.0.0/30"})
	require.Equal(t, http.StatusCreated, startResp.StatusCode)
	var job map[string]any
	require.NoError(t, json.Unmarshal(discReadBody(t, startResp), &job))
	jobID := job["id"].(string)

	// Insert a candidate directly.
	var candidateID uuid.UUID
	err := f.pool.QueryRow(context.Background(),
		`INSERT INTO manage_discovery_candidates (job_id, ip, open_ports)
		 VALUES ($1, '172.16.0.1', '{22}')
		 RETURNING id`,
		jobID,
	).Scan(&candidateID)
	require.NoError(t, err)

	// POST /import with the candidate ID and a hostname.
	importResp := discPostJSON(t, f.srv.URL+"/import", map[string]any{
		"candidates": []map[string]any{
			{"id": candidateID.String(), "hostname": "test-host.local"},
		},
	})
	importBody := discDecodeJSON(t, importResp)
	assert.Equal(t, http.StatusOK, importResp.StatusCode,
		"POST /import must return 200, got %v", importBody)

	imported, _ := importBody["imported"].(float64)
	assert.Equal(t, float64(1), imported, "exactly 1 host should be imported")

	// Verify the host was created in manage_hosts.
	count, err := f.hostsStore.Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "manage_hosts should contain the imported host")
}
