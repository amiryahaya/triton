//go:build integration

package scanjobs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// instanceMiddleware injects a fake instance ID into context for testing.
func instanceMiddleware(tenantID uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := orgctx.WithInstanceID(r.Context(), tenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func setupBatchHandlerServer(t *testing.T) (string, *scanjobs.PostgresStore, *hosts.PostgresStore, uuid.UUID, *pgxpool.Pool) {
	t.Helper()
	pool := newTestPool(t)
	store := scanjobs.NewPostgresStore(pool)
	hostsStore := hosts.NewPostgresStore(pool)
	tenantID := uuid.New()
	h := scanjobs.NewBatchHandlers(store, hostsStore)
	r := chi.NewRouter()
	r.Use(instanceMiddleware(tenantID))
	r.Post("/", h.EnqueueBatch)
	r.Get("/", h.ListBatches)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv.URL, store, hostsStore, tenantID, pool
}

// seedCredential inserts a minimal manage_credentials row and returns its ID.
func seedCredential(t *testing.T, pool *pgxpool.Pool, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	var credID uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO manage_credentials (tenant_id, name, auth_type, vault_path)
		 VALUES ($1, $2, 'ssh-key', 'secret/test')
		 RETURNING id`,
		tenantID, "cred-"+uuid.New().String()[:8],
	).Scan(&credID)
	require.NoError(t, err)
	return credID
}

func TestBatchHandler_EnqueueBoth_CreatesJobs(t *testing.T) {
	url, _, hostsStore, tenantID, pool := setupBatchHandlerServer(t)
	ctx := context.Background()

	// Seed a real credential so the FK on manage_hosts.credentials_ref is satisfied.
	credID := seedCredential(t, pool, tenantID)
	h1, err := hostsStore.Create(ctx, hosts.Host{Hostname: "web-01", IP: "10.0.1.1", ConnectionType: "ssh", CredentialsRef: &credID, SSHPort: 22})
	require.NoError(t, err)
	h2, err := hostsStore.Create(ctx, hosts.Host{Hostname: "db-01", IP: "10.0.1.2", ConnectionType: "agent"})
	require.NoError(t, err)
	// h3 has no credential — filesystem job will be skipped
	h3, err := hostsStore.Create(ctx, hosts.Host{Hostname: "mail-01", IP: "10.0.1.3", ConnectionType: "ssh"})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{
		"job_types": []string{"port_survey", "filesystem"},
		"host_ids":  []string{h1.ID.String(), h2.ID.String(), h3.ID.String()},
		"profile":   "standard",
	})
	resp, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var result scanjobs.BatchEnqueueResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.NotEqual(t, uuid.Nil, result.BatchID)
	// h1: port_survey + filesystem = 2 jobs
	// h2: port_survey + filesystem (agent) = 2 jobs
	// h3: port_survey only (no cred) = 1 job; filesystem skipped
	assert.Equal(t, 5, result.JobsCreated)
	require.Len(t, result.JobsSkipped, 1)
	assert.Equal(t, h3.ID, result.JobsSkipped[0].HostID)
	assert.Equal(t, "no_credential", result.JobsSkipped[0].Reason)
}

func TestBatchHandler_EmptyJobTypes_Returns400(t *testing.T) {
	url, _, _, _, _ := setupBatchHandlerServer(t)
	body, _ := json.Marshal(map[string]any{
		"job_types": []string{},
		"host_ids":  []string{uuid.New().String()},
		"profile":   "standard",
	})
	resp, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBatchHandler_EmptyHostIDs_Returns400(t *testing.T) {
	url, _, _, _, _ := setupBatchHandlerServer(t)
	body, _ := json.Marshal(map[string]any{
		"job_types": []string{"port_survey"},
		"host_ids":  []string{},
		"profile":   "standard",
	})
	resp, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBatchHandler_InvalidProfile_Returns400(t *testing.T) {
	url, _, _, _, _ := setupBatchHandlerServer(t)
	body, _ := json.Marshal(map[string]any{
		"job_types": []string{"port_survey"},
		"host_ids":  []string{uuid.New().String()},
		"profile":   "bogus",
	})
	resp, err := http.Post(url+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBatchHandler_ListBatches_FiltersByTenant(t *testing.T) {
	url, store, hostsStore, tenantID, _ := setupBatchHandlerServer(t)
	ctx := context.Background()

	// Seed a host to give the batch a valid FK.
	h, err := hostsStore.Create(ctx, hosts.Host{Hostname: "list-host", IP: "10.0.2.1", ConnectionType: "agent"})
	require.NoError(t, err)

	// Enqueue a batch via store directly (tenant matches the server's tenant).
	req := scanjobs.BatchEnqueueReq{
		TenantID: tenantID,
		JobTypes: []scanjobs.JobType{scanjobs.JobTypePortSurvey},
		HostIDs:  []uuid.UUID{h.ID},
		Profile:  scanjobs.ProfileQuick,
	}
	specs := []scanjobs.JobSpec{{HostID: h.ID, JobType: scanjobs.JobTypePortSurvey}}
	_, err = store.EnqueueBatch(ctx, req, specs, nil)
	require.NoError(t, err)

	// Enqueue a batch for a different tenant — must not appear in response.
	otherReq := scanjobs.BatchEnqueueReq{
		TenantID: uuid.New(),
		JobTypes: []scanjobs.JobType{scanjobs.JobTypePortSurvey},
		HostIDs:  []uuid.UUID{h.ID},
		Profile:  scanjobs.ProfileQuick,
	}
	_, err = store.EnqueueBatch(ctx, otherReq, specs, nil)
	require.NoError(t, err)

	resp, err := http.Get(url + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var batches []scanjobs.Batch
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&batches))
	assert.Len(t, batches, 1)
	assert.Equal(t, tenantID, batches[0].TenantID)
}
