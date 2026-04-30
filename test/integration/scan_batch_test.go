//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// batchSchemaSeq allocates unique PG schemas so parallel tests don't collide.
var batchSchemaSeq atomic.Int64

type batchFixture struct {
	pool       *pgxpool.Pool
	hostsStore *hosts.PostgresStore
	batchStore *scanjobs.PostgresStore
	tenantID   uuid.UUID
	srv        *httptest.Server
	cleanup    func()
}

func newBatchFixture(t *testing.T) *batchFixture {
	t.Helper()

	schema := fmt.Sprintf("test_scanbatch_%d", batchSchemaSeq.Add(1))
	ms, err := managestore.NewPostgresStoreInSchema(context.Background(), getManageDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}

	pool := ms.Pool()
	tenantID := uuid.New()

	hostsStore := hosts.NewPostgresStore(pool)
	batchStore := scanjobs.NewPostgresStore(pool)

	hostsH := hosts.NewAdminHandlers(hostsStore, nil)
	batchH := scanjobs.NewBatchHandlers(batchStore, hostsStore)

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
			next.ServeHTTP(w, rq.WithContext(orgctx.WithInstanceID(rq.Context(), tenantID)))
		})
	})
	hosts.MountAdminRoutes(r, hostsH)
	r.Route("/scan-batches", func(r chi.Router) {
		scanjobs.MountBatchRoutes(r, batchH)
	})

	srv := httptest.NewServer(r)

	return &batchFixture{
		pool:       pool,
		hostsStore: hostsStore,
		batchStore: batchStore,
		tenantID:   tenantID,
		srv:        srv,
		cleanup: func() {
			srv.Close()
			_ = ms.DropSchema(context.Background())
			_ = ms.Close()
		},
	}
}

// batchInsertHost creates a host via the admin API and returns its UUID.
func batchInsertHost(t *testing.T, baseURL string, h hosts.Host) uuid.UUID {
	t.Helper()
	body, _ := json.Marshal(h)
	resp, err := http.Post(baseURL+"/", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created hosts.Host
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	return created.ID
}

// postBatch sends POST /scan-batches and returns the status code + decoded body.
func postBatch(t *testing.T, baseURL string, body any) (int, scanjobs.BatchEnqueueResp) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/scan-batches", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	var result scanjobs.BatchEnqueueResp
	if resp.StatusCode == http.StatusCreated {
		_ = json.NewDecoder(resp.Body).Decode(&result)
	}
	return resp.StatusCode, result
}

// seedCredentialInPool inserts a minimal manage_credentials row for FK satisfaction.
func seedCredentialInPool(t *testing.T, pool *pgxpool.Pool, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO manage_credentials (tenant_id, name, auth_type, vault_path)
		 VALUES ($1, $2, 'ssh-key', 'secret/test') RETURNING id`,
		tenantID, "cred-"+uuid.New().String()[:8],
	).Scan(&id)
	require.NoError(t, err)
	return id
}

func TestScanBatch_PortSurveyOnly_AllHostsGetJob(t *testing.T) {
	f := newBatchFixture(t)
	defer f.cleanup()

	h1 := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "ps-01", IP: "10.1.0.1", ConnectionType: "ssh"})
	h2 := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "ps-02", IP: "10.1.0.2", ConnectionType: "ssh"})

	code, resp := postBatch(t, f.srv.URL, map[string]any{
		"job_types": []string{"port_survey"},
		"host_ids":  []string{h1.String(), h2.String()},
		"profile":   "quick",
	})
	assert.Equal(t, http.StatusCreated, code)
	assert.Equal(t, 2, resp.JobsCreated)
	assert.Empty(t, resp.JobsSkipped)
	assert.NotEqual(t, uuid.Nil, resp.BatchID)
}

func TestScanBatch_BothJobTypes_SkipsUnconfiguredFilesystem(t *testing.T) {
	f := newBatchFixture(t)
	defer f.cleanup()

	credID := seedCredentialInPool(t, f.pool, f.tenantID)

	hSSH := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "ssh-01", IP: "10.2.0.1", ConnectionType: "ssh", CredentialsRef: &credID, SSHPort: 22})
	hAgent := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "agent-01", IP: "10.2.0.2", ConnectionType: "agent"})
	hNone := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "none-01", IP: "10.2.0.3", ConnectionType: "ssh"})

	code, resp := postBatch(t, f.srv.URL, map[string]any{
		"job_types": []string{"port_survey", "filesystem"},
		"host_ids":  []string{hSSH.String(), hAgent.String(), hNone.String()},
		"profile":   "standard",
	})
	assert.Equal(t, http.StatusCreated, code)
	// hSSH: port_survey + filesystem = 2 jobs
	// hAgent: port_survey + filesystem (agent) = 2 jobs
	// hNone: port_survey = 1 job (filesystem skipped — no cred, no agent)
	assert.Equal(t, 5, resp.JobsCreated)
	require.Len(t, resp.JobsSkipped, 1)
	assert.Equal(t, hNone, resp.JobsSkipped[0].HostID)
	assert.Equal(t, "no_credential", resp.JobsSkipped[0].Reason)
}

func TestScanBatch_EmptyJobTypes_Returns400(t *testing.T) {
	f := newBatchFixture(t)
	defer f.cleanup()

	code, _ := postBatch(t, f.srv.URL, map[string]any{
		"job_types": []string{},
		"host_ids":  []string{uuid.New().String()},
		"profile":   "standard",
	})
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestScanBatch_EmptyHostIDs_Returns400(t *testing.T) {
	f := newBatchFixture(t)
	defer f.cleanup()

	code, _ := postBatch(t, f.srv.URL, map[string]any{
		"job_types": []string{"port_survey"},
		"host_ids":  []string{},
		"profile":   "standard",
	})
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestScanBatch_BatchStartsQueued_VisibleInList(t *testing.T) {
	f := newBatchFixture(t)
	defer f.cleanup()

	h1 := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "batch-h1", IP: "10.3.0.1", ConnectionType: "ssh"})

	_, resp := postBatch(t, f.srv.URL, map[string]any{
		"job_types": []string{"port_survey"},
		"host_ids":  []string{h1.String()},
		"profile":   "quick",
	})
	require.NotEqual(t, uuid.Nil, resp.BatchID)

	getResp, err := http.Get(f.srv.URL + "/scan-batches")
	require.NoError(t, err)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)

	var batches []scanjobs.Batch
	require.NoError(t, json.NewDecoder(getResp.Body).Decode(&batches))
	require.Len(t, batches, 1)
	assert.Equal(t, scanjobs.BatchStatusQueued, batches[0].Status)
	assert.Equal(t, resp.BatchID, batches[0].ID)
}

func TestScanBatch_ResourceLimits_PropagateToChildJobs(t *testing.T) {
	f := newBatchFixture(t)
	defer f.cleanup()

	h := batchInsertHost(t, f.srv.URL, hosts.Host{Hostname: "rl-01", IP: "10.4.0.1", ConnectionType: "ssh"})
	cpu, mem, dur := 50, 1024, 3600

	code, resp := postBatch(t, f.srv.URL, map[string]any{
		"job_types":      []string{"port_survey"},
		"host_ids":       []string{h.String()},
		"profile":        "quick",
		"max_cpu_pct":    cpu,
		"max_memory_mb":  mem,
		"max_duration_s": dur,
	})
	require.Equal(t, http.StatusCreated, code)
	assert.Equal(t, 1, resp.JobsCreated)

	// Verify child job inherited resource limits from the batch.
	jobs, err := f.batchStore.List(context.Background(), f.tenantID, 10)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	require.NotNil(t, jobs[0].MaxCPUPct)
	assert.Equal(t, cpu, *jobs[0].MaxCPUPct)
	require.NotNil(t, jobs[0].MaxMemoryMB)
	assert.Equal(t, mem, *jobs[0].MaxMemoryMB)
	require.NotNil(t, jobs[0].MaxDurationS)
	assert.Equal(t, dur, *jobs[0].MaxDurationS)
}
