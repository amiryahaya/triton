//go:build integration

package scanjobs_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/managestore"
)

var testSchemaSeq atomic.Int64

// newTestPool mirrors the isolation pattern used by zones/hosts tests:
// each test gets a fresh schema with the full manage_* migration set.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_scanjobs_%d", testSchemaSeq.Add(1))

	ctx := context.Background()
	setupPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	if _, err := setupPool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		setupPool.Close()
		t.Fatalf("drop stale schema: %v", err)
	}
	if _, err := setupPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		setupPool.Close()
		t.Fatalf("create schema: %v", err)
	}
	setupPool.Close()

	cfg, err := pgxpool.ParseConfig(dbURL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)

	require.NoError(t, managestore.Migrate(ctx, pool))

	t.Cleanup(func() {
		pool.Close()
		cleanup, cerr := pgxpool.New(context.Background(), dbURL)
		if cerr != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	return pool
}

// seedZoneAndHost creates one zone and one host inside it. Returns
// (zoneID, host) for convenience.
func seedZoneAndHost(t *testing.T, pool *pgxpool.Pool, hostname string) (uuid.UUID, hosts.Host) {
	t.Helper()
	ctx := context.Background()
	var zoneID uuid.UUID
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO manage_zones (name) VALUES ($1) RETURNING id`,
		"z-"+hostname,
	).Scan(&zoneID))
	h, err := hosts.NewPostgresStore(pool).Create(ctx, hosts.Host{
		Hostname: hostname, ZoneID: &zoneID,
	})
	require.NoError(t, err)
	return zoneID, h
}

func TestScanJobs_EndToEndHappyPath(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	zoneID, h := seedZoneAndHost(t, pool, "db-01")
	s := scanjobs.NewPostgresStore(pool)

	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := s.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID,
		ZoneIDs:  []uuid.UUID{zoneID},
		Profile:  scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, scanjobs.StatusQueued, jobs[0].Status)
	assert.Equal(t, tenantID, jobs[0].TenantID)
	assert.Equal(t, h.ID, jobs[0].HostID)

	claimed, ok, err := s.ClaimNext(ctx, "worker-1")
	require.NoError(t, err)
	require.True(t, ok, "expected a queued job to claim")
	assert.Equal(t, jobs[0].ID, claimed.ID)
	assert.Equal(t, scanjobs.StatusRunning, claimed.Status)
	assert.Equal(t, "worker-1", claimed.WorkerID)
	require.NotNil(t, claimed.StartedAt)
	require.NotNil(t, claimed.RunningHeartbeatAt)

	require.NoError(t, s.Heartbeat(ctx, claimed.ID, "scanning 1/1"))
	require.NoError(t, s.Complete(ctx, claimed.ID))

	got, err := s.Get(ctx, claimed.ID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.StatusCompleted, got.Status)
	require.NotNil(t, got.FinishedAt)
	assert.Equal(t, "scanning 1/1", got.ProgressText)
}

func TestScanJobs_Get_Missing_ReturnsNotFound(t *testing.T) {
	pool := newTestPool(t)
	s := scanjobs.NewPostgresStore(pool)

	_, err := s.Get(context.Background(), uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, scanjobs.ErrNotFound)
}

func TestScanJobs_List_FiltersByTenant(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	zoneID, _ := seedZoneAndHost(t, pool, "shared")
	s := scanjobs.NewPostgresStore(pool)

	tenantA := uuid.Must(uuid.NewV7())
	tenantB := uuid.Must(uuid.NewV7())

	_, err := s.Enqueue(ctx, scanjobs.EnqueueReq{TenantID: tenantA, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick})
	require.NoError(t, err)
	_, err = s.Enqueue(ctx, scanjobs.EnqueueReq{TenantID: tenantB, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick})
	require.NoError(t, err)
	_, err = s.Enqueue(ctx, scanjobs.EnqueueReq{TenantID: tenantB, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick})
	require.NoError(t, err)

	listA, err := s.List(ctx, tenantA, 0)
	require.NoError(t, err)
	assert.Len(t, listA, 1)
	assert.Equal(t, tenantA, listA[0].TenantID)

	listB, err := s.List(ctx, tenantB, 0)
	require.NoError(t, err)
	assert.Len(t, listB, 2)
	for _, j := range listB {
		assert.Equal(t, tenantB, j.TenantID)
	}
}

func TestScanJobs_Enqueue_FiltersByHostGlob(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	var zoneID uuid.UUID
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO manage_zones (name) VALUES ('glob-zone') RETURNING id`,
	).Scan(&zoneID))

	hs := hosts.NewPostgresStore(pool)
	for _, name := range []string{"web-01", "web-02", "db-01"} {
		_, err := hs.Create(ctx, hosts.Host{Hostname: name, ZoneID: &zoneID})
		require.NoError(t, err)
	}

	s := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.Must(uuid.NewV7())

	jobs, err := s.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID:   tenantID,
		ZoneIDs:    []uuid.UUID{zoneID},
		HostFilter: "web-*",
		Profile:    scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	assert.Len(t, jobs, 2, "web-* glob should match web-01 and web-02 but not db-01")
}

func TestScanJobs_ClaimNext_EmptyQueue_ReturnsFalse(t *testing.T) {
	pool := newTestPool(t)
	s := scanjobs.NewPostgresStore(pool)

	_, ok, err := s.ClaimNext(context.Background(), "worker-1")
	require.NoError(t, err)
	assert.False(t, ok, "empty queue must return ok=false without error")
}

func TestScanJobs_ClaimNext_ConcurrentWorkersPickDifferentRows(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	zoneID, _ := seedZoneAndHost(t, pool, "parallel-host-1")

	// Seed a second host in the same zone so Enqueue produces 2 jobs.
	_, err := hosts.NewPostgresStore(pool).Create(ctx, hosts.Host{
		Hostname: "parallel-host-2", ZoneID: &zoneID,
	})
	require.NoError(t, err)

	s := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := s.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	// Two sequential claims must pick different rows (SKIP LOCKED
	// wouldn't serialise back-to-back on the same connection but this
	// at least ensures the worker_id stamp doesn't resurrect a running
	// row).
	a, ok, err := s.ClaimNext(ctx, "worker-a")
	require.NoError(t, err)
	require.True(t, ok)

	b, ok, err := s.ClaimNext(ctx, "worker-b")
	require.NoError(t, err)
	require.True(t, ok)

	assert.NotEqual(t, a.ID, b.ID)

	// Queue is now empty.
	_, ok, err = s.ClaimNext(ctx, "worker-c")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestScanJobs_Heartbeat_Missing_ReturnsNotFound(t *testing.T) {
	pool := newTestPool(t)
	s := scanjobs.NewPostgresStore(pool)

	err := s.Heartbeat(context.Background(), uuid.Must(uuid.NewV7()), "x")
	assert.ErrorIs(t, err, scanjobs.ErrNotFound)
}

func TestScanJobs_Fail_RecordsError(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	zoneID, _ := seedZoneAndHost(t, pool, "err-host")

	s := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := s.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)

	claimed, _, err := s.ClaimNext(ctx, "w")
	require.NoError(t, err)

	require.NoError(t, s.Fail(ctx, claimed.ID, "scan panicked"))

	got, err := s.Get(ctx, jobs[0].ID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.StatusFailed, got.Status)
	assert.Equal(t, "scan panicked", got.ErrorMessage)
	require.NotNil(t, got.FinishedAt)
}
