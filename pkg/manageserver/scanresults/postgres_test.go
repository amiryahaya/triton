//go:build integration

package scanresults_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
	"github.com/amiryahaya/triton/pkg/managestore"
	"github.com/amiryahaya/triton/pkg/model"
)

var testSchemaSeq atomic.Int64

// newTestPool mirrors the isolation pattern used by scanjobs tests:
// each test gets a fresh schema with the full manage_* migration set.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_scanresults_%d", testSchemaSeq.Add(1))

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

// seedJob creates a zone+host+tenant+job tuple and returns the
// scan-job UUID the caller can use to enqueue scan results against.
// Shared helper across E1/E2/E3 tests.
func seedJob(t *testing.T, pool *pgxpool.Pool, hostname string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	var zoneID uuid.UUID
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO manage_zones (name) VALUES ($1) RETURNING id`,
		"z-"+hostname,
	).Scan(&zoneID))
	_, err := hosts.NewPostgresStore(pool).Create(ctx, hosts.Host{
		Hostname: hostname, ZoneID: &zoneID,
	})
	require.NoError(t, err)

	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := scanjobs.NewPostgresStore(pool).Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	return jobs[0].ID, tenantID
}

func sampleScan() *model.ScanResult {
	return &model.ScanResult{
		ID: uuid.Must(uuid.NewV7()).String(),
		Metadata: model.ScanMetadata{
			Hostname:    "test-host",
			OS:          "linux",
			ScanProfile: "quick",
			Timestamp:   time.Now().UTC(),
		},
	}
}

func TestResultsQueue_EnqueueAndDrain(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	jobID, _ := seedJob(t, pool, "rh-01")

	store := scanresults.NewPostgresStore(pool)
	sourceID := uuid.Must(uuid.NewV7())

	require.NoError(t, store.Enqueue(ctx, jobID, "manage", sourceID, sampleScan()))

	depth, err := store.QueueDepth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), depth)

	rows, err := store.ClaimDue(ctx, 10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, jobID, rows[0].ScanJobID)
	assert.Equal(t, "manage", rows[0].SourceType)
	assert.Equal(t, sourceID, rows[0].SourceID)

	// Envelope shape — must match the Report Server's POST /api/v1/scans
	// contract: { scan, submitted_by: { type, id } }. Queue-row metadata
	// (scan_job_id, enqueued_at, source_*) lives on the DB columns, not
	// the payload, so the Report Server's audit query
	// (result_json->'submitted_by'->>'type') sees a clean shape.
	var env map[string]any
	require.NoError(t, json.Unmarshal(rows[0].PayloadJSON, &env))
	assert.Contains(t, env, "scan", "envelope must carry the scan result")
	require.Contains(t, env, "submitted_by", "envelope must carry submitted_by")
	sb, ok := env["submitted_by"].(map[string]any)
	require.True(t, ok, "submitted_by must be a nested object")
	assert.Equal(t, "manage", sb["type"])
	assert.Equal(t, sourceID.String(), sb["id"])

	// Inverse: top-level queue-row metadata MUST NOT leak into payload_json.
	assert.NotContains(t, env, "scan_job_id",
		"scan_job_id is a queue-row column, not envelope field")
	assert.NotContains(t, env, "source_type",
		"source_type is a queue-row column, not envelope field")
	assert.NotContains(t, env, "source_id",
		"source_id is a queue-row column, not envelope field")
	assert.NotContains(t, env, "submitted_at",
		"submitted_at is captured by manage_scan_results_queue.enqueued_at")

	require.NoError(t, store.Delete(ctx, rows[0].ID))

	depth, err = store.QueueDepth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), depth)
}

func TestResultsQueue_Delete_Missing_ReturnsNotFound(t *testing.T) {
	pool := newTestPool(t)
	store := scanresults.NewPostgresStore(pool)

	err := store.Delete(context.Background(), uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, scanresults.ErrNotFound)
}

func TestResultsQueue_Defer_IncrementsAttemptAndNextAt(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	jobID, _ := seedJob(t, pool, "defer-01")

	store := scanresults.NewPostgresStore(pool)
	require.NoError(t, store.Enqueue(ctx, jobID, "manage", uuid.Nil, sampleScan()))

	rows, err := store.ClaimDue(ctx, 10)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	future := time.Now().Add(10 * time.Second)
	require.NoError(t, store.Defer(ctx, rows[0].ID, future, "upstream 500"))

	// After Defer the row is no longer due; ClaimDue returns 0.
	due, err := store.ClaimDue(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, due, 0, "deferred row must not be claimable until next_attempt_at")

	// Re-read the row via a wider query to verify attempt_count=1.
	var attempt int
	var lastErr string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT attempt_count, last_error FROM manage_scan_results_queue WHERE id = $1`,
		rows[0].ID,
	).Scan(&attempt, &lastErr))
	assert.Equal(t, 1, attempt)
	assert.Equal(t, "upstream 500", lastErr)
}

func TestResultsQueue_DeadLetter_MovesRow(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	jobID, _ := seedJob(t, pool, "dl-01")

	store := scanresults.NewPostgresStore(pool)
	require.NoError(t, store.Enqueue(ctx, jobID, "manage", uuid.Nil, sampleScan()))

	rows, err := store.ClaimDue(ctx, 10)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	require.NoError(t, store.DeadLetter(ctx, rows[0].ID, "HTTP 400"))

	// Queue empty.
	depth, err := store.QueueDepth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), depth)

	// Dead-letter has the row with the expected reason.
	var dlCount int
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(MAX(dead_letter_reason), '') FROM manage_scan_results_dead_letter`,
	).Scan(&dlCount, &reason))
	assert.Equal(t, 1, dlCount)
	assert.Equal(t, "HTTP 400", reason)
}

func TestResultsQueue_DeadLetter_Missing_ReturnsNotFound(t *testing.T) {
	pool := newTestPool(t)
	store := scanresults.NewPostgresStore(pool)

	err := store.DeadLetter(context.Background(), uuid.Must(uuid.NewV7()), "nope")
	assert.ErrorIs(t, err, scanresults.ErrNotFound)
}

func TestResultsQueue_OldestAge_EmptyQueue_ReturnsZero(t *testing.T) {
	pool := newTestPool(t)
	store := scanresults.NewPostgresStore(pool)

	age, err := store.OldestAge(context.Background())
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), age)
}

func TestResultsQueue_PushCreds_RoundTrip(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	store := scanresults.NewPostgresStore(pool)

	// Missing row → ErrNotFound.
	_, err := store.LoadPushCreds(ctx)
	assert.ErrorIs(t, err, scanresults.ErrNotFound)

	creds := scanresults.PushCreds{
		ClientCertPEM: "-----BEGIN CERTIFICATE-----\ntestcert\n-----END CERTIFICATE-----",
		ClientKeyPEM:  "-----BEGIN PRIVATE KEY-----\ntestkey\n-----END PRIVATE KEY-----",
		CACertPEM:     "-----BEGIN CERTIFICATE-----\ntestca\n-----END CERTIFICATE-----",
		ReportURL:     "https://report.example.com:9443",
		TenantID:      "tenant-1",
	}
	require.NoError(t, store.SavePushCreds(ctx, creds))

	got, err := store.LoadPushCreds(ctx)
	require.NoError(t, err)
	assert.Equal(t, creds, got)

	// Upsert overwrites.
	creds.ReportURL = "https://new.example.com"
	require.NoError(t, store.SavePushCreds(ctx, creds))
	got, err = store.LoadPushCreds(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://new.example.com", got.ReportURL)
}

func TestResultsQueue_LicenseState_SuccessAndFailure(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	store := scanresults.NewPostgresStore(pool)

	// Fresh install: singleton row is seeded by the migration with
	// consecutive_failures=0, last_pushed_at IS NULL.
	st, err := store.LoadLicenseState(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), st.QueueDepth)
	assert.Nil(t, st.LastPushedAt)
	assert.Equal(t, 0, st.ConsecutiveFailures)

	// Success zeroes counters + stamps last_pushed_at.
	require.NoError(t, store.RecordPushSuccess(ctx, []byte(`{"scans":3}`)))
	st, err = store.LoadLicenseState(ctx)
	require.NoError(t, err)
	require.NotNil(t, st.LastPushedAt)
	assert.Equal(t, 0, st.ConsecutiveFailures)
	assert.Equal(t, "", st.LastPushError)

	// 3 failures in a row bump consecutive_failures.
	for i := 0; i < 3; i++ {
		require.NoError(t, store.RecordPushFailure(ctx, fmt.Sprintf("boom %d", i)))
	}
	st, err = store.LoadLicenseState(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, st.ConsecutiveFailures)
	assert.Equal(t, "boom 2", st.LastPushError)

	// A subsequent success resets counters.
	require.NoError(t, store.RecordPushSuccess(ctx, nil))
	st, err = store.LoadLicenseState(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, st.ConsecutiveFailures)
	assert.Equal(t, "", st.LastPushError)
}
