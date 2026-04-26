//go:build integration

package scanjobs_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// TestScanJobs_ReapStale_RevertsToQueued exercises the reaper that
// recovers jobs abandoned by a crashed worker. We synthesise a stale
// running row directly via SQL (rather than going through ClaimNext +
// sleep) so the test is deterministic and fast.
func TestScanJobs_ReapStale_RevertsToQueued(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	tagID, _ := seedTagAndHost(t, pool, "stale-host")
	s := scanjobs.NewPostgresStore(pool)

	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := s.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, TagIDs: []uuid.UUID{tagID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	// Simulate a crashed worker: flip to running with a heartbeat
	// timestamp 10 minutes in the past. Bypass ClaimNext so we can
	// control the timestamp precisely.
	_, err = pool.Exec(ctx,
		`UPDATE manage_scan_jobs
		    SET status='running',
		        worker_id='ghost-worker',
		        started_at=NOW() - INTERVAL '10 minutes',
		        running_heartbeat_at=NOW() - INTERVAL '10 minutes'
		  WHERE id=$1`,
		jobs[0].ID,
	)
	require.NoError(t, err)

	// ReapStale with a 5-minute threshold must revert exactly 1 row.
	n, err := s.ReapStale(ctx, 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	got, err := s.Get(ctx, jobs[0].ID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.StatusQueued, got.Status)
	assert.Equal(t, "", got.WorkerID, "reaped row must have worker_id cleared")
	assert.Nil(t, got.StartedAt, "reaped row must have started_at cleared")
	assert.Nil(t, got.RunningHeartbeatAt, "reaped row must have heartbeat cleared")

	// A live row (fresh heartbeat) must NOT be reaped. Re-claim the
	// newly-queued job, which stamps a NOW() heartbeat, then call
	// ReapStale again — should be a no-op.
	_, ok, err := s.ClaimNext(ctx, "fresh-worker")
	require.NoError(t, err)
	require.True(t, ok)

	n, err = s.ReapStale(ctx, 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "fresh heartbeat must not be reaped")
}

// TestScanJobs_ReapStale_IgnoresCompletedRows ensures the reaper never
// resurrects terminal rows — only status='running' is eligible.
func TestScanJobs_ReapStale_IgnoresCompletedRows(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	tagID, _ := seedTagAndHost(t, pool, "done-host")
	s := scanjobs.NewPostgresStore(pool)

	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := s.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, TagIDs: []uuid.UUID{tagID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)

	claimed, _, err := s.ClaimNext(ctx, "w")
	require.NoError(t, err)
	require.NoError(t, s.Complete(ctx, claimed.ID))

	// Backdate the heartbeat even though the row is already completed.
	_, err = pool.Exec(ctx,
		`UPDATE manage_scan_jobs
		    SET running_heartbeat_at = NOW() - INTERVAL '10 minutes'
		  WHERE id = $1`,
		jobs[0].ID,
	)
	require.NoError(t, err)

	n, err := s.ReapStale(ctx, 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "terminal rows must never be reaped")

	got, err := s.Get(ctx, jobs[0].ID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.StatusCompleted, got.Status)
}
