//go:build integration

package scanjobs_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// openTestStoreWithPool returns both a store and the underlying pool so tests
// can call seedHost without going through the full hosts package.
func openTestStoreWithPool(t *testing.T) (*scanjobs.PostgresStore, *pgxpool.Pool) {
	t.Helper()
	pool := newTestPool(t)
	return scanjobs.NewPostgresStore(pool), pool
}

// enqueueSingleJobBatch creates a single-job batch and returns (batchID, jobID).
// It seeds a minimal host row to satisfy the FK on manage_scan_jobs.host_id.
func enqueueSingleJobBatch(t *testing.T, s *scanjobs.PostgresStore, pool *pgxpool.Pool, jt scanjobs.JobType) (batchID, jobID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tenantID := uuid.New()
	hostID := seedHost(t, pool)

	req := scanjobs.BatchEnqueueReq{
		TenantID: tenantID, JobTypes: []scanjobs.JobType{jt},
		HostIDs: []uuid.UUID{hostID}, Profile: scanjobs.ProfileQuick,
	}
	specs := []scanjobs.JobSpec{{HostID: hostID, JobType: jt}}
	resp, err := s.EnqueueBatch(ctx, req, specs, nil)
	require.NoError(t, err)

	jobs, err := s.List(ctx, tenantID, 1)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	return resp.BatchID, jobs[0].ID
}

func TestBatchStatus_AllCompleted(t *testing.T) {
	s, pool := openTestStoreWithPool(t)
	ctx := context.Background()
	batchID, jobID := enqueueSingleJobBatch(t, s, pool, scanjobs.JobTypePortSurvey)

	// ClaimByID (port_survey jobs are not picked up by ClaimNext which
	// only claims filesystem jobs). Transition queued→running first.
	_, err := s.ClaimByID(ctx, jobID, "worker-1")
	require.NoError(t, err)

	require.NoError(t, s.Complete(ctx, jobID))

	b, err := s.GetBatch(ctx, batchID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.BatchStatusCompleted, b.Status)
	assert.NotNil(t, b.FinishedAt)
}

func TestBatchStatus_AnyFailed(t *testing.T) {
	s, pool := openTestStoreWithPool(t)
	ctx := context.Background()
	batchID, jobID := enqueueSingleJobBatch(t, s, pool, scanjobs.JobTypePortSurvey)

	_, err := s.ClaimByID(ctx, jobID, "worker-1")
	require.NoError(t, err)

	require.NoError(t, s.Fail(ctx, jobID, "timeout"))

	b, err := s.GetBatch(ctx, batchID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.BatchStatusFailed, b.Status)
}

func TestBatchStatus_AllCancelled(t *testing.T) {
	s, pool := openTestStoreWithPool(t)
	ctx := context.Background()
	batchID, jobID := enqueueSingleJobBatch(t, s, pool, scanjobs.JobTypePortSurvey)

	require.NoError(t, s.Cancel(ctx, jobID))

	b, err := s.GetBatch(ctx, batchID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.BatchStatusCancelled, b.Status)
}

func TestBatchStatus_ClaimTransitionsToRunning(t *testing.T) {
	s, pool := openTestStoreWithPool(t)
	ctx := context.Background()

	// Use filesystem job type so ClaimNext picks it up.
	batchID, _ := enqueueSingleJobBatch(t, s, pool, scanjobs.JobTypeFilesystem)

	_, ok, err := s.ClaimNext(ctx, "worker-1")
	require.NoError(t, err)
	require.True(t, ok)

	b, err := s.GetBatch(ctx, batchID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.BatchStatusRunning, b.Status)
}
