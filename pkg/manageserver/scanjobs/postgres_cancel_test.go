//go:build integration

package scanjobs_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// TestScanJobs_Cancel_RunningJob walks the full cancellation lifecycle
// the orchestrator uses:
//
//  1. Admin requests cancel (RequestCancel flips the flag).
//  2. Heartbeat watcher sees IsCancelRequested=true.
//  3. Worker writes the terminal state (Cancel).
//  4. Post-terminal Complete is a silent no-op — the status='running'
//     guard on Complete prevents resurrecting the row.
func TestScanJobs_Cancel_RunningJob(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	tagID, _ := seedTagAndHost(t, pool, "cancel-host")
	s := scanjobs.NewPostgresStore(pool)

	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := s.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, TagIDs: []uuid.UUID{tagID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	claimed, ok, err := s.ClaimNext(ctx, "worker-1")
	require.NoError(t, err)
	require.True(t, ok)

	// Admin requests cancellation.
	require.NoError(t, s.RequestCancel(ctx, claimed.ID))

	// Orchestrator heartbeat watcher sees the flag.
	requested, err := s.IsCancelRequested(ctx, claimed.ID)
	require.NoError(t, err)
	assert.True(t, requested)

	// Worker writes the terminal state.
	require.NoError(t, s.Cancel(ctx, claimed.ID))

	got, err := s.Get(ctx, claimed.ID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.StatusCancelled, got.Status)
	require.NotNil(t, got.FinishedAt, "cancellation must stamp finished_at")

	// Post-terminal Complete must be a silent no-op — the row stays
	// cancelled, not completed.
	require.NoError(t, s.Complete(ctx, claimed.ID))
	got2, err := s.Get(ctx, claimed.ID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.StatusCancelled, got2.Status, "Complete after Cancel must be a no-op")
}

// TestScanJobs_Cancel_QueuedJob covers the race where an admin cancels
// a job before any worker claims it. Cancel must take it straight from
// queued to cancelled without passing through running.
func TestScanJobs_Cancel_QueuedJob(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	tagID, _ := seedTagAndHost(t, pool, "queued-cancel-host")
	s := scanjobs.NewPostgresStore(pool)

	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := s.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, TagIDs: []uuid.UUID{tagID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	require.NoError(t, s.Cancel(ctx, jobs[0].ID))

	got, err := s.Get(ctx, jobs[0].ID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.StatusCancelled, got.Status)

	// The queue must now be empty — a later ClaimNext must not
	// resurrect a cancelled row.
	_, ok, err := s.ClaimNext(ctx, "later-worker")
	require.NoError(t, err)
	assert.False(t, ok, "cancelled jobs must not be reclaimable")
}

// TestScanJobs_RequestCancel_MissingReturnsNotFound pins the error
// surface of the flag write so handlers can map it to HTTP 404.
func TestScanJobs_RequestCancel_MissingReturnsNotFound(t *testing.T) {
	pool := newTestPool(t)
	s := scanjobs.NewPostgresStore(pool)

	err := s.RequestCancel(context.Background(), uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, scanjobs.ErrNotFound)
}

// TestScanJobs_Heartbeat_NoOpOnTerminalRow pins the status='running'
// guard on Heartbeat. If a heartbeat tick fires between a Cancel write
// and the orchestrator noticing the cancel, the UPDATE must not
// silently overwrite running_heartbeat_at on the cancelled row. The
// guard turns the write into a no-op and Heartbeat returns ErrNotFound
// so the orchestrator's cancel watcher exits promptly.
func TestScanJobs_Heartbeat_NoOpOnTerminalRow(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	tagID, _ := seedTagAndHost(t, pool, "hb-terminal-host")
	s := scanjobs.NewPostgresStore(pool)

	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := s.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, TagIDs: []uuid.UUID{tagID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	claimed, ok, err := s.ClaimNext(ctx, "worker-1")
	require.NoError(t, err)
	require.True(t, ok)

	// Snapshot the heartbeat timestamp set by ClaimNext.
	before, err := s.Get(ctx, claimed.ID)
	require.NoError(t, err)
	require.NotNil(t, before.RunningHeartbeatAt)
	snapshot := *before.RunningHeartbeatAt

	// Admin requests + worker writes terminal state.
	require.NoError(t, s.RequestCancel(ctx, claimed.ID))
	require.NoError(t, s.Cancel(ctx, claimed.ID))

	// Heartbeat on the cancelled row must return ErrNotFound (the
	// status guard makes it match zero rows).
	hbErr := s.Heartbeat(ctx, claimed.ID, "hb-after-cancel")
	assert.ErrorIs(t, hbErr, scanjobs.ErrNotFound,
		"Heartbeat on a terminal row must return ErrNotFound")

	// The cancelled row's running_heartbeat_at must NOT have moved.
	after, err := s.Get(ctx, claimed.ID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.StatusCancelled, after.Status)
	require.NotNil(t, after.RunningHeartbeatAt)
	assert.True(t, after.RunningHeartbeatAt.Equal(snapshot),
		"Heartbeat must not touch running_heartbeat_at on a cancelled row (was %v, now %v)",
		snapshot, *after.RunningHeartbeatAt)
	// Progress text must also be untouched.
	assert.NotEqual(t, "hb-after-cancel", after.ProgressText,
		"Heartbeat must not touch progress_text on a cancelled row")
}
