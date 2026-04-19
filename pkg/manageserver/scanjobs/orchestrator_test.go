//go:build integration

package scanjobs_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/model"
)

// fakeResultEnqueuer records Enqueue calls to an in-memory slice.
// Batch E's scanresults.PostgresStore will implement this interface
// for real; until then this lets D5 exercise the whole pipeline.
type fakeResultEnqueuer struct {
	mu    sync.Mutex
	calls []scanjobs.Job // keyed-by jobID isn't needed; size/ordering is what the test asserts
}

func (f *fakeResultEnqueuer) Enqueue(_ context.Context, scanJobID uuid.UUID, _ string, _ uuid.UUID, _ *model.ScanResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, scanjobs.Job{ID: scanJobID})
	return nil
}

func (f *fakeResultEnqueuer) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// seedZoneAndHosts creates one zone and n hosts inside it. Used by the
// orchestrator tests to populate an Enqueue target set.
func seedZoneAndHosts(t *testing.T, pool *pgxpool.Pool, n int) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var zoneID uuid.UUID
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO manage_zones (name) VALUES ('orchestrator-zone') RETURNING id`,
	).Scan(&zoneID))
	hs := hosts.NewPostgresStore(pool)
	for i := 0; i < n; i++ {
		_, err := hs.Create(ctx, hosts.Host{
			Hostname: "orch-host-" + time.Now().Format("150405") + "-" + strint(i),
			ZoneID:   &zoneID,
		})
		require.NoError(t, err)
	}
	return zoneID
}

func strint(i int) string {
	if i == 0 {
		return "0"
	}
	const digits = "0123456789"
	s := ""
	for i > 0 {
		s = string(digits[i%10]) + s
		i /= 10
	}
	return s
}

// TestOrchestrator_EnqueueToCompletion verifies the happy path:
// jobs flow queued → running → completed, the ResultEnqueuer sees
// one call per job, and the orchestrator waits for all workers on
// ctx.Done.
func TestOrchestrator_EnqueueToCompletion(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	zoneID := seedZoneAndHosts(t, pool, 5)
	store := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := store.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 5)

	fakeResults := &fakeResultEnqueuer{}
	scanFunc := func(ctx context.Context, _ scanjobs.Job) (*model.ScanResult, error) {
		// Short but non-zero so heartbeat ticks can fire at least once
		// for some jobs without making the whole test slow.
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &model.ScanResult{Metadata: model.ScanMetadata{Hostname: "test-host"}}, nil
	}

	o := scanjobs.NewOrchestrator(scanjobs.OrchestratorConfig{
		Store:             store,
		ResultStore:       fakeResults,
		Parallelism:       2,
		ScanFunc:          scanFunc,
		HeartbeatInterval: 200 * time.Millisecond,
		PollInterval:      50 * time.Millisecond,
		SourceID:          uuid.Must(uuid.NewV7()),
	})

	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		o.Run(runCtx)
		close(done)
	}()

	// Wait until all 5 jobs are terminal (completed) or the run deadline
	// fires. Poll every 100ms.
	assert.Eventually(t, func() bool {
		list, err := store.List(ctx, tenantID, 20)
		if err != nil {
			return false
		}
		completed := 0
		for _, j := range list {
			if j.Status == scanjobs.StatusCompleted {
				completed++
			}
		}
		return completed == 5
	}, 4*time.Second, 100*time.Millisecond, "all 5 jobs must complete")

	// Shut down the orchestrator and wait for clean exit.
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after context cancelled")
	}

	assert.Equal(t, 5, fakeResults.Count(), "ResultEnqueuer must see one call per completed job")
}

// TestOrchestrator_Cancellation verifies that an admin-requested
// cancel propagates through the heartbeat watcher and terminates the
// in-flight scan.
func TestOrchestrator_Cancellation(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	zoneID := seedZoneAndHosts(t, pool, 1)
	store := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := store.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	// ScanFunc blocks until its own context is cancelled, then returns
	// ctx.Err() like a well-behaved cancellable scanner would.
	scanFunc := func(ctx context.Context, _ scanjobs.Job) (*model.ScanResult, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	fakeResults := &fakeResultEnqueuer{}
	o := scanjobs.NewOrchestrator(scanjobs.OrchestratorConfig{
		Store:             store,
		ResultStore:       fakeResults,
		Parallelism:       1,
		ScanFunc:          scanFunc,
		HeartbeatInterval: 200 * time.Millisecond, // fast enough for a 3s test budget
		PollInterval:      50 * time.Millisecond,
		SourceID:          uuid.Must(uuid.NewV7()),
	})

	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		o.Run(runCtx)
		close(done)
	}()

	// Give the worker a moment to claim the job.
	assert.Eventually(t, func() bool {
		j, err := store.Get(ctx, jobs[0].ID)
		return err == nil && j.Status == scanjobs.StatusRunning
	}, 2*time.Second, 50*time.Millisecond, "worker must claim and start the job")

	// Admin flips the cancel flag.
	require.NoError(t, store.RequestCancel(ctx, jobs[0].ID))

	// Wait for terminal state.
	assert.Eventually(t, func() bool {
		j, err := store.Get(ctx, jobs[0].ID)
		return err == nil && j.Status == scanjobs.StatusCancelled
	}, 3*time.Second, 100*time.Millisecond, "job must end up cancelled")

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after context cancelled")
	}

	// Cancelled jobs must NOT show up in the result queue — Cancel
	// writes terminal state and runOneJob returns before the enqueue
	// branch.
	assert.Equal(t, 0, fakeResults.Count(), "cancelled jobs must not reach ResultEnqueuer")
}

// TestOrchestrator_FailOnScanError pins the failure path: a non-ctx
// scan error must mark the job failed with the error string preserved.
func TestOrchestrator_FailOnScanError(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	zoneID := seedZoneAndHosts(t, pool, 1)
	store := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := store.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)

	scanFunc := func(_ context.Context, _ scanjobs.Job) (*model.ScanResult, error) {
		return nil, errors.New("simulated scanner panic")
	}

	fakeResults := &fakeResultEnqueuer{}
	o := scanjobs.NewOrchestrator(scanjobs.OrchestratorConfig{
		Store:             store,
		ResultStore:       fakeResults,
		Parallelism:       1,
		ScanFunc:          scanFunc,
		HeartbeatInterval: 200 * time.Millisecond,
		PollInterval:      50 * time.Millisecond,
		SourceID:          uuid.Must(uuid.NewV7()),
	})

	runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() { o.Run(runCtx); close(done) }()

	assert.Eventually(t, func() bool {
		j, err := store.Get(ctx, jobs[0].ID)
		return err == nil && j.Status == scanjobs.StatusFailed
	}, 2*time.Second, 50*time.Millisecond, "failing scan must mark job failed")

	got, err := store.Get(ctx, jobs[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "simulated scanner panic", got.ErrorMessage)

	cancel()
	<-done

	assert.Equal(t, 0, fakeResults.Count(), "failed jobs must not reach ResultEnqueuer")
}

// TestOrchestrator_PanicRecovery_FailsJobAndContinues verifies that a
// ScanFunc panic does NOT kill the worker goroutine. The first job must
// end up failed with "internal panic" preserved, and the second job
// must still progress to completed — evidence that the worker survived
// and is still draining the queue.
func TestOrchestrator_PanicRecovery_FailsJobAndContinues(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	zoneID := seedZoneAndHosts(t, pool, 2)
	store := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := store.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	// First call panics, every subsequent call succeeds. We key on the
	// call count rather than the job ID because ordering between the
	// parallel Enqueue'd rows is decided by Postgres, not us.
	var calls atomic.Int32
	scanFunc := func(_ context.Context, _ scanjobs.Job) (*model.ScanResult, error) {
		if calls.Add(1) == 1 {
			panic("simulated nil deref inside a module")
		}
		return &model.ScanResult{Metadata: model.ScanMetadata{Hostname: "post-panic"}}, nil
	}

	fakeResults := &fakeResultEnqueuer{}
	o := scanjobs.NewOrchestrator(scanjobs.OrchestratorConfig{
		Store:             store,
		ResultStore:       fakeResults,
		Parallelism:       1, // force serial execution so the ordering is deterministic
		ScanFunc:          scanFunc,
		HeartbeatInterval: 200 * time.Millisecond,
		PollInterval:      50 * time.Millisecond,
		SourceID:          uuid.Must(uuid.NewV7()),
	})

	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() { o.Run(runCtx); close(done) }()

	// Wait until both jobs are terminal: one failed (the panicker), one
	// completed (proving the worker survived the panic).
	assert.Eventually(t, func() bool {
		list, err := store.List(ctx, tenantID, 20)
		if err != nil || len(list) != 2 {
			return false
		}
		var failed, completed int
		for _, j := range list {
			switch j.Status {
			case scanjobs.StatusFailed:
				failed++
			case scanjobs.StatusCompleted:
				completed++
			}
		}
		return failed == 1 && completed == 1
	}, 4*time.Second, 100*time.Millisecond, "panicking job must fail, surviving job must complete")

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after context cancelled")
	}

	// Assert the failed job carries the panic marker in error_message.
	list, err := store.List(ctx, tenantID, 20)
	require.NoError(t, err)
	var failedMsg string
	for _, j := range list {
		if j.Status == scanjobs.StatusFailed {
			failedMsg = j.ErrorMessage
		}
	}
	assert.True(t, strings.Contains(failedMsg, "internal panic"),
		"failed error_message must contain 'internal panic', got %q", failedMsg)
	assert.Equal(t, 1, fakeResults.Count(),
		"only the surviving job must reach ResultEnqueuer")
}

// TestNewOrchestrator_NilResultStore_FailsJobsSafely pins the
// misconfiguration path: if the operator forgot to wire a ResultStore,
// NewOrchestrator must not panic at construction and must not silently
// drop scan results on the floor. Instead the downstream Enqueue call
// errors loudly and surfaces via Store.Fail so the operator sees the
// failure in the admin UI.
func TestNewOrchestrator_NilResultStore_FailsJobsSafely(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	zoneID := seedZoneAndHosts(t, pool, 1)
	store := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.Must(uuid.NewV7())
	jobs, err := store.Enqueue(ctx, scanjobs.EnqueueReq{
		TenantID: tenantID, ZoneIDs: []uuid.UUID{zoneID}, Profile: scanjobs.ProfileQuick,
	})
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	scanFunc := func(_ context.Context, _ scanjobs.Job) (*model.ScanResult, error) {
		return &model.ScanResult{Metadata: model.ScanMetadata{Hostname: "orphan-result"}}, nil
	}

	// Explicitly build the config WITHOUT ResultStore — this is the bug
	// NewOrchestrator must defend against.
	cfg := scanjobs.OrchestratorConfig{
		Store: store,
		// ResultStore is deliberately nil.
		Parallelism:       1,
		ScanFunc:          scanFunc,
		HeartbeatInterval: 200 * time.Millisecond,
		PollInterval:      50 * time.Millisecond,
		SourceID:          uuid.Must(uuid.NewV7()),
	}

	require.NotPanics(t, func() {
		_ = scanjobs.NewOrchestrator(cfg)
	}, "NewOrchestrator must not panic on nil ResultStore")

	o := scanjobs.NewOrchestrator(cfg)

	runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() { o.Run(runCtx); close(done) }()

	assert.Eventually(t, func() bool {
		j, err := store.Get(ctx, jobs[0].ID)
		return err == nil && j.Status == scanjobs.StatusFailed
	}, 2*time.Second, 50*time.Millisecond, "missing ResultStore must cause job failure")

	cancel()
	<-done

	got, err := store.Get(ctx, jobs[0].ID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.StatusFailed, got.Status)
	assert.True(t, strings.Contains(got.ErrorMessage, "ResultStore not configured"),
		"error_message must name the missing collaborator, got %q", got.ErrorMessage)
}
