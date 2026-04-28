//go:build integration

package scanresults_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
)

// TestDrain_DeadLetterAfter400 covers the non-retryable 4xx branch:
// a single tick lands the row straight in manage_scan_results_dead_letter
// with the exact reason string, and the queue is empty afterwards.
//
// 401/403/429 are deliberately *not* part of this branch (they're
// retryable — see handleRow); we assert 400 specifically here.
func TestDrain_DeadLetterAfter400(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	// Body snippet is part of the dead-letter reason contract: operators
	// need the Report Server's error message directly in the DB.
	const upstreamErr = `{"error":"schema mismatch: missing field submitted_by"}`
	var received atomic.Int32
	stub, store, client := setupPushStack(t, pool, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(upstreamErr))
	}))

	jobID, _ := seedJob(t, pool, "dl-net-01")
	require.NoError(t, store.Enqueue(ctx, jobID, "manage", uuid.Must(uuid.NewV7()), sampleScan()))

	drain := scanresults.NewDrain(scanresults.DrainConfig{
		Store:     store,
		ReportURL: stub.URL,
		Client:    client,
		Batch:     1,
		Interval:  24 * time.Hour,
	})

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		drain.Run(runCtx)
		close(done)
	}()

	// Wait until the row has left the queue, not just until the stub
	// receives the HTTP request. Cancelling on receipt introduces a
	// race: the drain still needs to write the dead-letter DB row after
	// pushOne returns, and a cancelled context makes that write fail
	// silently. Polling QueueDepth avoids the race (same approach as
	// TestDrain_DeadLetterAfterMaxRetries).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		d, _ := store.QueueDepth(ctx)
		if d == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	assert.Equal(t, int32(1), received.Load())

	// Queue empty.
	depth, err := store.QueueDepth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), depth)

	// Dead-letter has 1 row with the expected reason.
	var dlCount int
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(MAX(dead_letter_reason), '') FROM manage_scan_results_dead_letter`,
	).Scan(&dlCount, &reason))
	assert.Equal(t, 1, dlCount, "4xx must move the row to dead-letter")
	assert.True(t, strings.Contains(reason, "HTTP 400"),
		"dead-letter reason must record the HTTP status (got %q)", reason)
	assert.True(t, strings.Contains(reason, "schema mismatch"),
		"dead-letter reason must include the Report Server's error body (got %q)", reason)

	// License state updated.
	st, err := store.LoadLicenseState(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, st.ConsecutiveFailures)
	assert.Contains(t, st.LastPushError, "400")
	assert.Contains(t, st.LastPushError, "schema mismatch")
}

// TestDrain_DeadLetterAfterMaxRetries covers the retryable-exhausted
// branch: we pre-load attempt_count=9 (one below the threshold), fire
// a tick against a 500-returning stub, and assert the row is
// dead-lettered instead of deferred for the 10th time.
func TestDrain_DeadLetterAfterMaxRetries(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	stub, store, client := setupPushStack(t, pool, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	jobID, _ := seedJob(t, pool, "dl-retry-01")
	require.NoError(t, store.Enqueue(ctx, jobID, "manage", uuid.Must(uuid.NewV7()), sampleScan()))

	// Fast-forward attempt_count to the cusp of the cutoff. Scope the
	// UPDATE to the specific row we just enqueued — an unconditional
	// UPDATE would clobber any stray rows the test pool happens to share
	// and hide bugs that manifest as mis-targeted writes.
	rows, err := store.ClaimDue(ctx, 10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	rowID := rows[0].ID
	_, err = pool.Exec(ctx,
		`UPDATE manage_scan_results_queue SET attempt_count = 9, next_attempt_at = NOW() WHERE id = $1`,
		rowID,
	)
	require.NoError(t, err)

	drain := scanresults.NewDrain(scanresults.DrainConfig{
		Store:     store,
		ReportURL: stub.URL,
		Client:    client,
		Batch:     1,
		Interval:  24 * time.Hour,
	})

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		drain.Run(runCtx)
		close(done)
	}()

	// Wait until row has left the queue.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		d, _ := store.QueueDepth(ctx)
		if d == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	// Queue empty.
	depth, err := store.QueueDepth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), depth)

	// Dead-letter has 1 row with "max retries exceeded" reason.
	var dlCount int
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(MAX(dead_letter_reason), '') FROM manage_scan_results_dead_letter`,
	).Scan(&dlCount, &reason))
	assert.Equal(t, 1, dlCount)
	assert.Contains(t, reason, "max retries")
}
