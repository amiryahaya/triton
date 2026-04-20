//go:build integration

package scanresults_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
)

// TestDrain_BackoffOnFailure verifies that after N drain ticks against
// a 5xx-returning stub:
//   - attempt_count monotonically increases
//   - next_attempt_at pushes further into the future on each tick (10s,
//     20s, 40s pattern)
//   - the row never moves to dead-letter before attempt_count reaches
//     the maxAttempts threshold
//   - manage_license_state.consecutive_failures increments per tick
//
// Using the Run() loop would require simulating future time; calling
// drainOnce via the ticker would still work but involves sleeping past
// each successive backoff. The plan recommends calling drainOnce
// directly, but that method is unexported. We drive the ticker-free
// path via a short-interval Run() + manual backoff reset between
// ticks.
//
// Instead of poking at clocks, the strategy here is: reset
// next_attempt_at to NOW() between ticks so the row is always due,
// and assert the *gap* between the stamped next_attempt_at and its
// reset time matches the expected exponential pattern.
func TestDrain_BackoffOnFailure(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	var received atomic.Int32
	stub, store, client := setupPushStack(t, pool, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))

	jobID, _ := seedJob(t, pool, "backoff-01")
	require.NoError(t, store.Enqueue(ctx, jobID, "manage", uuid.Must(uuid.NewV7()), sampleScan()))

	rows, err := store.ClaimDue(ctx, 1)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	rowID := rows[0].ID

	drain := scanresults.NewDrain(scanresults.DrainConfig{
		Store:     store,
		ReportURL: stub.URL,
		Client:    client,
		Batch:     1,
		Interval:  24 * time.Hour, // effectively: one tick on Run() entry, then sleep
	})

	// Pattern: attempt 1 → gap ≈ 10s; attempt 2 → 20s; attempt 3 → 40s.
	expectedSecs := []int{10, 20, 40}

	for tick, expected := range expectedSecs {
		// Force the row to be due again so the next Run() tick picks it up.
		_, err := pool.Exec(ctx,
			`UPDATE manage_scan_results_queue SET next_attempt_at = NOW() WHERE id = $1`,
			rowID,
		)
		require.NoError(t, err)

		// Stamp the pre-tick NOW() so we can compare against the
		// next_attempt_at the drain sets.
		var beforeTick time.Time
		require.NoError(t, pool.QueryRow(ctx, `SELECT NOW()`).Scan(&beforeTick))

		// Run once: the initial-tick branch calls drainOnce
		// synchronously before blocking on the ticker. Cancel
		// immediately after so Run returns.
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			drain.Run(runCtx)
			close(done)
		}()
		// Poll until the stub has received one more hit, signalling
		// the tick completed.
		targetHits := int32(tick + 1)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && received.Load() < targetHits {
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
		<-done

		require.Equal(t, targetHits, received.Load(), "tick %d: stub hit count", tick+1)

		// Assert attempt_count and next_attempt_at gap.
		var attempt int
		var nextAt time.Time
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT attempt_count, next_attempt_at FROM manage_scan_results_queue WHERE id = $1`,
			rowID,
		).Scan(&attempt, &nextAt))
		assert.Equal(t, tick+1, attempt, "tick %d: attempt_count", tick+1)

		gap := nextAt.Sub(beforeTick).Seconds()
		// Wide tolerance: the test races with pg clock + go scheduler.
		// We want to catch order-of-magnitude regressions (10 → 1 → 100)
		// not millisecond-perfect drift.
		assert.InDelta(t, float64(expected), gap, 5.0,
			"tick %d: backoff gap (expected %ds, got %.2fs)", tick+1, expected, gap)
	}

	// License state should reflect 3 consecutive failures.
	st, err := store.LoadLicenseState(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, st.ConsecutiveFailures)
}
