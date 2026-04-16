//go:build integration

package jobqueue

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("TRITON_TEST_DB_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("connect to test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedDiscoveryJob creates the minimum fixture rows required to INSERT
// into discovery_jobs: an org, a user, and an engine. Returns the IDs.
func seedDiscoveryJob(t *testing.T, pool *pgxpool.Pool, status string) (orgID, engineID, jobID uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	orgID = uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	engineID = uuid.Must(uuid.NewV7())
	jobID = uuid.Must(uuid.NewV7())

	// Seed org.
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations (id, name) VALUES ($1, $2)`,
		orgID, "jq-test-org-"+orgID.String()[:8],
	)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	// Seed user.
	_, err = pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, name, password, role)
		 VALUES ($1, $2, $3, 'Test User', 'hash', 'org_admin')`,
		userID, orgID, fmt.Sprintf("jq-%s@test.local", userID.String()[:8]),
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})

	// Seed engine.
	_, err = pool.Exec(ctx,
		`INSERT INTO engines (id, org_id, label, cert_fingerprint, status)
		 VALUES ($1, $2, $3, $4, 'online')`,
		engineID, orgID, "jq-engine-"+engineID.String()[:8], "fp-"+engineID.String(),
	)
	if err != nil {
		t.Fatalf("seed engine: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM engines WHERE id = $1`, engineID)
	})

	// Seed discovery_jobs row.
	_, err = pool.Exec(ctx,
		`INSERT INTO discovery_jobs
		 (id, org_id, engine_id, requested_by, cidrs, ports, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		jobID, orgID, engineID, userID,
		[]string{"10.0.0.0/24"}, []int32{22}, status,
	)
	if err != nil {
		t.Fatalf("seed discovery_jobs: %v", err)
	}
	// Cleanup is LIFO so children are deleted before parents.
	// Cleanups already registered above (org, user, engine) will run
	// after this one due to LIFO ordering — but discovery_jobs has
	// CASCADE from engine_id so it will be deleted when the engine row
	// goes. Register an explicit cleanup anyway for clarity.
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM discovery_jobs WHERE id = $1`, jobID)
	})

	return orgID, engineID, jobID
}

func discoveryQueue(pool *pgxpool.Pool) *Queue {
	return New(pool, Config{
		Table:             "discovery_jobs",
		EngineIDColumn:    "engine_id",
		StatusColumn:      "status",
		ClaimedAtColumn:   "claimed_at",
		RequestedAtColumn: "requested_at",
		CompletedAtColumn: "completed_at",
		QueuedStatus:      "queued",
		ClaimedStatus:     "claimed",
		TerminalStatuses:  []string{"completed", "failed", "cancelled"},
	})
}

func TestQueue_ClaimNextID_SingleUse(t *testing.T) {
	pool := testPool(t)
	_, engineID, jobID := seedDiscoveryJob(t, pool, "queued")
	q := discoveryQueue(pool)

	const workers = 5
	var won atomic.Int32
	var wonID uuid.UUID
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			id, found, err := q.ClaimNextID(context.Background(), engineID)
			if err != nil {
				t.Errorf("ClaimNextID: %v", err)
				return
			}
			if found {
				won.Add(1)
				mu.Lock()
				wonID = id
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if got := won.Load(); got != 1 {
		t.Fatalf("expected exactly 1 winner, got %d", got)
	}
	if wonID != jobID {
		t.Errorf("won ID = %s, want %s", wonID, jobID)
	}

	// Verify the row is now claimed.
	var status string
	err := pool.QueryRow(context.Background(),
		`SELECT status FROM discovery_jobs WHERE id = $1`, jobID,
	).Scan(&status)
	if err != nil {
		t.Fatalf("check status: %v", err)
	}
	if status != "claimed" {
		t.Errorf("status = %q, want 'claimed'", status)
	}
}

func TestQueue_Finish_OwnershipGuard(t *testing.T) {
	pool := testPool(t)
	_, engineA, jobID := seedDiscoveryJob(t, pool, "queued")
	q := discoveryQueue(pool)

	// Claim with engine A.
	_, found, err := q.ClaimNextID(context.Background(), engineA)
	if err != nil || !found {
		t.Fatalf("claim: found=%v err=%v", found, err)
	}

	// Finish with engine B (different UUID).
	engineB := uuid.Must(uuid.NewV7())
	err = q.Finish(context.Background(), engineB, jobID, "completed", "")
	if err != ErrNotOwned {
		t.Errorf("Finish with wrong engine: got %v, want ErrNotOwned", err)
	}
}

func TestQueue_Finish_TerminalGuard(t *testing.T) {
	pool := testPool(t)
	_, engineID, jobID := seedDiscoveryJob(t, pool, "queued")
	q := discoveryQueue(pool)

	// Claim.
	_, found, err := q.ClaimNextID(context.Background(), engineID)
	if err != nil || !found {
		t.Fatalf("claim: found=%v err=%v", found, err)
	}

	// Finish once — should succeed.
	if err := q.Finish(context.Background(), engineID, jobID, "completed", ""); err != nil {
		t.Fatalf("first Finish: %v", err)
	}

	// Finish again — should fail with ErrAlreadyTerminal.
	err = q.Finish(context.Background(), engineID, jobID, "failed", "oops")
	if err != ErrAlreadyTerminal {
		t.Errorf("second Finish: got %v, want ErrAlreadyTerminal", err)
	}
}

func TestQueue_ReclaimStale(t *testing.T) {
	pool := testPool(t)
	_, engineID, jobID := seedDiscoveryJob(t, pool, "queued")
	q := discoveryQueue(pool)

	// Claim.
	_, found, err := q.ClaimNextID(context.Background(), engineID)
	if err != nil || !found {
		t.Fatalf("claim: found=%v err=%v", found, err)
	}

	// Backdate claimed_at to simulate a stale claim.
	_, err = pool.Exec(context.Background(),
		`UPDATE discovery_jobs SET claimed_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, jobID,
	)
	if err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// Reclaim with a cutoff 30 minutes ago.
	cutoff := time.Now().Add(-30 * time.Minute)
	if err := q.ReclaimStale(context.Background(), cutoff); err != nil {
		t.Fatalf("ReclaimStale: %v", err)
	}

	// Verify the row is back to queued.
	var status string
	err = pool.QueryRow(context.Background(),
		`SELECT status FROM discovery_jobs WHERE id = $1`, jobID,
	).Scan(&status)
	if err != nil {
		t.Fatalf("check status: %v", err)
	}
	if status != "queued" {
		t.Errorf("status = %q, want 'queued'", status)
	}
}

func TestQueue_Cancel_QueuedOK(t *testing.T) {
	pool := testPool(t)
	orgID, _, jobID := seedDiscoveryJob(t, pool, "queued")
	q := discoveryQueue(pool)

	if err := q.Cancel(context.Background(), orgID, jobID); err != nil {
		t.Fatalf("Cancel queued job: %v", err)
	}

	var status string
	err := pool.QueryRow(context.Background(),
		`SELECT status FROM discovery_jobs WHERE id = $1`, jobID,
	).Scan(&status)
	if err != nil {
		t.Fatalf("check status: %v", err)
	}
	if status != "cancelled" {
		t.Errorf("status = %q, want 'cancelled'", status)
	}
}

func TestQueue_Cancel_ClaimedNotCancellable(t *testing.T) {
	pool := testPool(t)
	orgID, engineID, jobID := seedDiscoveryJob(t, pool, "queued")
	q := discoveryQueue(pool)

	// Claim first.
	_, found, err := q.ClaimNextID(context.Background(), engineID)
	if err != nil || !found {
		t.Fatalf("claim: found=%v err=%v", found, err)
	}

	// Cancel should fail.
	err = q.Cancel(context.Background(), orgID, jobID)
	if err != ErrNotCancellable {
		t.Errorf("Cancel claimed job: got %v, want ErrNotCancellable", err)
	}
}

func TestQueue_Cancel_NotFound(t *testing.T) {
	pool := testPool(t)
	q := discoveryQueue(pool)

	err := q.Cancel(context.Background(), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()))
	if err != ErrNotFound {
		t.Errorf("Cancel non-existent: got %v, want ErrNotFound", err)
	}
}

func TestQueue_Finish_NotFound(t *testing.T) {
	pool := testPool(t)
	q := discoveryQueue(pool)

	err := q.Finish(context.Background(), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), "completed", "")
	if err != ErrNotFound {
		t.Errorf("Finish non-existent: got %v, want ErrNotFound", err)
	}
}
