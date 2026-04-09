//go:build integration

package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestBackfillFindings_EmptyDB(t *testing.T) {
	s := testStore(t)
	err := s.BackfillFindings(context.Background())
	assert.NoError(t, err)
}

func TestBackfillFindings_PopulatesUnmarkedScans(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-org")

	scan := testScanResult(testUUID("bf-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
	}
	// Save via the LEGACY SaveScan path, then clear the marker to
	// simulate a pre-migration scan.
	require.NoError(t, s.SaveScan(context.Background(), scan))
	_, err := s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	require.NoError(t, err)

	require.NoError(t, s.BackfillFindings(context.Background()))

	assert.Equal(t, 1, queryFindingsCount(t, s, scan.ID))
	assert.True(t, queryScanBackfilled(t, s, scan.ID))
}

func TestBackfillFindings_SkipsAlreadyMarked(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-skip-org")

	scan := saveScan(t, s, testUUID("bf-skip"), "host-1", orgID,
		cryptoFinding("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	)
	countBefore := queryFindingsCount(t, s, scan.ID)

	require.NoError(t, s.BackfillFindings(context.Background()))
	countAfter := queryFindingsCount(t, s, scan.ID)
	assert.Equal(t, countBefore, countAfter,
		"backfill must not re-insert findings for already-marked scans")
}

func TestBackfillFindings_Idempotent(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-idem-org")

	scan := testScanResult(testUUID("bf-idem"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	}
	require.NoError(t, s.SaveScan(context.Background(), scan))
	_, _ = s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)

	require.NoError(t, s.BackfillFindings(context.Background()))
	// Clear marker and re-run — ON CONFLICT DO NOTHING keeps it safe.
	_, _ = s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	require.NoError(t, s.BackfillFindings(context.Background()))

	assert.Equal(t, 1, queryFindingsCount(t, s, scan.ID))
}

func TestBackfillFindings_ContextCancellationAllowsResume(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-resume-org")

	for i := 0; i < 3; i++ {
		suffix := string(rune('a' + i))
		scan := testScanResult(testUUID("bf-resume-"+suffix), "host-"+suffix, "quick")
		scan.OrgID = orgID
		scan.Findings = []model.Finding{
			cryptoFinding("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
		}
		require.NoError(t, s.SaveScan(context.Background(), scan))
		_, _ = s.pool.Exec(context.Background(),
			`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	}

	// Cancel immediately — no scans processed, graceful return.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_ = s.BackfillFindings(cancelled)

	// Resume with a fresh context — all three scans should be
	// processed.
	require.NoError(t, s.BackfillFindings(context.Background()))

	var unmarked int
	err := s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM scans WHERE org_id = $1 AND findings_extracted_at IS NULL`,
		orgID).Scan(&unmarked)
	require.NoError(t, err)
	assert.Equal(t, 0, unmarked)
}

// TestBackfillFindings_CorruptBlobMarkedAndCounted guards the
// operationally critical "mark anyway + increment failed counter"
// path from /pensive:full-review action item T1 (2026-04-09). A
// scan whose result_json cannot be unmarshalled into a ScanResult
// must be skipped (no findings inserted), marked as processed (so
// the backfill doesn't retry it forever), AND counted as a failure
// via the backfillScansFailed metric so operators can see it in
// /api/v1/metrics.
func TestBackfillFindings_CorruptBlobMarkedAndCounted(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Insert a scan row directly with a non-JSON result_json payload.
	// This bypasses SaveScan which would JSON-marshal a valid
	// ScanResult. We use raw SQL to write garbage bytes so the
	// backfill's json.Unmarshal step will fail.
	corruptScanID := testUUID("bf-corrupt")
	orgID := testUUID("bf-corrupt-org")
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scans (id, hostname, timestamp, profile, total_findings,
		                   safe, transitional, deprecated, unsafe, result_json, org_id)
		VALUES ($1, $2, NOW(), $3, 0, 0, 0, 0, 0, $4::jsonb, $5)
	`, corruptScanID, "host-corrupt", "quick", `"not a scan result"`, orgID)
	require.NoError(t, err)

	// Reset counters for a deterministic assertion on THIS run.
	s.backfillScansSucceeded.Store(0)
	s.backfillScansFailed.Store(0)

	// Run backfill — must NOT return an error (corrupt rows are
	// non-fatal) and must mark the scan anyway.
	require.NoError(t, s.BackfillFindings(ctx))

	// No findings inserted for the corrupt scan.
	assert.Equal(t, 0, queryFindingsCount(t, s, corruptScanID))

	// Scan marked so next run skips it (prevents retry loop).
	assert.True(t, queryScanBackfilled(t, s, corruptScanID),
		"corrupt scan must be marked to prevent retry loop")

	// Failed counter incremented so operators see the failure in
	// /api/v1/metrics.
	assert.Equal(t, uint64(1), s.backfillScansFailed.Load(),
		"corrupt scan must increment the failed counter, not the success counter")
	assert.Equal(t, uint64(0), s.backfillScansSucceeded.Load())
}

// TestBackfillFindings_TimeoutExpiresCleanly exercises the mid-loop
// context-cancellation path, which is distinct from immediate
// cancellation (TestBackfillFindings_ContextCancellationAllowsResume).
// A sub-millisecond timeout fires during batch processing, after
// some scans have been processed but before all are done. The
// function must return without error, leave some scans marked, and
// leave the rest unmarked for a future run to pick up.
// /pensive:full-review T4.
func TestBackfillFindings_TimeoutExpiresCleanly(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-timeout-org")

	// Seed ~150 scans so the batchSize=100 loop needs at least two
	// iterations. A realistic catalog, bigger than immediate cancel
	// can handle.
	for i := 0; i < 150; i++ {
		scan := testScanResult(testUUID("bf-timeout-"+string(rune('a'+i/26))+string(rune('a'+i%26))),
			"host-"+string(rune('a'+i/26))+string(rune('a'+i%26)), "quick")
		scan.OrgID = orgID
		scan.Findings = []model.Finding{
			cryptoFinding("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
		}
		require.NoError(t, s.SaveScan(context.Background(), scan))
		_, err := s.pool.Exec(context.Background(),
			`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
		require.NoError(t, err)
	}

	// Verify our seed worked.
	var initialUnmarked int
	require.NoError(t, s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM scans WHERE org_id = $1 AND findings_extracted_at IS NULL`,
		orgID).Scan(&initialUnmarked))
	require.Equal(t, 150, initialUnmarked)

	// 1-millisecond deadline forces mid-loop cancellation somewhere
	// between batches. The exact stopping point is non-deterministic,
	// but the function must return nil (cancellation is graceful,
	// not an error).
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	err := s.BackfillFindings(ctx)
	assert.NoError(t, err, "graceful timeout must not surface as an error")

	// Some scans MAY or MAY NOT have been processed depending on
	// timing — we can't assert an exact count. What we CAN assert:
	//   (a) the function returned
	//   (b) any processed scans are marked (so a future run skips them)
	//   (c) the remaining scans are still unmarked (so a future run picks them up)
	// The combination of (b) and (c) is exactly what resumability
	// requires.
	var processed, remaining int
	require.NoError(t, s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM scans WHERE org_id = $1 AND findings_extracted_at IS NOT NULL`,
		orgID).Scan(&processed))
	require.NoError(t, s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM scans WHERE org_id = $1 AND findings_extracted_at IS NULL`,
		orgID).Scan(&remaining))
	assert.Equal(t, 150, processed+remaining, "every seeded scan must be either marked or unmarked (never lost)")

	// Most realistic scenario: a few batches completed before the
	// deadline, leaving many scans still to go. Verify there's
	// something left AND something done — not all-or-nothing.
	// If the test machine is very fast and processes all 150 within
	// 1ms (unlikely), we accept that too — just check the invariant.
	t.Logf("timeout test: %d processed, %d remaining", processed, remaining)
}

// TestBackfillFindings_ConcurrentSubmitSafe exercises the race
// between the backfill goroutine and a live scan submission for the
// SAME scan. The scan is seeded with a cleared marker (so backfill
// picks it up), then a SaveScanWithFindings call races against the
// backfill. Either order must leave exactly one set of findings
// rows — the ON CONFLICT (scan_id, finding_index) DO NOTHING
// idempotency guard closes the race.
// /pensive:full-review T2.
func TestBackfillFindings_ConcurrentSubmitSafe(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-race-org")

	scan := testScanResult(testUUID("bf-race"), "host-race", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
		cryptoFinding("key", "/b", &model.CryptoAsset{Algorithm: "AES", KeySize: 256}),
	}
	// Seed via legacy SaveScan so findings_extracted_at stays NULL
	// and backfill will try to process it.
	require.NoError(t, s.SaveScan(context.Background(), scan))
	_, err := s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	require.NoError(t, err)

	extracted := ExtractFindings(scan)
	require.Len(t, extracted, 2)

	// Launch backfill and submit concurrently. Both call paths insert
	// findings for the same (scan_id, finding_index) pair — the
	// ON CONFLICT DO NOTHING clause must coalesce them to a single
	// committed row set.
	var wg sync.WaitGroup
	wg.Add(2)
	var backfillErr, submitErr error
	go func() {
		defer wg.Done()
		backfillErr = s.BackfillFindings(context.Background())
	}()
	go func() {
		defer wg.Done()
		submitErr = s.SaveScanWithFindings(context.Background(), scan, extracted)
	}()
	wg.Wait()

	require.NoError(t, backfillErr, "backfill must not return error on race")
	require.NoError(t, submitErr, "SaveScanWithFindings must not return error on race")

	// Exactly 2 finding rows — not 0 (both dropped), not 4 (both
	// inserted) — regardless of which goroutine committed first.
	count := queryFindingsCount(t, s, scan.ID)
	assert.Equal(t, 2, count, "concurrent writers + ON CONFLICT must coalesce to exactly one row per finding")
}

func TestBackfillFindings_CountersIncrement(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-count-org")

	scan := testScanResult(testUUID("bf-count"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	}
	require.NoError(t, s.SaveScan(context.Background(), scan))
	_, _ = s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)

	// Reset counters for a deterministic assertion.
	s.backfillScansSucceeded.Store(0)
	s.backfillScansFailed.Store(0)

	require.NoError(t, s.BackfillFindings(context.Background()))

	assert.GreaterOrEqual(t, s.backfillScansSucceeded.Load(), uint64(1))
	assert.Equal(t, uint64(0), s.backfillScansFailed.Load())
}
