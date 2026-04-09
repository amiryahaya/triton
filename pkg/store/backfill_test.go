//go:build integration

package store

import (
	"context"
	"testing"

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
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
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
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
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
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
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
			cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
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

func TestBackfillFindings_CountersIncrement(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-count-org")

	scan := testScanResult(testUUID("bf-count"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	}
	require.NoError(t, s.SaveScan(context.Background(), scan))
	_, _ = s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)

	// Reset counters for a deterministic assertion.
	s.backfillScansTotal.Store(0)
	s.backfillScansFailed.Store(0)

	require.NoError(t, s.BackfillFindings(context.Background()))

	assert.GreaterOrEqual(t, s.backfillScansTotal.Load(), uint64(1))
	assert.Equal(t, uint64(0), s.backfillScansFailed.Load())
}
