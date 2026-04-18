//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPruneScansBefore_RemovesOldRows verifies that PruneScansBefore deletes
// rows whose timestamp is before the cutoff and leaves newer rows intact.
func TestPruneScansBefore_RemovesOldRows(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Insert an old scan (>365 days ago) and a recent scan (10 days ago)
	// using raw SQL to set an explicit past timestamp.
	// SaveScan uses time.Now() so we can't control the timestamp via it.
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scans (id, hostname, timestamp, profile, total_findings, safe, transitional, deprecated, unsafe, result_json)
		VALUES (gen_random_uuid(), 'old-host', NOW() - INTERVAL '400 days', 'quick', 0, 0, 0, 0, 0, '{}')
	`)
	require.NoError(t, err)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO scans (id, hostname, timestamp, profile, total_findings, safe, transitional, deprecated, unsafe, result_json)
		VALUES (gen_random_uuid(), 'new-host', NOW() - INTERVAL '10 days', 'quick', 0, 0, 0, 0, 0, '{}')
	`)
	require.NoError(t, err)

	// Prune scans older than 365 days.
	cutoff := time.Now().UTC().Add(-365 * 24 * time.Hour)
	n, err := s.PruneScansBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "exactly one old scan should be deleted")

	// The recent scan should still be present.
	var count int
	err = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM scans`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "only the recent scan should remain")
}

// TestPruneScansBefore_NothingToDelete verifies no error when no rows qualify.
func TestPruneScansBefore_NothingToDelete(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Empty table — prune should succeed with zero rows affected.
	cutoff := time.Now().UTC().Add(-365 * 24 * time.Hour)
	n, err := s.PruneScansBefore(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}
