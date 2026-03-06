//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface satisfaction assertions.
var _ Store = (*PostgresStore)(nil)
var _ ScanStore = (*PostgresStore)(nil)
var _ HashStore = (*PostgresStore)(nil)

// testStore creates a PostgresStore for testing.
// Requires PostgreSQL running (e.g., podman compose up -d).
func testStore(t *testing.T) *PostgresStore {
	t.Helper()
	dbUrl := os.Getenv("TRITON_TEST_DB_URL")
	if dbUrl == "" {
		dbUrl = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()
	s, err := NewPostgresStore(ctx, dbUrl)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	// Truncate at start to handle stale data from parallel package tests
	require.NoError(t, s.TruncateAll(ctx))
	t.Cleanup(func() {
		_ = s.TruncateAll(ctx)
		s.Close()
	})
	return s
}

func testScanResult(id, hostname, profile string) *model.ScanResult {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &model.ScanResult{
		ID: id,
		Metadata: model.ScanMetadata{
			Timestamp:   now,
			Hostname:    hostname,
			OS:          "linux",
			ScanProfile: profile,
			ToolVersion: "2.0.0-test",
		},
		Findings: []model.Finding{
			{
				ID:       "f1",
				Category: 2,
				Source:   model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "RSA-2048",
					PQCStatus: "TRANSITIONAL",
				},
				Module:    "certificates",
				Timestamp: now,
			},
			{
				ID:       "f2",
				Category: 3,
				Source:   model.FindingSource{Type: "file", Path: "/usr/lib/libssl.so"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "AES-256-GCM",
					PQCStatus: "SAFE",
				},
				Module:    "libraries",
				Timestamp: now,
			},
		},
		Summary: model.Summary{
			TotalFindings:     2,
			TotalCryptoAssets: 2,
			Safe:              1,
			Transitional:      1,
		},
	}
}

// --- Schema / Migration Tests ---

func TestNewPostgresStore_Connection(t *testing.T) {
	s := testStore(t)

	v, err := s.SchemaVersion(context.Background())
	require.NoError(t, err)
	assert.Equal(t, len(migrations), v)
}

func TestNewPostgresStore_BadURL(t *testing.T) {
	ctx := context.Background()
	_, err := NewPostgresStore(ctx, "postgres://baduser:badpass@localhost:59999/nonexistent?sslmode=disable")
	require.Error(t, err)
}

func TestNewPostgresStore_IdempotentMigrations(t *testing.T) {
	dbUrl := os.Getenv("TRITON_TEST_DB_URL")
	if dbUrl == "" {
		dbUrl = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	ctx := context.Background()

	// First open — runs migrations.
	s1, err := NewPostgresStore(ctx, dbUrl)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	s1.Close()

	// Second open — should not fail (migrations already applied).
	s2, err := NewPostgresStore(ctx, dbUrl)
	require.NoError(t, err)
	defer s2.Close()

	v, err := s2.SchemaVersion(context.Background())
	require.NoError(t, err)
	assert.Equal(t, len(migrations), v)
}

// --- Scan CRUD Tests ---

func TestSaveScan_And_GetScan(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	result := testScanResult("scan-001", "host-a", "quick")

	err := s.SaveScan(ctx, result)
	require.NoError(t, err)

	got, err := s.GetScan(ctx, "scan-001", "")
	require.NoError(t, err)
	assert.Equal(t, result.ID, got.ID)
	assert.Equal(t, result.Metadata.Hostname, got.Metadata.Hostname)
	assert.Equal(t, result.Summary.Safe, got.Summary.Safe)
	assert.Equal(t, result.Summary.Transitional, got.Summary.Transitional)
	assert.Len(t, got.Findings, 2)
	assert.Equal(t, "RSA-2048", got.Findings[0].CryptoAsset.Algorithm)
}

func TestGetScan_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetScan(ctx, "nonexistent", "")
	require.Error(t, err)

	var nf *ErrNotFound
	assert.True(t, errors.As(err, &nf))
	assert.Equal(t, "scan", nf.Resource)
}

func TestSaveScan_Upsert(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	result := testScanResult("scan-upsert", "host-a", "quick")
	require.NoError(t, s.SaveScan(ctx, result))

	// Update summary and save again.
	result.Summary.Safe = 10
	result.Summary.Unsafe = 5
	require.NoError(t, s.SaveScan(ctx, result))

	got, err := s.GetScan(ctx, "scan-upsert", "")
	require.NoError(t, err)
	assert.Equal(t, 10, got.Summary.Safe)
	assert.Equal(t, 5, got.Summary.Unsafe)
}

func TestDeleteScan(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	result := testScanResult("scan-del", "host-a", "quick")
	require.NoError(t, s.SaveScan(ctx, result))

	err := s.DeleteScan(ctx, "scan-del", "")
	require.NoError(t, err)

	_, err = s.GetScan(ctx, "scan-del", "")
	var nf *ErrNotFound
	assert.True(t, errors.As(err, &nf))
}

func TestDeleteScan_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.DeleteScan(ctx, "nonexistent", "")
	var nf *ErrNotFound
	assert.True(t, errors.As(err, &nf))
}

// --- ListScans Tests ---

func TestListScans_All(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		r := testScanResult("scan-list-"+string(rune('a'+i)), "host-a", "standard")
		r.Metadata.Timestamp = time.Now().UTC().Add(time.Duration(i) * time.Hour).Truncate(time.Microsecond)
		require.NoError(t, s.SaveScan(ctx, r))
	}

	summaries, err := s.ListScans(ctx, ScanFilter{})
	require.NoError(t, err)
	assert.Len(t, summaries, 3)

	// Should be ordered by timestamp DESC.
	assert.Equal(t, "scan-list-c", summaries[0].ID)
	assert.Equal(t, "scan-list-b", summaries[1].ID)
	assert.Equal(t, "scan-list-a", summaries[2].ID)
}

func TestListScans_FilterHostname(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	require.NoError(t, s.SaveScan(ctx, testScanResult("s1", "host-a", "quick")))
	require.NoError(t, s.SaveScan(ctx, testScanResult("s2", "host-b", "quick")))
	require.NoError(t, s.SaveScan(ctx, testScanResult("s3", "host-a", "standard")))

	summaries, err := s.ListScans(ctx, ScanFilter{Hostname: "host-a"})
	require.NoError(t, err)
	assert.Len(t, summaries, 2)
}

func TestListScans_FilterProfile(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	require.NoError(t, s.SaveScan(ctx, testScanResult("s1", "host-a", "quick")))
	require.NoError(t, s.SaveScan(ctx, testScanResult("s2", "host-a", "standard")))

	summaries, err := s.ListScans(ctx, ScanFilter{Profile: "quick"})
	require.NoError(t, err)
	assert.Len(t, summaries, 1)
	assert.Equal(t, "s1", summaries[0].ID)
}

func TestListScans_FilterTimeRange(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		r := testScanResult("ts-"+string(rune('a'+i)), "host-a", "quick")
		r.Metadata.Timestamp = base.Add(time.Duration(i) * 24 * time.Hour)
		require.NoError(t, s.SaveScan(ctx, r))
	}

	after := base.Add(24 * time.Hour)
	before := base.Add(3 * 24 * time.Hour)
	summaries, err := s.ListScans(ctx, ScanFilter{After: &after, Before: &before})
	require.NoError(t, err)
	assert.Len(t, summaries, 3) // days 1, 2, 3
}

func TestListScans_Limit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		r := testScanResult("lim-"+string(rune('a'+i)), "host-a", "quick")
		r.Metadata.Timestamp = time.Now().UTC().Add(time.Duration(i) * time.Hour).Truncate(time.Microsecond)
		require.NoError(t, s.SaveScan(ctx, r))
	}

	summaries, err := s.ListScans(ctx, ScanFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, summaries, 2)
}

func TestListScans_Empty(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	summaries, err := s.ListScans(ctx, ScanFilter{})
	require.NoError(t, err)
	assert.Empty(t, summaries)
}

// --- File Hash Tests ---

func TestSetFileHash_And_GetFileHash(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.SetFileHash(ctx, "/etc/ssl/cert.pem", "abc123")
	require.NoError(t, err)

	hash, scannedAt, err := s.GetFileHash(ctx, "/etc/ssl/cert.pem")
	require.NoError(t, err)
	assert.Equal(t, "abc123", hash)
	assert.WithinDuration(t, time.Now(), scannedAt, 5*time.Second)
}

func TestGetFileHash_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, _, err := s.GetFileHash(ctx, "/no/such/file")
	var nf *ErrNotFound
	assert.True(t, errors.As(err, &nf))
}

func TestSetFileHash_Upsert(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	require.NoError(t, s.SetFileHash(ctx, "/path", "hash1"))
	require.NoError(t, s.SetFileHash(ctx, "/path", "hash2"))

	hash, _, err := s.GetFileHash(ctx, "/path")
	require.NoError(t, err)
	assert.Equal(t, "hash2", hash)
}

func TestPruneStaleHashes(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Insert three hashes.
	require.NoError(t, s.SetFileHash(ctx, "/a", "h1"))
	require.NoError(t, s.SetFileHash(ctx, "/b", "h2"))
	require.NoError(t, s.SetFileHash(ctx, "/c", "h3"))

	// Prune anything older than 1 hour from now — should prune nothing since
	// they were just inserted.
	cutoff := time.Now().Add(-1 * time.Hour)
	require.NoError(t, s.PruneStaleHashes(ctx, cutoff))

	h, _, err := s.GetFileHash(ctx, "/a")
	require.NoError(t, err)
	assert.Equal(t, "h1", h)

	// Prune with a future cutoff — should prune all.
	cutoff = time.Now().Add(1 * time.Hour)
	require.NoError(t, s.PruneStaleHashes(ctx, cutoff))

	_, _, err = s.GetFileHash(ctx, "/a")
	var nf *ErrNotFound
	assert.True(t, errors.As(err, &nf))
}

// --- ScanSummary Field Accuracy ---

func TestListScans_SummaryFieldsAccurate(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	result := testScanResult("fields-test", "fieldhost", "comprehensive")
	result.Summary = model.Summary{
		TotalFindings: 100,
		Safe:          40,
		Transitional:  30,
		Deprecated:    20,
		Unsafe:        10,
	}
	require.NoError(t, s.SaveScan(ctx, result))

	summaries, err := s.ListScans(ctx, ScanFilter{})
	require.NoError(t, err)
	require.Len(t, summaries, 1)

	ss := summaries[0]
	assert.Equal(t, "fields-test", ss.ID)
	assert.Equal(t, "fieldhost", ss.Hostname)
	assert.Equal(t, "comprehensive", ss.Profile)
	assert.Equal(t, 100, ss.TotalFindings)
	assert.Equal(t, 40, ss.Safe)
	assert.Equal(t, 30, ss.Transitional)
	assert.Equal(t, 20, ss.Deprecated)
	assert.Equal(t, 10, ss.Unsafe)
}

// --- ErrNotFound ---

func TestErrNotFound_Error(t *testing.T) {
	e := &ErrNotFound{Resource: "scan", ID: "xyz"}
	assert.Equal(t, "scan not found: xyz", e.Error())
}

// --- FileHashStats ---

func TestFileHashStats_Empty(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	count, oldest, newest, err := s.FileHashStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.True(t, oldest.IsZero())
	assert.True(t, newest.IsZero())
}

func TestFileHashStats_WithEntries(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	require.NoError(t, s.SetFileHash(ctx, "/a", "h1"))
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, s.SetFileHash(ctx, "/b", "h2"))
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, s.SetFileHash(ctx, "/c", "h3"))

	count, oldest, newest, err := s.FileHashStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
	assert.False(t, oldest.IsZero())
	assert.False(t, newest.IsZero())
	assert.True(t, !newest.Before(oldest))
}

// --- Context Cancellation ---

func TestSaveScan_CancelledContext(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := testScanResult("cancelled", "host", "quick")
	err := s.SaveScan(ctx, result)
	assert.Error(t, err)
}

func TestGetScan_CancelledContext(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	require.NoError(t, s.SaveScan(ctx, testScanResult("ctx-get", "host-a", "quick")))

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.GetScan(cancelCtx, "ctx-get", "")
	assert.Error(t, err)
}

func TestListScans_CancelledContext(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.ListScans(ctx, ScanFilter{})
	assert.Error(t, err)
}

func TestDeleteScan_CancelledContext(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	require.NoError(t, s.SaveScan(ctx, testScanResult("ctx-del", "host-a", "quick")))

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.DeleteScan(cancelCtx, "ctx-del", "")
	assert.Error(t, err)
}

func TestSetFileHash_CancelledContext(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.SetFileHash(ctx, "/path", "hash")
	assert.Error(t, err)
}

func TestGetFileHash_CancelledContext(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	require.NoError(t, s.SetFileHash(ctx, "/path", "hash"))

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := s.GetFileHash(cancelCtx, "/path")
	assert.Error(t, err)
}

func TestPruneStaleHashes_CancelledContext(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.PruneStaleHashes(ctx, time.Now())
	assert.Error(t, err)
}

func TestFileHashStats_CancelledContext(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, _, err := s.FileHashStats(ctx)
	assert.Error(t, err)
}

// --- Combined Filters ---

func TestListScans_CombinedFilters(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1 := testScanResult("cf-1", "host-a", "quick")
	r1.Metadata.Timestamp = base
	r2 := testScanResult("cf-2", "host-a", "standard")
	r2.Metadata.Timestamp = base.Add(24 * time.Hour)
	r3 := testScanResult("cf-3", "host-b", "quick")
	r3.Metadata.Timestamp = base.Add(48 * time.Hour)

	require.NoError(t, s.SaveScan(ctx, r1))
	require.NoError(t, s.SaveScan(ctx, r2))
	require.NoError(t, s.SaveScan(ctx, r3))

	// Filter by hostname + profile
	summaries, err := s.ListScans(ctx, ScanFilter{Hostname: "host-a", Profile: "quick"})
	require.NoError(t, err)
	assert.Len(t, summaries, 1)
	assert.Equal(t, "cf-1", summaries[0].ID)

	// Filter by hostname + time range + limit
	after := base
	before := base.Add(49 * time.Hour)
	summaries, err = s.ListScans(ctx, ScanFilter{
		Hostname: "host-a",
		After:    &after,
		Before:   &before,
		Limit:    1,
	})
	require.NoError(t, err)
	assert.Len(t, summaries, 1)
}
