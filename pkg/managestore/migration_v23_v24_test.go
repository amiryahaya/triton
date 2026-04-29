//go:build integration

package managestore_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigration_v23_ManageScanSchedules(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	require.True(t, tableExists(t, s, "manage_scan_schedules"),
		"manage_scan_schedules must exist after v23")
	for _, col := range []string{
		"id", "tenant_id", "name", "job_types", "host_ids",
		"profile", "cron_expr", "enabled", "next_run_at", "created_at",
		"max_cpu_pct", "max_memory_mb", "max_duration_s", "last_run_at",
	} {
		assert.True(t, columnExists(t, s, "manage_scan_schedules", col),
			"manage_scan_schedules must have column %q", col)
	}

	// next_run_at must be indexed (partial: enabled=true)
	var indexExists bool
	err := s.QueryRowForTest(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE schemaname = current_schema()
			AND tablename = 'manage_scan_schedules'
			AND indexname LIKE '%manage_scan_schedules_next%'
		)`).Scan(&indexExists)
	require.NoError(t, err)
	assert.True(t, indexExists, "idx_manage_scan_schedules_next must exist")
}

func TestMigration_v24_ManageScanBatches(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	require.True(t, tableExists(t, s, "manage_scan_batches"),
		"manage_scan_batches must exist after v24")
	for _, col := range []string{
		"id", "tenant_id", "job_types", "host_ids", "profile",
		"status", "enqueued_at", "finished_at", "schedule_id",
		"max_cpu_pct", "max_memory_mb", "max_duration_s",
	} {
		assert.True(t, columnExists(t, s, "manage_scan_batches", col),
			"manage_scan_batches must have column %q", col)
	}

	// batch status must default to 'queued'
	tenantID := "00000000-0000-0000-0000-000000000001"
	var status string
	err := s.QueryRowForTest(ctx, `
		INSERT INTO manage_scan_batches (tenant_id, job_types, host_ids, profile)
		VALUES ($1, ARRAY['port_survey'], ARRAY[]::uuid[], 'standard')
		RETURNING status`, tenantID).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "queued", status)

	// manage_scan_jobs must have batch_id + resource limit columns
	for _, col := range []string{"batch_id", "max_cpu_pct", "max_memory_mb", "max_duration_s"} {
		assert.True(t, columnExists(t, s, "manage_scan_jobs", col),
			"manage_scan_jobs must have column %q after v24", col)
	}
}
