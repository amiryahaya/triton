//go:build integration

package scanjobs_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

func TestScheduleRunner_FiresDueSchedule(t *testing.T) {
	s := openTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tenantID := uuid.New()
	hostID := uuid.New()
	pastTime := time.Now().UTC().Add(-time.Minute)

	// Insert a due schedule using raw SQL (CreateSchedule always computes
	// next_run_at in the future so we bypass it here).
	var schedID uuid.UUID
	err := s.QueryRowForTest(ctx, `
		INSERT INTO manage_scan_schedules
		  (tenant_id, name, job_types, host_ids, profile, cron_expr, next_run_at)
		VALUES ($1, 'runner-test', ARRAY['port_survey']::text[], $2::uuid[], 'quick', '0 * * * *', $3)
		RETURNING id`,
		tenantID, []uuid.UUID{hostID}, pastTime,
	).Scan(&schedID)
	require.NoError(t, err)

	// Insert the host so EnqueueBatch FK constraint on manage_hosts succeeds.
	// ip is required (NOT NULL + UNIQUE); use the first 3 bytes of hostID as
	// a deterministic address to avoid conflicts across test runs.
	hostIP := fmt.Sprintf("10.%d.%d.%d", hostID[0], hostID[1], hostID[2])
	insertErr := s.QueryRowForTest(ctx, `
		INSERT INTO manage_hosts (id, hostname, ip, ssh_port)
		VALUES ($1, 'runner-host', $2, 22)
		RETURNING id`,
		hostID, hostIP,
	).Scan(new(uuid.UUID))
	require.NoError(t, insertErr, "seed host")

	runner := scanjobs.NewScheduleRunner(scanjobs.ScheduleRunnerConfig{
		ScheduleStore: s,
		BatchStore:    s,
		TickInterval:  50 * time.Millisecond,
	})
	go runner.Run(ctx)

	require.Eventually(t, func() bool {
		batches, _ := s.ListBatches(ctx, tenantID, 10)
		return len(batches) >= 1
	}, 3*time.Second, 100*time.Millisecond, "schedule runner must spawn a batch within 3s")

	batches, _ := s.ListBatches(ctx, tenantID, 10)
	require.Len(t, batches, 1)
	assert.Equal(t, schedID, *batches[0].ScheduleID)
}

func TestScheduleRunner_DisabledNotFired(t *testing.T) {
	s := openTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	tenantID := uuid.New()
	pastTime := time.Now().UTC().Add(-time.Minute)
	err := s.QueryRowForTest(ctx, `
		INSERT INTO manage_scan_schedules
		  (tenant_id, name, job_types, host_ids, profile, cron_expr, next_run_at, enabled)
		VALUES ($1, 'disabled', ARRAY['port_survey']::text[], ARRAY[]::uuid[], 'quick', '0 * * * *', $2, false)
		RETURNING id`,
		tenantID, pastTime,
	).Scan(new(uuid.UUID))
	require.NoError(t, err)

	runner := scanjobs.NewScheduleRunner(scanjobs.ScheduleRunnerConfig{
		ScheduleStore: s, BatchStore: s,
		TickInterval: 50 * time.Millisecond,
	})
	go runner.Run(ctx)
	<-ctx.Done()

	batches, _ := s.ListBatches(context.Background(), tenantID, 10)
	assert.Empty(t, batches, "disabled schedule must not spawn a batch")
}
