//go:build integration

package scanjobs_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

func makeScheduleReq(tenantID uuid.UUID, cronExpr string) scanjobs.ScheduleReq {
	return scanjobs.ScheduleReq{
		TenantID: tenantID,
		Name:     "test-schedule",
		JobTypes: []scanjobs.JobType{scanjobs.JobTypePortSurvey},
		HostIDs:  []uuid.UUID{uuid.New()},
		Profile:  scanjobs.ProfileQuick,
		CronExpr: cronExpr,
	}
}

func TestCreateSchedule_NextRunAtComputed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	before := time.Now().UTC().Truncate(time.Minute)
	sched, err := s.CreateSchedule(ctx, makeScheduleReq(uuid.New(), "0 2 * * 1"))
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, sched.ID)
	assert.True(t, sched.NextRunAt.After(before), "next_run_at must be in the future")
	assert.True(t, sched.Enabled)
}

func TestListSchedules_TenantScoped(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	t1 := uuid.New()
	t2 := uuid.New()

	_, _ = s.CreateSchedule(ctx, makeScheduleReq(t1, "0 * * * *"))
	_, _ = s.CreateSchedule(ctx, makeScheduleReq(t1, "0 2 * * 1"))
	_, _ = s.CreateSchedule(ctx, makeScheduleReq(t2, "0 3 * * *"))

	list, err := s.ListSchedules(ctx, t1)
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestPatchSchedule_DisablesSchedule(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	sched, _ := s.CreateSchedule(ctx, makeScheduleReq(uuid.New(), "0 * * * *"))

	disabled := false
	patched, err := s.PatchSchedule(ctx, sched.ID, scanjobs.SchedulePatchReq{Enabled: &disabled})
	require.NoError(t, err)
	assert.False(t, patched.Enabled)
}

func TestPatchSchedule_UpdatesCronRecomputesNextRunAt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	sched, _ := s.CreateSchedule(ctx, makeScheduleReq(uuid.New(), "0 * * * *"))

	newCron := "0 3 * * 1"
	patched, err := s.PatchSchedule(ctx, sched.ID, scanjobs.SchedulePatchReq{CronExpr: &newCron})
	require.NoError(t, err)
	assert.Equal(t, "0 3 * * 1", patched.CronExpr)
	assert.True(t, patched.NextRunAt.After(time.Now()))
}

func TestDeleteSchedule_RemovesRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	sched, _ := s.CreateSchedule(ctx, makeScheduleReq(uuid.New(), "0 * * * *"))

	require.NoError(t, s.DeleteSchedule(ctx, sched.ID))
	list, _ := s.ListSchedules(ctx, sched.TenantID)
	assert.Empty(t, list)
}

func TestClaimDueSchedules_ClaimsAndAdvancesNextRunAt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenantID := uuid.New()

	// Insert a schedule whose next_run_at is in the past.
	// Use direct SQL since CreateSchedule computes next_run_at in the future.
	pastTime := time.Now().UTC().Add(-5 * time.Minute)
	var schedID uuid.UUID
	err := s.QueryRowForTest(ctx, `
		INSERT INTO manage_scan_schedules
		  (tenant_id, name, job_types, host_ids, profile, cron_expr, next_run_at)
		VALUES ($1, 'due', ARRAY['port_survey']::text[], ARRAY[]::uuid[], 'quick', '0 * * * *', $2)
		RETURNING id`,
		tenantID, pastTime,
	).Scan(&schedID)
	require.NoError(t, err)

	due, err := s.ClaimDueSchedules(ctx)
	require.NoError(t, err)
	require.Len(t, due, 1)
	assert.Equal(t, schedID, due[0].ID)
	assert.True(t, due[0].NextRunAt.After(time.Now()), "next_run_at must be advanced to future")
}

func TestClaimDueSchedules_DisabledNotClaimed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	pastTime := time.Now().UTC().Add(-5 * time.Minute)

	err := s.QueryRowForTest(ctx, `
		INSERT INTO manage_scan_schedules
		  (tenant_id, name, job_types, host_ids, profile, cron_expr, next_run_at, enabled)
		VALUES ($1, 'disabled', ARRAY['port_survey']::text[], ARRAY[]::uuid[], 'quick', '0 * * * *', $2, false)
		RETURNING id`,
		uuid.New(), pastTime,
	).Scan(new(uuid.UUID))
	require.NoError(t, err)

	due, err := s.ClaimDueSchedules(ctx)
	require.NoError(t, err)
	assert.Empty(t, due, "disabled schedule must not be claimed")
}

func TestClaimDueSchedules_NoConcurrentDoubleFire(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	pastTime := time.Now().UTC().Add(-5 * time.Minute)
	_ = s.QueryRowForTest(ctx, `
		INSERT INTO manage_scan_schedules
		  (tenant_id, name, job_types, host_ids, profile, cron_expr, next_run_at)
		VALUES ($1, 'once', ARRAY['port_survey']::text[], ARRAY[]::uuid[], 'quick', '0 * * * *', $2)
		RETURNING id`,
		uuid.New(), pastTime,
	).Scan(new(uuid.UUID))

	// Two concurrent claims — only one should win.
	ch := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() {
			due, _ := s.ClaimDueSchedules(ctx)
			ch <- len(due)
		}()
	}
	total := <-ch + <-ch
	assert.Equal(t, 1, total, "schedule must fire exactly once even under concurrent ticks")
}
