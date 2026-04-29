//go:build !integration

package scanjobs_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// ---------------------------------------------------------------------------
// Stub implementations for ScheduleStore and BatchStore used by unit tests.
// ---------------------------------------------------------------------------

type stubScheduleStore struct {
	mu       sync.Mutex
	toReturn []scanjobs.Schedule
}

func (s *stubScheduleStore) ClaimDueSchedules(_ context.Context) ([]scanjobs.Schedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.toReturn
	s.toReturn = nil // only fire once
	return out, nil
}

func (s *stubScheduleStore) CreateSchedule(_ context.Context, _ scanjobs.ScheduleReq) (scanjobs.Schedule, error) {
	return scanjobs.Schedule{}, nil
}
func (s *stubScheduleStore) ListSchedules(_ context.Context, _ uuid.UUID) ([]scanjobs.Schedule, error) {
	return nil, nil
}
func (s *stubScheduleStore) PatchSchedule(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ scanjobs.SchedulePatchReq) (scanjobs.Schedule, error) {
	return scanjobs.Schedule{}, nil
}
func (s *stubScheduleStore) DeleteSchedule(_ context.Context, _ uuid.UUID, _ uuid.UUID) error {
	return nil
}

type capturedBatchReq struct {
	req     scanjobs.BatchEnqueueReq
	specs   []scanjobs.JobSpec
	skipped []scanjobs.SkippedJob
}

type stubBatchStoreRunner struct {
	mu       sync.Mutex
	captured []capturedBatchReq
}

func (s *stubBatchStoreRunner) EnqueueBatch(_ context.Context, req scanjobs.BatchEnqueueReq, specs []scanjobs.JobSpec, skipped []scanjobs.SkippedJob) (scanjobs.BatchEnqueueResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.captured = append(s.captured, capturedBatchReq{req, specs, skipped})
	return scanjobs.BatchEnqueueResp{BatchID: uuid.New(), JobsCreated: len(specs)}, nil
}
func (s *stubBatchStoreRunner) GetBatch(_ context.Context, _ uuid.UUID) (scanjobs.Batch, error) {
	return scanjobs.Batch{}, nil
}
func (s *stubBatchStoreRunner) ListBatches(_ context.Context, _ uuid.UUID, _ int) ([]scanjobs.Batch, error) {
	return nil, nil
}
func (s *stubBatchStoreRunner) CountPendingJobs(_ context.Context) (int64, error) { return 0, nil }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestScheduleRunner_NilHostsStore_PropagatesIDs verifies that when HostsStore
// is nil, the runner forwards host IDs from the schedule and still creates a batch.
func TestScheduleRunner_NilHostsStore_PropagatesIDs(t *testing.T) {
	schedID := uuid.New()
	tenantID := uuid.New()
	hostID := uuid.New()

	sched := scanjobs.Schedule{
		ID:       schedID,
		TenantID: tenantID,
		HostIDs:  []uuid.UUID{hostID},
		JobTypes: []scanjobs.JobType{scanjobs.JobTypePortSurvey},
		Profile:  scanjobs.ProfileQuick,
	}

	schedStore := &stubScheduleStore{toReturn: []scanjobs.Schedule{sched}}
	batchStore := &stubBatchStoreRunner{}

	runner := scanjobs.NewScheduleRunner(scanjobs.ScheduleRunnerConfig{
		ScheduleStore: schedStore,
		BatchStore:    batchStore,
		TickInterval:  20 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go runner.Run(ctx)
	<-ctx.Done()

	batchStore.mu.Lock()
	captured := batchStore.captured
	batchStore.mu.Unlock()

	require.Len(t, captured, 1)
	assert.Equal(t, &schedID, captured[0].req.ScheduleID)
	assert.Equal(t, tenantID, captured[0].req.TenantID)
}

// TestScheduleRunner_ResourceLimitsPropagated verifies max_cpu_pct,
// max_memory_mb, max_duration_s are forwarded from the schedule to the batch.
func TestScheduleRunner_ResourceLimitsPropagated(t *testing.T) {
	cpu, mem, dur := 50, 1024, 3600
	sched := scanjobs.Schedule{
		ID:           uuid.New(),
		TenantID:     uuid.New(),
		HostIDs:      []uuid.UUID{uuid.New()},
		JobTypes:     []scanjobs.JobType{scanjobs.JobTypePortSurvey},
		Profile:      scanjobs.ProfileQuick,
		MaxCPUPct:    &cpu,
		MaxMemoryMB:  &mem,
		MaxDurationS: &dur,
	}

	schedStore := &stubScheduleStore{toReturn: []scanjobs.Schedule{sched}}
	batchStore := &stubBatchStoreRunner{}

	runner := scanjobs.NewScheduleRunner(scanjobs.ScheduleRunnerConfig{
		ScheduleStore: schedStore,
		BatchStore:    batchStore,
		TickInterval:  20 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go runner.Run(ctx)
	<-ctx.Done()

	batchStore.mu.Lock()
	captured := batchStore.captured
	batchStore.mu.Unlock()

	require.Len(t, captured, 1)
	req := captured[0].req
	require.NotNil(t, req.MaxCPUPct)
	assert.Equal(t, cpu, *req.MaxCPUPct)
	require.NotNil(t, req.MaxMemoryMB)
	assert.Equal(t, mem, *req.MaxMemoryMB)
	require.NotNil(t, req.MaxDurationS)
	assert.Equal(t, dur, *req.MaxDurationS)
}
