//go:build integration

package scanjobs_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// openTestStore returns a store backed by a fresh isolated schema.
// It reuses newTestPool (defined in postgres_test.go) which creates a unique
// schema per test invocation and drops it on cleanup.
func openTestStore(t *testing.T) *scanjobs.PostgresStore {
	t.Helper()
	pool := newTestPool(t)
	return scanjobs.NewPostgresStore(pool)
}

// seedHost inserts a minimal manage_hosts row and returns its ID. Used by
// batch tests that need a valid FK reference without going through the full
// hosts package.
func seedHost(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	ip := fmt.Sprintf("10.%d.%d.%d", id[0], id[1], id[2])
	_, err := pool.Exec(context.Background(),
		`INSERT INTO manage_hosts (id, hostname, ip, ssh_port)
		 VALUES ($1, $2, $3, 22)`,
		id, "host-"+id.String()[:8], ip,
	)
	require.NoError(t, err)
	return id
}

func TestEnqueueBatch_BothJobTypes(t *testing.T) {
	pool := newTestPool(t)
	s := scanjobs.NewPostgresStore(pool)
	ctx := context.Background()
	tenantID := uuid.New()
	hostID := seedHost(t, pool)

	req := scanjobs.BatchEnqueueReq{
		TenantID: tenantID,
		JobTypes: []scanjobs.JobType{scanjobs.JobTypePortSurvey, scanjobs.JobTypeFilesystem},
		HostIDs:  []uuid.UUID{hostID},
		Profile:  scanjobs.ProfileStandard,
	}
	specs := []scanjobs.JobSpec{
		{HostID: hostID, JobType: scanjobs.JobTypePortSurvey},
		{HostID: hostID, JobType: scanjobs.JobTypeFilesystem},
	}

	resp, err := s.EnqueueBatch(ctx, req, specs, nil)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, resp.BatchID)
	assert.Equal(t, 2, resp.JobsCreated)
	assert.Empty(t, resp.JobsSkipped)

	// Batch row persisted with status=queued
	batch, err := s.GetBatch(ctx, resp.BatchID)
	require.NoError(t, err)
	assert.Equal(t, scanjobs.BatchStatusQueued, batch.Status)
	assert.Equal(t, 2, batch.JobsCreated)
}

func TestEnqueueBatch_ResourceLimitsOnJobs(t *testing.T) {
	pool := newTestPool(t)
	s := scanjobs.NewPostgresStore(pool)
	ctx := context.Background()
	tenantID := uuid.New()
	hostID := seedHost(t, pool)
	cpu, mem, dur := 50, 2048, 3600

	req := scanjobs.BatchEnqueueReq{
		TenantID:     tenantID,
		JobTypes:     []scanjobs.JobType{scanjobs.JobTypePortSurvey},
		HostIDs:      []uuid.UUID{hostID},
		Profile:      scanjobs.ProfileQuick,
		MaxCPUPct:    &cpu,
		MaxMemoryMB:  &mem,
		MaxDurationS: &dur,
	}
	specs := []scanjobs.JobSpec{{HostID: hostID, JobType: scanjobs.JobTypePortSurvey}}

	resp, err := s.EnqueueBatch(ctx, req, specs, nil)
	require.NoError(t, err)

	jobs, err := s.List(ctx, tenantID, 10)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	require.NotNil(t, jobs[0].MaxCPUPct)
	assert.Equal(t, 50, *jobs[0].MaxCPUPct)
	assert.Equal(t, 2048, *jobs[0].MaxMemoryMB)
	assert.Equal(t, 3600, *jobs[0].MaxDurationS)
	assert.Equal(t, &resp.BatchID, jobs[0].BatchID)
}

func TestListBatches(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenantID := uuid.New()
	otherTenant := uuid.New()

	enqueue := func(tid uuid.UUID) {
		req := scanjobs.BatchEnqueueReq{TenantID: tid, JobTypes: []scanjobs.JobType{scanjobs.JobTypePortSurvey}, HostIDs: []uuid.UUID{uuid.New()}, Profile: scanjobs.ProfileQuick}
		_, _ = s.EnqueueBatch(ctx, req, nil, nil)
	}
	enqueue(tenantID)
	enqueue(tenantID)
	enqueue(otherTenant)

	batches, err := s.ListBatches(ctx, tenantID, 10)
	require.NoError(t, err)
	assert.Len(t, batches, 2, "must return only batches for the requesting tenant")
}
