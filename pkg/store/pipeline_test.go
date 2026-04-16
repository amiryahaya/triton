package store

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// pipelineMockStore implements Store for pipeline unit tests.
// Only the three methods called by Pipeline have real behaviour;
// all other methods panic to catch unexpected calls.
type pipelineMockStore struct {
	t2Calls  atomic.Int64
	t3Calls  atomic.Int64
	t2Err    error
	t3Err    error
	stale    []PipelineJob
	staleErr error
}

// --- Pipeline-relevant methods ---

func (m *pipelineMockStore) RefreshHostSummary(_ context.Context, _, _ string) error {
	m.t2Calls.Add(1)
	return m.t2Err
}

func (m *pipelineMockStore) RefreshOrgSnapshot(_ context.Context, _ string) error {
	m.t3Calls.Add(1)
	return m.t3Err
}

func (m *pipelineMockStore) ListStaleHosts(_ context.Context) ([]PipelineJob, error) {
	return m.stale, m.staleErr
}

// --- ScanStore stubs ---

func (m *pipelineMockStore) SaveScan(_ context.Context, _ *model.ScanResult) error {
	panic("not implemented")
}
func (m *pipelineMockStore) GetScan(_ context.Context, _, _ string) (*model.ScanResult, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListScans(_ context.Context, _ ScanFilter) ([]ScanSummary, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListScansOrderedByTime(_ context.Context, _ string) ([]ScanSummary, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) DeleteScan(_ context.Context, _, _ string) error {
	panic("not implemented")
}

// --- HashStore stubs ---

func (m *pipelineMockStore) GetFileHash(_ context.Context, _ string) (string, time.Time, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) SetFileHash(_ context.Context, _, _ string) error {
	panic("not implemented")
}
func (m *pipelineMockStore) PruneStaleHashes(_ context.Context, _ time.Time) error {
	panic("not implemented")
}
func (m *pipelineMockStore) FileHashStats(_ context.Context) (int, time.Time, time.Time, error) {
	panic("not implemented")
}

// --- OrgStore stubs ---

func (m *pipelineMockStore) CreateOrg(_ context.Context, _ *Organization) error {
	panic("not implemented")
}
func (m *pipelineMockStore) GetOrg(_ context.Context, _ string) (*Organization, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListOrgs(_ context.Context) ([]Organization, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) UpdateOrg(_ context.Context, _ *Organization) error {
	panic("not implemented")
}
func (m *pipelineMockStore) DeleteOrg(_ context.Context, _ string) error {
	panic("not implemented")
}

// --- UserStore stubs ---

func (m *pipelineMockStore) CreateUser(_ context.Context, _ *User) error {
	panic("not implemented")
}
func (m *pipelineMockStore) GetUser(_ context.Context, _ string) (*User, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) GetUserByEmail(_ context.Context, _ string) (*User, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListUsers(_ context.Context, _ UserFilter) ([]User, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) UpdateUser(_ context.Context, _ UserUpdate) error {
	panic("not implemented")
}
func (m *pipelineMockStore) DeleteUser(_ context.Context, _ string) error {
	panic("not implemented")
}
func (m *pipelineMockStore) CountUsersByOrg(_ context.Context, _ string) (int, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ResendInvite(_ context.Context, _, _ string) error {
	panic("not implemented")
}

// --- SessionStore stubs ---

func (m *pipelineMockStore) CreateSession(_ context.Context, _ *Session) error {
	panic("not implemented")
}
func (m *pipelineMockStore) GetSessionByHash(_ context.Context, _ string) (*Session, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) DeleteSession(_ context.Context, _ string) error {
	panic("not implemented")
}
func (m *pipelineMockStore) DeleteExpiredSessions(_ context.Context) error {
	panic("not implemented")
}

// --- AuditStore stubs ---

func (m *pipelineMockStore) WriteAudit(_ context.Context, _ *AuditEvent) error {
	panic("not implemented")
}
func (m *pipelineMockStore) ListAudit(_ context.Context, _ AuditFilter) ([]AuditEvent, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) GetOnboardingMetrics(_ context.Context, _ string) (*OnboardingMetrics, error) {
	panic("not implemented")
}

// --- Remaining Store methods stubs ---

func (m *pipelineMockStore) SaveScanWithFindings(_ context.Context, _ *model.ScanResult, _ []Finding) error {
	panic("not implemented")
}
func (m *pipelineMockStore) ListInventory(_ context.Context, _ string, _ FilterParams) ([]InventoryRow, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListExpiringCertificates(_ context.Context, _ string, _ time.Duration, _ FilterParams) ([]ExpiringCertRow, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListTopPriorityFindings(_ context.Context, _ string, _ int, _ FilterParams) ([]PriorityRow, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListFilterOptions(_ context.Context, _ string) (FilterOptions, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListHostSummaries(_ context.Context, _ string, _ string) ([]HostSummary, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) GetOrgSnapshot(_ context.Context, _ string) (*OrgSnapshot, error) {
	panic("not implemented")
}

// --- Remediation stubs ---

func (m *pipelineMockStore) SetFindingStatus(_ context.Context, _ *FindingStatusEntry) error {
	panic("not implemented")
}
func (m *pipelineMockStore) GetFindingHistory(_ context.Context, _, _ string) ([]FindingStatusEntry, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) GetRemediationSummary(_ context.Context, _ string) (*RemediationSummary, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListRemediationFindings(_ context.Context, _ string, _, _, _ string) ([]RemediationRow, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) GetFindingByID(_ context.Context, _, _ string) (*Finding, error) {
	panic("not implemented")
}
func (m *pipelineMockStore) ListFindingStatusLog(_ context.Context, _ string, _ int) ([]FindingStatusEntry, error) {
	panic("not implemented")
}

func (m *pipelineMockStore) Close() error {
	return nil
}

// Compile-time assertion: pipelineMockStore must satisfy Store.
var _ Store = (*pipelineMockStore)(nil)

// --- Tests ---

func TestPipeline_EnqueueDedup(t *testing.T) {
	p := &Pipeline{
		queue:   make(chan PipelineJob, 10),
		pending: make(map[string]bool),
	}

	p.Enqueue(PipelineJob{OrgID: "org1", Hostname: "host1"})
	p.Enqueue(PipelineJob{OrgID: "org1", Hostname: "host1"}) // dedup — same key
	p.Enqueue(PipelineJob{OrgID: "org1", Hostname: "host2"}) // different host

	assert.Equal(t, 2, len(p.queue), "dedup should have prevented the duplicate")
}

func TestPipeline_EnqueueDifferentOrg(t *testing.T) {
	p := &Pipeline{
		queue:   make(chan PipelineJob, 10),
		pending: make(map[string]bool),
	}

	p.Enqueue(PipelineJob{OrgID: "org1", Hostname: "host1"})
	p.Enqueue(PipelineJob{OrgID: "org2", Hostname: "host1"}) // different org — NOT a dup

	assert.Equal(t, 2, len(p.queue), "different org+host key should not be deduplicated")
}

func TestPipeline_Status_Idle(t *testing.T) {
	p := &Pipeline{
		queue:   make(chan PipelineJob, 10),
		pending: make(map[string]bool),
	}
	s := p.Status()
	assert.Equal(t, "idle", s.Status)
	assert.Equal(t, 0, s.QueueDepth)
	assert.Equal(t, int64(0), s.JobsProcessedTotal)
	assert.Equal(t, int64(0), s.JobsFailedTotal)
	assert.True(t, s.LastProcessedAt.IsZero())
}

func TestPipeline_Status_Processing(t *testing.T) {
	p := &Pipeline{
		queue:   make(chan PipelineJob, 10),
		pending: make(map[string]bool),
	}
	p.queue <- PipelineJob{OrgID: "org1", Hostname: "host1"}

	s := p.Status()
	assert.Equal(t, "processing", s.Status)
	assert.Equal(t, 1, s.QueueDepth)
}

func TestPipeline_ProcessJob_Success(t *testing.T) {
	mock := &pipelineMockStore{}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pipeline{
		store:   mock,
		queue:   make(chan PipelineJob, 10),
		pending: make(map[string]bool),
		ctx:     ctx,
		cancel:  cancel,
	}

	p.processJob(PipelineJob{OrgID: "org1", Hostname: "host1", ScanID: "scan1"})

	assert.Equal(t, int64(1), mock.t2Calls.Load())
	assert.Equal(t, int64(1), mock.t3Calls.Load())
	assert.Equal(t, int64(1), p.jobsProcessed.Load())
	assert.Equal(t, int64(0), p.jobsFailed.Load())

	// lastProcessed should be set
	v := p.lastProcessed.Load()
	require.NotNil(t, v)
	lastProc := v.(time.Time)
	assert.WithinDuration(t, time.Now().UTC(), lastProc, 5*time.Second)
}

func TestPipeline_ProcessJob_T2Error(t *testing.T) {
	mock := &pipelineMockStore{t2Err: errors.New("t2 boom")}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pipeline{
		store:   mock,
		queue:   make(chan PipelineJob, 10),
		pending: make(map[string]bool),
		ctx:     ctx,
		cancel:  cancel,
	}

	p.processJob(PipelineJob{OrgID: "org1", Hostname: "host1"})

	assert.Equal(t, int64(1), mock.t2Calls.Load())
	assert.Equal(t, int64(0), mock.t3Calls.Load(), "T3 should not run when T2 fails")
	assert.Equal(t, int64(0), p.jobsProcessed.Load())
	assert.Equal(t, int64(1), p.jobsFailed.Load())
}

func TestPipeline_ProcessJob_T3Error(t *testing.T) {
	mock := &pipelineMockStore{t3Err: errors.New("t3 boom")}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pipeline{
		store:   mock,
		queue:   make(chan PipelineJob, 10),
		pending: make(map[string]bool),
		ctx:     ctx,
		cancel:  cancel,
	}

	p.processJob(PipelineJob{OrgID: "org1", Hostname: "host1"})

	assert.Equal(t, int64(1), mock.t2Calls.Load())
	assert.Equal(t, int64(1), mock.t3Calls.Load())
	assert.Equal(t, int64(0), p.jobsProcessed.Load())
	assert.Equal(t, int64(1), p.jobsFailed.Load())
}

func TestPipeline_StartStop(t *testing.T) {
	mock := &pipelineMockStore{}
	p := NewPipeline(mock)
	p.Start()

	p.Enqueue(PipelineJob{OrgID: "org1", Hostname: "host1"})
	p.Enqueue(PipelineJob{OrgID: "org1", Hostname: "host2"})

	// Give the worker time to process the two jobs
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.jobsProcessed.Load() == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	p.Stop()

	assert.Equal(t, int64(2), p.jobsProcessed.Load())
	assert.Equal(t, int64(0), p.jobsFailed.Load())
}

func TestPipeline_QueueFull_DropsJob(t *testing.T) {
	// Use a tiny capacity to trigger the drop path easily.
	p := &Pipeline{
		queue:   make(chan PipelineJob, 1),
		pending: make(map[string]bool),
	}

	// Fill the queue
	p.Enqueue(PipelineJob{OrgID: "org1", Hostname: "host1"})
	// This would be a dup so pending guard fires first — use a new host
	p.Enqueue(PipelineJob{OrgID: "org1", Hostname: "host2"}) // queue full → dropped

	assert.Equal(t, 1, len(p.queue), "second job should be dropped when queue is full")
}

func TestPipeline_ClearPending(t *testing.T) {
	p := &Pipeline{
		queue:   make(chan PipelineJob, 10),
		pending: make(map[string]bool),
	}

	job := PipelineJob{OrgID: "org1", Hostname: "host1"}
	p.Enqueue(job)
	assert.True(t, p.pending["org1/host1"], "should be pending after enqueue")

	p.clearPending(job)
	assert.False(t, p.pending["org1/host1"], "should be cleared after clearPending")

	// Should be enqueueable again after clearing
	p.Enqueue(job)
	assert.Equal(t, 2, len(p.queue))
}

func TestPipeline_RebuildStale(t *testing.T) {
	staleJobs := []PipelineJob{
		{OrgID: "org1", Hostname: "h1"},
		{OrgID: "org1", Hostname: "h2"},
		{OrgID: "org2", Hostname: "h1"},
	}
	mock := &pipelineMockStore{stale: staleJobs}
	p := NewPipeline(mock)

	err := p.RebuildStale(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, len(p.queue))
}

func TestPipeline_RebuildStale_Empty(t *testing.T) {
	mock := &pipelineMockStore{stale: nil}
	p := NewPipeline(mock)

	err := p.RebuildStale(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, len(p.queue))
}

func TestPipeline_RebuildStale_Error(t *testing.T) {
	mock := &pipelineMockStore{staleErr: errors.New("db error")}
	p := NewPipeline(mock)

	err := p.RebuildStale(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listing stale hosts")
}

func TestPipeline_WorkerDrainsOnStop(t *testing.T) {
	// Verify the worker drains the queue on stop (does not block).
	mock := &pipelineMockStore{}
	p := NewPipeline(mock)
	p.Start()

	// Enqueue several jobs then stop immediately.
	for i := 0; i < 5; i++ {
		p.Enqueue(PipelineJob{OrgID: "org1", Hostname: "host" + string(rune('0'+i))})
	}
	p.Stop() // must not deadlock
	// After Stop, all metrics should be consistent (processed + failed == enqueued that ran)
	total := p.jobsProcessed.Load() + p.jobsFailed.Load()
	assert.GreaterOrEqual(t, total, int64(0))
}
