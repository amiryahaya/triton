//go:build !integration

package discovery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/tags"
)

// ---------------------------------------------------------------------------
// fakeStore implements discovery.Store in memory.
// ---------------------------------------------------------------------------

type fakeStore struct {
	mu sync.Mutex

	job        Job
	candidates []Candidate
	progress   []int // sequence of UpdateProgress counts

	// insertErrFor causes InsertCandidate to return an error for the given IP.
	insertErrFor map[string]bool
}

func newFakeStore(job Job) *fakeStore {
	return &fakeStore{job: job, insertErrFor: make(map[string]bool)}
}

func (f *fakeStore) CreateJob(_ context.Context, _ EnqueueReq, _ uuid.UUID) (Job, error) {
	return f.job, nil
}

func (f *fakeStore) GetCurrentJob(_ context.Context, _ uuid.UUID) (Job, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.job, nil
}

func (f *fakeStore) ActiveJobExists(_ context.Context, _ uuid.UUID) (bool, error) {
	return true, nil
}

func (f *fakeStore) SetCancelRequested(_ context.Context, _ uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.job.CancelRequested = true
	return nil
}

func (f *fakeStore) UpdateProgress(_ context.Context, _ uuid.UUID, scannedIPs, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.progress = append(f.progress, scannedIPs)
	return nil
}

func (f *fakeStore) UpdateStatus(_ context.Context, upd StatusUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.job.Status = upd.Status
	if upd.StartedAt != nil {
		f.job.StartedAt = upd.StartedAt
	}
	if upd.FinishedAt != nil {
		f.job.FinishedAt = upd.FinishedAt
	}
	if upd.ErrorMessage != "" {
		f.job.ErrorMessage = upd.ErrorMessage
	}
	return nil
}

func (f *fakeStore) InsertCandidate(_ context.Context, c Candidate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.insertErrFor[c.IP] {
		return errors.New("insert error for " + c.IP)
	}
	f.candidates = append(f.candidates, c)
	return nil
}

func (f *fakeStore) ListCandidates(_ context.Context, _ uuid.UUID) ([]Candidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.candidates, nil
}

func (f *fakeStore) GetCandidates(_ context.Context, _ uuid.UUID, ids []uuid.UUID) ([]Candidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idSet := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	var out []Candidate
	for _, c := range f.candidates {
		if idSet[c.ID] {
			out = append(out, c)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// fakeStoreCancelling wraps fakeStore and overrides GetCurrentJob to
// return CancelRequested=true once a threshold number of candidates have been
// inserted.
// ---------------------------------------------------------------------------

type fakeStoreCancelling struct {
	*fakeStore
	cancelAfterCount int
}

func (f *fakeStoreCancelling) GetCurrentJob(ctx context.Context, tenantID uuid.UUID) (Job, error) {
	j, err := f.fakeStore.GetCurrentJob(ctx, tenantID)
	if err != nil {
		return j, err
	}
	f.mu.Lock()
	count := len(f.candidates)
	f.mu.Unlock()
	if count >= f.cancelAfterCount {
		j.CancelRequested = true
	}
	return j, nil
}

// ---------------------------------------------------------------------------
// fakeHostsStore implements hosts.Store in memory.
// ---------------------------------------------------------------------------

type fakeHostsStore struct {
	hosts []hosts.Host
}

func (f *fakeHostsStore) Create(_ context.Context, h hosts.Host) (hosts.Host, error) {
	f.hosts = append(f.hosts, h)
	return h, nil
}

func (f *fakeHostsStore) Get(_ context.Context, id uuid.UUID) (hosts.Host, error) {
	for _, h := range f.hosts {
		if h.ID == id {
			return h, nil
		}
	}
	return hosts.Host{}, hosts.ErrNotFound
}

func (f *fakeHostsStore) List(_ context.Context) ([]hosts.Host, error) {
	return f.hosts, nil
}

func (f *fakeHostsStore) Update(_ context.Context, h hosts.Host) (hosts.Host, error) {
	for i, existing := range f.hosts {
		if existing.ID == h.ID {
			f.hosts[i] = h
			return h, nil
		}
	}
	return hosts.Host{}, hosts.ErrNotFound
}

func (f *fakeHostsStore) Delete(_ context.Context, id uuid.UUID) error {
	for i, h := range f.hosts {
		if h.ID == id {
			f.hosts = append(f.hosts[:i], f.hosts[i+1:]...)
			return nil
		}
	}
	return hosts.ErrNotFound
}

func (f *fakeHostsStore) Count(_ context.Context) (int64, error) {
	return int64(len(f.hosts)), nil
}

func (f *fakeHostsStore) SetTags(_ context.Context, _ uuid.UUID, _ []uuid.UUID) error {
	return nil
}

func (f *fakeHostsStore) ResolveTagNames(_ context.Context, names []string, _ string) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, len(names))
	for i := range names {
		ids[i] = uuid.New()
	}
	return ids, nil
}

func (f *fakeHostsStore) ListByTags(_ context.Context, _ []uuid.UUID) ([]hosts.Host, error) {
	return nil, nil
}

func (f *fakeHostsStore) CountByTag(_ context.Context, _ uuid.UUID) (int64, error) {
	return 0, nil
}

func (f *fakeHostsStore) ListByHostnames(_ context.Context, _ []string) ([]hosts.Host, error) {
	return nil, nil
}

func (f *fakeHostsStore) BulkCreate(_ context.Context, hs []hosts.Host) ([]hosts.Host, error) {
	f.hosts = append(f.hosts, hs...)
	return hs, nil
}

// ---------------------------------------------------------------------------
// fakeScanner emits pre-configured candidates then returns an optional error.
// It implements ScannerIface so it can be injected directly into Worker.
// ---------------------------------------------------------------------------

type fakeScanner struct {
	candidates []Candidate
	err        error
}

func (fs *fakeScanner) Scan(_ context.Context, _ string, _ int, out chan<- Candidate, progress chan<- struct{}) error {
	for _, c := range fs.candidates {
		out <- c
		progress <- struct{}{}
	}
	close(out)
	close(progress)
	return fs.err
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newJob(tenantID uuid.UUID) Job {
	return Job{
		ID:       uuid.New(),
		TenantID: tenantID,
		CIDR:     "10.0.0.0/24",
		SSHPort:  22,
		Status:   "queued",
	}
}

func makeCandidates(n int) []Candidate {
	cs := make([]Candidate, n)
	for i := range cs {
		cs[i] = Candidate{
			ID: uuid.New(),
			IP: fmt.Sprintf("10.0.%d.%d", i/254, (i%254)+1),
		}
	}
	return cs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestWorkerCancelsCleanly: 60 candidates, cancel triggered after 50 inserted.
func TestWorkerCancelsCleanly(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)

	base := newFakeStore(job)
	store := &fakeStoreCancelling{fakeStore: base, cancelAfterCount: 50}

	hostsStore := &fakeHostsStore{}
	fs := &fakeScanner{candidates: makeCandidates(60)}

	w := &Worker{Store: store, HostsStore: hostsStore, Scanner: fs}
	w.Run(context.Background(), job)

	base.mu.Lock()
	status := base.job.Status
	count := len(base.candidates)
	base.mu.Unlock()

	if status != "cancelled" {
		t.Errorf("expected status=cancelled, got %q", status)
	}
	if count < 50 {
		t.Errorf("expected ≥50 candidates inserted before cancel, got %d", count)
	}
}

// TestWorkerSetsFailedOnScanError: scanner returns a non-nil, non-Canceled error.
func TestWorkerSetsFailedOnScanError(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)

	store := newFakeStore(job)
	hostsStore := &fakeHostsStore{}

	scanErr := errors.New("network unreachable")
	fs := &fakeScanner{candidates: makeCandidates(3), err: scanErr}

	w := &Worker{Store: store, HostsStore: hostsStore, Scanner: fs}
	w.Run(context.Background(), job)

	store.mu.Lock()
	status := store.job.Status
	errMsg := store.job.ErrorMessage
	store.mu.Unlock()

	if status != "failed" {
		t.Errorf("expected status=failed, got %q", status)
	}
	if errMsg != scanErr.Error() {
		t.Errorf("expected error_message=%q, got %q", scanErr.Error(), errMsg)
	}
}

// TestWorkerProgressUpdatedEvery50: 150 candidates → UpdateProgress called with
// 50, 100, 150 (in order) during the loop.
func TestWorkerProgressUpdatedEvery50(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)

	store := newFakeStore(job)
	hostsStore := &fakeHostsStore{}

	fs := &fakeScanner{candidates: makeCandidates(150)}

	w := &Worker{Store: store, HostsStore: hostsStore, Scanner: fs}
	w.Run(context.Background(), job)

	store.mu.Lock()
	progress := store.progress
	store.mu.Unlock()

	// We expect 50, 100, 150 to appear in order somewhere in progress.
	want := []int{50, 100, 150}
	idx := 0
	for _, p := range progress {
		if idx < len(want) && p == want[idx] {
			idx++
		}
	}
	if idx != len(want) {
		t.Errorf("expected UpdateProgress calls with values %v (in order), got %v", want, progress)
	}
}

// TestWorkerExistingHostIDSet: host "10.0.0.1" already exists → candidate gets ExistingHostID.
func TestWorkerExistingHostIDSet(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)

	store := newFakeStore(job)

	hostID := uuid.New()
	hostsStore := &fakeHostsStore{
		hosts: []hosts.Host{
			{
				ID:       hostID,
				Hostname: "existing-host",
				IP:       "10.0.0.1",
				Tags:     []tags.Tag{},
			},
		},
	}

	fs := &fakeScanner{
		candidates: []Candidate{
			{ID: uuid.New(), IP: "10.0.0.1"},
		},
	}

	w := &Worker{Store: store, HostsStore: hostsStore, Scanner: fs}
	w.Run(context.Background(), job)

	store.mu.Lock()
	cands := store.candidates
	store.mu.Unlock()

	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(cands))
	}
	if cands[0].ExistingHostID == nil {
		t.Fatal("expected ExistingHostID to be set, got nil")
	}
	if *cands[0].ExistingHostID != hostID {
		t.Errorf("expected ExistingHostID=%v, got %v", hostID, *cands[0].ExistingHostID)
	}
}

// TestWorkerDBInsertErrorSkipped: insert error for one IP → scan continues, status=completed.
func TestWorkerDBInsertErrorSkipped(t *testing.T) {
	tenantID := uuid.New()
	job := newJob(tenantID)

	store := newFakeStore(job)
	store.insertErrFor["10.0.0.2"] = true

	hostsStore := &fakeHostsStore{}

	fs := &fakeScanner{
		candidates: []Candidate{
			{ID: uuid.New(), IP: "10.0.0.1"},
			{ID: uuid.New(), IP: "10.0.0.2"},
			{ID: uuid.New(), IP: "10.0.0.3"},
		},
	}

	w := &Worker{Store: store, HostsStore: hostsStore, Scanner: fs}
	w.Run(context.Background(), job)

	store.mu.Lock()
	status := store.job.Status
	count := len(store.candidates)
	store.mu.Unlock()

	if status != "completed" {
		t.Errorf("expected status=completed, got %q", status)
	}
	if count != 2 {
		t.Errorf("expected 2 successfully inserted candidates (1 error skipped), got %d", count)
	}
}
