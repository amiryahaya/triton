package store

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const pipelineQueueCapacity = 1000

// Pipeline runs the T2+T3 analytics transforms in a background goroutine.
// Jobs are enqueued by scan submission handlers and the cold-start rebuilder.
// Analytics Phase 4A.
type Pipeline struct {
	store   Store
	queue   chan PipelineJob
	pending map[string]bool // key: "orgID/hostname", dedup guard
	stopped bool            // set in Stop(), checked in Enqueue() to prevent send-on-closed-channel
	mu      sync.Mutex
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	// Metrics (atomic for lock-free reads from the status endpoint)
	jobsProcessed atomic.Int64
	jobsFailed    atomic.Int64
	processing    atomic.Bool  // true while worker is executing a job
	lastProcessed atomic.Value // stores time.Time
}

// NewPipeline creates a pipeline. Call Start() to begin processing.
func NewPipeline(s Store) *Pipeline {
	ctx, cancel := context.WithCancel(context.Background())
	return &Pipeline{
		store:   s,
		queue:   make(chan PipelineJob, pipelineQueueCapacity),
		pending: make(map[string]bool),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start launches the background worker goroutine.
func (p *Pipeline) Start() {
	p.wg.Add(1)
	go p.worker()
}

// Stop signals the worker to drain and waits for completion.
// Must not be called concurrently with itself.
func (p *Pipeline) Stop() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	p.cancel()
	close(p.queue)
	p.wg.Wait()
}

// Enqueue adds a pipeline job. Deduplicates by org+hostname.
// Safe to call after Stop() — jobs are silently dropped.
func (p *Pipeline) Enqueue(job PipelineJob) {
	key := job.OrgID + "/" + job.Hostname
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped || p.pending[key] {
		return
	}
	select {
	case p.queue <- job:
		p.pending[key] = true
	default:
		log.Printf("pipeline: queue full (capacity %d), dropping job for %s/%s",
			pipelineQueueCapacity, job.OrgID, job.Hostname)
	}
}

// Status returns the current pipeline state for the status endpoint.
func (p *Pipeline) Status() PipelineStatus {
	status := "idle"
	if len(p.queue) > 0 || p.processing.Load() {
		status = "processing"
	}
	var lastProc time.Time
	if v := p.lastProcessed.Load(); v != nil {
		lastProc = v.(time.Time)
	}
	return PipelineStatus{
		Status:             status,
		QueueDepth:         len(p.queue),
		LastProcessedAt:    lastProc,
		JobsProcessedTotal: p.jobsProcessed.Load(),
		JobsFailedTotal:    p.jobsFailed.Load(),
	}
}

// RebuildStale enqueues pipeline jobs for all hosts whose summaries
// are missing or stale. Called on server start after the findings
// backfill completes.
func (p *Pipeline) RebuildStale(ctx context.Context) error {
	stale, err := p.store.ListStaleHosts(ctx)
	if err != nil {
		return fmt.Errorf("listing stale hosts: %w", err)
	}
	if len(stale) == 0 {
		return nil
	}
	log.Printf("pipeline: rebuilding summaries for %d stale hosts", len(stale))
	for _, job := range stale {
		p.Enqueue(job)
	}
	return nil
}

func (p *Pipeline) worker() {
	defer p.wg.Done()
	for job := range p.queue {
		p.clearPending(job)
		if p.ctx.Err() != nil {
			continue // drain the channel but skip processing
		}
		p.processJob(job)
	}
}

func (p *Pipeline) clearPending(job PipelineJob) {
	key := job.OrgID + "/" + job.Hostname
	p.mu.Lock()
	delete(p.pending, key)
	p.mu.Unlock()
}

func (p *Pipeline) processJob(job PipelineJob) {
	p.processing.Store(true)
	defer p.processing.Store(false)

	// T2: Refresh host summary
	if err := p.store.RefreshHostSummary(p.ctx, job.OrgID, job.Hostname); err != nil {
		log.Printf("pipeline T2 error (org=%s host=%s): %v", job.OrgID, job.Hostname, err)
		p.jobsFailed.Add(1)
		return
	}

	// T3: Refresh org snapshot
	if err := p.store.RefreshOrgSnapshot(p.ctx, job.OrgID); err != nil {
		log.Printf("pipeline T3 error (org=%s): %v", job.OrgID, err)
		p.jobsFailed.Add(1)
		return
	}

	p.jobsProcessed.Add(1)
	p.lastProcessed.Store(time.Now().UTC())
}
