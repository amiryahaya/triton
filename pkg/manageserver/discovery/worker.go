package discovery

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
)

// Worker orchestrates a single discovery job: runs the Scanner, inserts
// candidates as they arrive, polls for cancel requests every 50 IPs, and
// updates the job status in the Store.
type Worker struct {
	Store      Store
	HostsStore hosts.Store
	Scanner    ScannerIface
}

// Run executes the discovery job in the calling goroutine. It is intended to
// be launched with "go w.Run(ctx, job)" so the caller is not blocked.
func (w *Worker) Run(ctx context.Context, job Job) {
	defer func() {
		if r := recover(); r != nil {
			fin := time.Now()
			log.Printf("discovery worker: panic in job %s: %v", job.ID, r)
			_ = w.Store.UpdateStatus(ctx, StatusUpdate{
				JobID:        job.ID,
				Status:       "failed",
				FinishedAt:   &fin,
				ErrorMessage: fmt.Sprintf("internal panic: %v", r),
			})
		}
	}()

	// Step 1: mark job as running.
	now := time.Now()
	_ = w.Store.UpdateStatus(ctx, StatusUpdate{
		JobID:     job.ID,
		Status:    "running",
		StartedAt: &now,
	})

	// Step 2: child context so we can cancel the scanner independently.
	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan()

	// Step 3: start scanner in its own goroutine.
	out := make(chan Candidate, 64)
	progress := make(chan struct{}, 64)
	scanErr := make(chan error, 1)
	go func() {
		scanErr <- w.Scanner.Scan(scanCtx, job.CIDR, job.SSHPort, out, progress)
	}()

	// Step 3b: Build a one-time IP→host-ID map to avoid N full-table scans.
	hostByIP := make(map[string]uuid.UUID)
	if allHosts, err := w.HostsStore.List(ctx); err == nil {
		for i := range allHosts {
			if allHosts[i].IP != "" {
				hostByIP[allHosts[i].IP] = allHosts[i].ID
			}
		}
	} else {
		log.Printf("discovery worker: list hosts for IP lookup: %v", err)
	}

	// Step 4: consume candidates and progress ticks concurrently.
	// Both goroutines update these counters; use atomics to avoid a data race.
	var foundCount, scannedCount atomic.Int64

	// Drain the progress channel in a background goroutine so it never blocks
	// the scanner. We tally scanned IPs and fire periodic store updates here.
	var progressWg sync.WaitGroup
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		for range progress {
			sc := scannedCount.Add(1)
			if sc%50 == 0 {
				_ = w.Store.UpdateProgress(ctx, job.ID, int(sc), int(foundCount.Load()))
				j, err := w.Store.GetCurrentJob(ctx, job.TenantID)
				if err == nil && j.CancelRequested {
					cancelScan()
				}
			}
		}
	}()

	for c := range out {
		c.JobID = job.ID
		if id, ok := hostByIP[c.IP]; ok {
			c.ExistingHostID = &id
		}

		if err := w.Store.InsertCandidate(ctx, c); err != nil {
			log.Printf("discovery worker: insert candidate %s: %v", c.IP, err)
			// continue — don't abort the scan on a single insert failure
		} else {
			foundCount.Add(1)
		}
	}

	progressWg.Wait()

	// Step 5: wait for the scanner goroutine to finish.
	err := <-scanErr

	// Step 6: check if we were cancelled.
	j, _ := w.Store.GetCurrentJob(ctx, job.TenantID)
	if j.CancelRequested {
		fin := time.Now()
		_ = w.Store.UpdateStatus(ctx, StatusUpdate{
			JobID:      job.ID,
			Status:     "cancelled",
			FinishedAt: &fin,
		})
		return
	}

	// Step 7: handle scanner error vs completion.
	fin := time.Now()
	if err != nil && err != context.Canceled {
		_ = w.Store.UpdateStatus(ctx, StatusUpdate{
			JobID:        job.ID,
			Status:       "failed",
			FinishedAt:   &fin,
			ErrorMessage: err.Error(),
		})
		return
	}

	// Final progress update + completed status.
	_ = w.Store.UpdateProgress(ctx, job.ID, int(scannedCount.Load()), int(foundCount.Load()))
	_ = w.Store.UpdateStatus(ctx, StatusUpdate{
		JobID:      job.ID,
		Status:     "completed",
		FinishedAt: &fin,
	})
}
