package scanexec

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/amiryahaya/triton/pkg/engine/client"
)

// ScanAPI is the subset of *client.Client the worker needs. Narrowed to an
// interface so tests can inject a fake without touching HTTP.
type ScanAPI interface {
	PollScanJob(ctx context.Context) (*client.ScanJobPayload, error)
	SubmitScanProgress(ctx context.Context, jobID string, updates []client.ScanProgressUpdate) error
	SubmitScanFindings(ctx context.Context, jobID, hostID string, scanResult []byte, findings int) error
	FinishScanJob(ctx context.Context, jobID, status, errMsg string) error
}

// HostScanner is the subset of *Executor the worker needs.
type HostScanner interface {
	ScanHost(ctx context.Context, host HostTarget, secretRef, authType, profile string) HostResult
}

// Worker long-polls the portal for scan jobs, runs each host through the
// HostScanner, and streams progress + findings back to the portal.
type Worker struct {
	Client   ScanAPI
	Executor HostScanner

	// PollError is the backoff applied after a PollScanJob transport error.
	// Default 5s.
	PollError time.Duration

	// HostTimeout caps per-host scan duration. Default 5 minutes.
	HostTimeout time.Duration
}

// Run blocks until ctx is cancelled, polling for scan jobs and dispatching
// them one at a time.
func (w *Worker) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		job, err := w.Client.PollScanJob(ctx)
		if err != nil {
			wait := w.PollError
			if wait == 0 {
				wait = 5 * time.Second
			}
			log.Printf("scan job poll: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			continue
		}
		if job == nil {
			continue
		}
		w.runOne(ctx, job)
	}
}

func (w *Worker) runOne(ctx context.Context, job *client.ScanJobPayload) {
	log.Printf("scan job claimed: %s (%d hosts, profile=%s)", job.ID, len(job.Hosts), job.ScanProfile)

	hostTimeout := w.HostTimeout
	if hostTimeout == 0 {
		hostTimeout = 5 * time.Minute
	}

	secretRef := ""
	if job.CredentialSecretRef != nil {
		secretRef = *job.CredentialSecretRef
	}

	done, failed := 0, 0
	for i := range job.Hosts {
		if ctx.Err() != nil {
			return
		}

		host := job.Hosts[i]
		hctx, cancel := context.WithTimeout(ctx, hostTimeout)
		target := HostTarget{
			ID:       host.ID,
			Address:  host.Address,
			Port:     host.Port,
			Hostname: host.Hostname,
			OS:       host.OS,
		}
		res := w.Executor.ScanHost(hctx, target, secretRef, job.CredentialAuthType, job.ScanProfile)
		cancel()

		update := client.ScanProgressUpdate{
			HostID:        host.ID,
			FindingsCount: res.Findings,
		}
		if res.Success {
			done++
			update.Status = "completed"

			if res.Result != nil {
				scanJSON, err := json.Marshal(res.Result)
				if err != nil {
					log.Printf("marshal scan result for %s: %v", host.ID, err)
				} else if err := w.Client.SubmitScanFindings(ctx, job.ID, host.ID, scanJSON, res.Findings); err != nil {
					log.Printf("submit findings for %s: %v", host.ID, err)
				}
			}
		} else {
			failed++
			update.Status = "failed"
			update.Error = res.Error
		}

		if err := w.Client.SubmitScanProgress(ctx, job.ID, []client.ScanProgressUpdate{update}); err != nil {
			log.Printf("submit progress: %v", err)
		}
	}

	finalStatus := "completed"
	errMsg := ""
	total := len(job.Hosts)
	switch {
	case failed > 0 && done == 0:
		finalStatus = "failed"
		errMsg = fmt.Sprintf("all %d hosts failed", total)
	case failed > 0:
		errMsg = fmt.Sprintf("%d of %d hosts failed", failed, total)
	}
	if err := w.Client.FinishScanJob(ctx, job.ID, finalStatus, errMsg); err != nil {
		log.Printf("finish scan job: %v", err)
	}
}
