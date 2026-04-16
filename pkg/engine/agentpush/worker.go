package agentpush

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/amiryahaya/triton/pkg/engine/client"
)

// PushAPI is the subset of *client.Client the push worker needs.
// Narrowed to an interface so tests can inject a fake.
type PushAPI interface {
	PollPushJob(ctx context.Context) (*client.PushJobPayload, error)
	SubmitPushProgress(ctx context.Context, jobID string, updates []client.PushProgressUpdate) error
	FinishPushJob(ctx context.Context, jobID, status, errMsg string) error
	RegisterAgent(ctx context.Context, hostID, certFingerprint, version string) error
}

// HostPusher is the subset of *Executor the worker needs.
type HostPusher interface {
	PushToHost(ctx context.Context, host HostTarget, secretRef, authType string) PushResult
}

// Worker long-polls the portal for push jobs, runs each host through
// the HostPusher, and streams progress back. Mirrors scanexec.Worker.
type Worker struct {
	Client      PushAPI
	Executor    HostPusher
	PollError   time.Duration // backoff after poll error; default 5s
	HostTimeout time.Duration // per-host push timeout; default 5 min
	Version     string        // agent version to report on register
}

// Run blocks until ctx is cancelled, polling for push jobs and
// dispatching them one at a time.
func (w *Worker) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		job, err := w.Client.PollPushJob(ctx)
		if err != nil {
			wait := w.PollError
			if wait == 0 {
				wait = 5 * time.Second
			}
			log.Printf("push job poll: %v", err)
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

func (w *Worker) runOne(ctx context.Context, job *client.PushJobPayload) {
	log.Printf("push job claimed: %s (%d hosts)", job.ID, len(job.Hosts))

	hostTimeout := w.HostTimeout
	if hostTimeout == 0 {
		hostTimeout = 5 * time.Minute
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

		res := w.Executor.PushToHost(hctx, target, job.CredentialSecretRef, job.CredentialAuthType)
		cancel()

		update := client.PushProgressUpdate{
			HostID: host.ID,
		}
		if res.Success {
			done++
			update.Status = "completed"
			update.Fingerprint = res.Fingerprint

			// Register the agent with the portal.
			if err := w.Client.RegisterAgent(ctx, host.ID, res.Fingerprint, w.Version); err != nil {
				log.Printf("register agent for %s: %v", host.ID, err)
			}
		} else {
			failed++
			update.Status = "failed"
			update.Error = res.Error
		}

		if err := w.Client.SubmitPushProgress(ctx, job.ID, []client.PushProgressUpdate{update}); err != nil {
			log.Printf("submit push progress: %v", err)
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
	if err := w.Client.FinishPushJob(ctx, job.ID, finalStatus, errMsg); err != nil {
		log.Printf("finish push job: %v", err)
	}
}
