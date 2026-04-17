package discovery

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/google/uuid"

	srvdisc "github.com/amiryahaya/triton/pkg/server/discovery"
)

// clientAPI is the subset of *client.Client the worker needs. Defined
// as an interface here so tests can substitute a lightweight fake
// without standing up a real mTLS HTTP client. *client.Client
// satisfies this interface via its PollDiscovery + SubmitDiscovery
// methods.
type clientAPI interface {
	PollDiscovery(ctx context.Context) (*srvdisc.Job, error)
	SubmitDiscovery(ctx context.Context, jobID uuid.UUID, candidates []srvdisc.Candidate, errMsg string) error
}

// Worker drives the long-poll loop: claim a job, run the scan, submit
// results, repeat until ctx is cancelled. Errors are logged and never
// escalated — the engine is expected to keep running across transient
// network failures.
type Worker struct {
	Client        clientAPI
	Scanner       *Scanner
	PollErrorWait time.Duration
	// ScanTimeout bounds a single scan. Zero means 10 minutes. Exposed
	// primarily for tests.
	ScanTimeout time.Duration
}

// Run blocks until ctx is cancelled. Every iteration:
//   - PollDiscovery — on error, sleep PollErrorWait then retry.
//     A nil job (server returned 204) is *not* an error and the
//     worker re-polls immediately.
//   - Scan — bounded by ScanTimeout; errors are captured and
//     forwarded to the server via the submit body's "error" field.
//   - SubmitDiscovery — failures are logged but the loop continues;
//     the server will time the job out server-side.
func (w *Worker) Run(ctx context.Context) {
	pollWait := w.PollErrorWait
	if pollWait == 0 {
		pollWait = 5 * time.Second
	}
	scanTimeout := w.ScanTimeout
	if scanTimeout == 0 {
		scanTimeout = 10 * time.Minute
	}

	for {
		if ctx.Err() != nil {
			return
		}

		job, err := w.Client.PollDiscovery(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("discovery poll: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollWait):
			}
			continue
		}
		if job == nil {
			// 204 — re-poll immediately.
			continue
		}

		log.Printf("discovery job claimed: %s (cidrs=%v ports=%v)", job.ID, job.CIDRs, job.Ports)

		scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
		scanned, scanErr := w.Scanner.Scan(scanCtx, job.CIDRs, job.Ports)
		cancel()

		var errMsg string
		var out []srvdisc.Candidate
		if scanErr != nil {
			errMsg = scanErr.Error()
			log.Printf("discovery scan failed: %v", scanErr)
		} else {
			out = make([]srvdisc.Candidate, 0, len(scanned))
			for _, c := range scanned {
				// The engine-side Candidate carries Address as a
				// string; the wire format expects a parseable IP.
				// ParseIP handles both "10.0.0.1" and "::1".
				ip := net.ParseIP(c.Address)
				if ip == nil {
					log.Printf("discovery: dropping unparseable address %q", c.Address)
					continue
				}
				out = append(out, srvdisc.Candidate{
					Address:    ip,
					Hostname:   c.Hostname,
					OpenPorts:  c.OpenPorts,
					MACAddress: c.MACAddress,
					MACVendor:  c.MACVendor,
					Services:   c.Services,
				})
			}
		}

		if err := w.Client.SubmitDiscovery(ctx, job.ID, out, errMsg); err != nil {
			log.Printf("discovery submit: %v", err)
		}
	}
}
