// pkg/scanrunner/runner.go
package scanrunner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// RunOne executes the full lifecycle for one scan job:
// claim → resolve host → scan → submit → complete.
// Returns nil when the job is not found or already claimed (exit 0 case).
// Returns non-nil on scan or submission failure (caller should exit 1).
func RunOne(ctx context.Context, jobID uuid.UUID, manage *ManageClient, report *ReportClient, scanner Scanner) error {
	// Step 1: Claim.
	claim, err := manage.Claim(ctx, jobID)
	if err != nil {
		if errors.Is(err, ErrJobGone) {
			log.Printf("runner: job %s: not found or already claimed — exiting cleanly", jobID)
			return nil
		}
		return fmt.Errorf("runner: claim %s: %w", jobID, err)
	}

	// All failures from here must be reported to the manage server.
	fail := func(scanErr error) error {
		ctx2 := context.Background() // parent ctx may be cancelled
		if ferr := manage.Fail(ctx2, jobID, scanErr.Error()); ferr != nil {
			log.Printf("runner: report fail for %s: %v", jobID, ferr)
		}
		return scanErr
	}

	// Step 2: Resolve host IP.
	host, err := manage.GetHost(ctx, claim.HostID)
	if err != nil {
		return fail(fmt.Errorf("runner: get host %s: %w", claim.HostID, err))
	}
	if host.IP == "" {
		return fail(fmt.Errorf("runner: host %s has no IP address", claim.HostID))
	}

	// Step 3: Heartbeat goroutine.
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-tick.C:
				if err := manage.Heartbeat(hbCtx, jobID); err != nil {
					log.Printf("runner: heartbeat %s: %v", jobID, err)
				}
			}
		}
	}()

	// Step 4: Scan.
	target := Target{
		IP:           host.IP,
		Profile:      claim.Profile,
		PortOverride: claim.PortOverride,
	}
	var findings []Finding
	if err := scanner.Scan(ctx, target, func(f Finding) {
		findings = append(findings, f)
	}); err != nil {
		return fail(fmt.Errorf("runner: scan %s: %w", host.IP, err))
	}

	// Step 5: Map + submit.
	hostname := host.Hostname
	if hostname == "" {
		hostname = host.IP
	}
	result := ToScanResult(hostname, host.IP, claim.Profile, findings)
	if err := report.Submit(ctx, result); err != nil {
		return fail(fmt.Errorf("runner: submit %s: %w", jobID, err))
	}

	// Step 6: Mark complete (best-effort — result already submitted).
	if err := manage.Complete(ctx, jobID); err != nil {
		log.Printf("runner: complete %s: %v", jobID, err)
	}
	return nil
}
