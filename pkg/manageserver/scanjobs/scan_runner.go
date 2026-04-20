package scanjobs

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// hostLookup is the narrow subset of hosts.Store the scan runner
// needs. Declaring it as an interface — rather than taking the
// concrete *hosts.PostgresStore — lets tests inject a fake without
// spinning up Postgres for the lookup side.
type hostLookup interface {
	Get(ctx context.Context, id uuid.UUID) (hosts.Host, error)
}

// NewScanFunc builds the production ScanFunc: resolves the job's
// HostID via hl, builds a scanner Config from the job's profile, and
// runs the scanner Engine against it.
//
// Target shape mirrors the CLI's `triton scan` path (cmd/root.go):
// scannerconfig.BuildConfig produces the profile's default OS-local
// filesystem targets, then SetHostnameOverride stamps the job's host
// into the scan metadata so downstream reports attribute findings to
// the intended host. We deliberately do NOT mutate ScanTargets with
// the hostname — the scanner doesn't do remote file reads; the
// hostname is metadata, not a target.
func NewScanFunc(hl hostLookup) ScanFunc {
	return func(ctx context.Context, j Job) (*model.ScanResult, error) {
		h, err := hl.Get(ctx, j.HostID)
		if err != nil {
			return nil, fmt.Errorf("resolve host %s: %w", j.HostID, err)
		}

		cfg, err := scannerconfig.BuildConfig(scannerconfig.BuildOptions{
			Profile: string(j.Profile),
		})
		if err != nil {
			return nil, fmt.Errorf("build scan config: %w", err)
		}
		// Clear the DB URL so the scanner doesn't try to persist to
		// the embedded Triton store — Manage owns result persistence
		// via the scanresults queue.
		cfg.DBUrl = ""

		eng := scanner.New(cfg)
		eng.RegisterDefaultModules()
		if h.Hostname != "" {
			eng.SetHostnameOverride(h.Hostname)
		}

		// Engine.Scan defers close(progressCh) so we cannot pass nil.
		// Buffer generously (the CLI uses ~100) and spawn a drain
		// goroutine so Scan never blocks on send.
		progressCh := make(chan scanner.Progress, 100)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range progressCh {
				// Progress events are surfaced via heartbeat/progress_text
				// elsewhere (future enhancement); drain and discard here.
			}
		}()

		res := eng.Scan(ctx, progressCh)
		<-done

		if res == nil {
			return nil, fmt.Errorf("scanner returned nil result")
		}
		return res, nil
	}
}
