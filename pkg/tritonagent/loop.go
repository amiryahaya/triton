package tritonagent

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// EngineAPI is the interface the agent loop uses to communicate with the
// engine's agent gateway. Implemented by *Client for production; stubbed
// in tests.
type EngineAPI interface {
	Register(ctx context.Context, version string) error
	Heartbeat(ctx context.Context) error
	PollScan(ctx context.Context) (*ScanCommand, error)
	SubmitFindings(ctx context.Context, scanResult []byte) error
}

// Scanner abstracts local scan execution so that loop tests can avoid
// invoking the real scanner engine (which is slow and scans the filesystem).
type Scanner interface {
	// RunScan executes a scan with the given profile and returns the result
	// as a JSON-serializable object. Returns nil if the scan produced no result.
	RunScan(ctx context.Context, profile string) (any, error)
}

// Config holds the agent loop configuration.
type Config struct {
	HeartbeatInterval time.Duration
	PollInterval      time.Duration
	DefaultProfile    string
	Version           string
	Scanner           Scanner
}

// Run is the main agent loop: register with retries, then heartbeat and
// poll for scan commands in parallel. Blocks until ctx is cancelled.
func Run(ctx context.Context, c EngineAPI, cfg Config) error {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.DefaultProfile == "" {
		cfg.DefaultProfile = "standard"
	}
	if cfg.Version == "" {
		cfg.Version = "unknown"
	}

	// 1. Register with exponential backoff.
	backoff := 1 * time.Second
	for {
		if err := c.Register(ctx, cfg.Version); err == nil {
			log.Printf("agent registered (version %s)", cfg.Version)
			break
		} else if ctx.Err() != nil {
			return ctx.Err()
		} else {
			log.Printf("register: %v (retrying in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
		}
	}

	// 2. Heartbeat goroutine.
	go func() {
		t := time.NewTicker(cfg.HeartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := c.Heartbeat(ctx); err != nil {
					log.Printf("heartbeat: %v", err)
				}
			}
		}
	}()

	// 3. Scan poll loop.
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		cmd, err := c.PollScan(ctx)
		if err != nil {
			log.Printf("poll scan: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if cmd == nil {
			// No work — wait before re-polling.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(cfg.PollInterval):
			}
			continue
		}

		// Execute scan locally.
		profile := cmd.ScanProfile
		if profile == "" {
			profile = cfg.DefaultProfile
		}

		log.Printf("scan command received: profile=%s", profile)

		if cfg.Scanner == nil {
			log.Printf("no scanner configured, skipping scan")
			continue
		}

		result, err := cfg.Scanner.RunScan(ctx, profile)
		if err != nil {
			log.Printf("scan error: %v", err)
			continue
		}
		if result == nil {
			log.Printf("scan returned nil result")
			continue
		}

		resultJSON, err := json.Marshal(result)
		if err != nil {
			log.Printf("marshal scan result: %v", err)
			continue
		}

		if err := c.SubmitFindings(ctx, resultJSON); err != nil {
			log.Printf("submit findings: %v", err)
		} else {
			log.Printf("scan findings submitted (%d bytes)", len(resultJSON))
		}
	}
}
