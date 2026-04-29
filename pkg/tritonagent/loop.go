package tritonagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// ManageAPI is the interface the agent loop uses to communicate with the
// Manage Server's agent gateway. Implemented by *Client for production;
// stubbed in tests.
type ManageAPI interface {
	Heartbeat(ctx context.Context) error
	PollCommand(ctx context.Context) (*AgentCommand, error)
	SubmitScan(ctx context.Context, jobID string, scanResult []byte) error
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

// Run is the main agent loop: heartbeat and poll for commands in parallel.
// Blocks until ctx is cancelled.
func Run(ctx context.Context, c ManageAPI, cfg Config) error {
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

	// 1. Heartbeat goroutine.
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

	// 2. Command poll loop.
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		cmd, err := c.PollCommand(ctx)
		if err != nil {
			log.Printf("poll command: %v", err)
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

		log.Printf("command received: profile=%s job_id=%s", profile, cmd.JobID)

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

		// Stamp the source before marshaling.
		if sr, ok := result.(*model.ScanResult); ok {
			sr.Metadata.Source = model.ScanSourceAgent
		}

		resultJSON, err := json.Marshal(result)
		if err != nil {
			log.Printf("marshal scan result: %v", err)
			continue
		}

		if err := c.SubmitScan(ctx, cmd.JobID, resultJSON); err != nil {
			if errors.Is(err, ErrAuthFailed) {
				return fmt.Errorf("submit scan: authentication rejected — check certificate or agent enrollment: %w", err)
			}
			log.Printf("submit scan: %v", err)
		} else {
			log.Printf("scan submitted (%d bytes, job_id=%s)", len(resultJSON), cmd.JobID)
		}
	}
}
