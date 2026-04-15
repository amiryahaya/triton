// Package loop implements the long-running control loop for the
// triton-engine binary: enroll with exponential backoff, then emit a
// heartbeat on a fixed cadence until the supplied context is cancelled.
package loop

import (
	"context"
	"log"
	"time"
)

// clientAPI is the subset of *client.Client the loop needs. Declared
// as an interface so tests can swap in a mock without wiring real
// TLS or HTTP machinery.
type clientAPI interface {
	Enroll(ctx context.Context) error
	Heartbeat(ctx context.Context) error
}

// DiscoveryWorker is the optional long-running subsystem spawned by
// Run once enrollment succeeds. In production this is
// *discovery.Worker; tests can pass a stub. Passing nil disables the
// discovery loop entirely — useful for engines that only do scans on
// manual trigger (future work).
type DiscoveryWorker interface {
	Run(ctx context.Context)
}

// Config tunes the loop's timing. Zero values fall back to production
// defaults (30s heartbeat, 60s max enroll backoff, 1s initial backoff).
type Config struct {
	HeartbeatInterval    time.Duration
	EnrollMaxBackoff     time.Duration
	EnrollInitialBackoff time.Duration
	// DiscoveryWorker is spawned in its own goroutine after the
	// first successful Enroll. Optional — nil disables discovery.
	DiscoveryWorker DiscoveryWorker
}

// Run blocks until ctx is cancelled. It first drives Enroll to
// success with exponential backoff (capped at cfg.EnrollMaxBackoff),
// then issues Heartbeat every cfg.HeartbeatInterval. Heartbeat
// failures are logged but never terminate the loop — transient
// network blips should not take the engine down.
func Run(ctx context.Context, c clientAPI, cfg Config) error {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.EnrollMaxBackoff == 0 {
		cfg.EnrollMaxBackoff = 60 * time.Second
	}
	if cfg.EnrollInitialBackoff == 0 {
		cfg.EnrollInitialBackoff = 1 * time.Second
	}

	if err := enrollWithBackoff(ctx, c, cfg.EnrollInitialBackoff, cfg.EnrollMaxBackoff); err != nil {
		return err
	}

	// Spawn the discovery worker (if configured) now that we're
	// enrolled. Its lifetime is tied to ctx; Run will return when
	// ctx is cancelled.
	if cfg.DiscoveryWorker != nil {
		go cfg.DiscoveryWorker.Run(ctx)
	}

	t := time.NewTicker(cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := c.Heartbeat(ctx); err != nil {
				log.Printf("heartbeat: %v", err)
			}
		}
	}
}

// enrollWithBackoff retries c.Enroll until it succeeds or ctx is
// cancelled. Backoff starts at 1s and doubles up to maxBackoff.
func enrollWithBackoff(ctx context.Context, c clientAPI, initial, maxBackoff time.Duration) error {
	backoff := initial
	for {
		err := c.Enroll(ctx)
		if err == nil {
			log.Printf("engine enrolled")
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("enroll failed (retrying in %s): %v", backoff, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
