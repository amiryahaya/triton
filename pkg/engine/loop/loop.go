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

// Worker is implemented by any long-running engine background process
// that should be started after the first successful enroll and stopped
// when ctx is cancelled. discovery.Worker, credentials.Handler, and
// credentials.TestWorker all satisfy this.
type Worker interface {
	Run(ctx context.Context)
}

// Config tunes the loop's timing. Zero values fall back to production
// defaults (30s heartbeat, 60s max enroll backoff, 1s initial backoff).
type Config struct {
	HeartbeatInterval    time.Duration
	EnrollMaxBackoff     time.Duration
	EnrollInitialBackoff time.Duration

	// DiscoveryWorker is spawned in its own goroutine after the first
	// successful Enroll. Optional — nil disables the discovery loop.
	DiscoveryWorker Worker

	// CredentialHandler processes incoming credential push/delete
	// deliveries. Spawned after first successful Enroll. Optional.
	CredentialHandler Worker

	// CredentialTestWorker runs credential-test probe jobs. Spawned
	// after first successful Enroll. Optional.
	CredentialTestWorker Worker

	// OnEnrolled is called exactly once, immediately after the first
	// successful Enroll and before any Worker is spawned. Intended for
	// the engine to publish its encryption pubkey once the portal has
	// accepted enrollment. The callback is invoked on the ctx passed to
	// Run, so long-running work inside it will block Worker spawn.
	OnEnrolled func(ctx context.Context)
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

	// One-shot post-enroll hook. Guaranteed to fire before any Worker
	// starts so callbacks that depend on server-side state (e.g. pubkey
	// submission) can complete before workers begin polling.
	if cfg.OnEnrolled != nil {
		cfg.OnEnrolled(ctx)
	}

	if cfg.DiscoveryWorker != nil {
		go cfg.DiscoveryWorker.Run(ctx)
	}
	if cfg.CredentialHandler != nil {
		go cfg.CredentialHandler.Run(ctx)
	}
	if cfg.CredentialTestWorker != nil {
		go cfg.CredentialTestWorker.Run(ctx)
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
