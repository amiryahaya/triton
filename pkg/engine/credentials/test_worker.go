package credentials

import (
	"context"
	"log"
	"time"

	"github.com/amiryahaya/triton/pkg/engine/client"
	"github.com/amiryahaya/triton/pkg/engine/keystore"
)

// TestAPI is the slice of the engine HTTP client used by the credential
// test worker.
type TestAPI interface {
	PollCredentialTest(ctx context.Context) (*client.TestJobPayload, error)
	SubmitCredentialTest(ctx context.Context, testID string, results []client.SubmittedTestResult, errMsg string) error
}

// HostProber is the interface satisfied by *Prober. Declared here so
// tests can inject a fake without a real SSH server.
type HostProber interface {
	Probe(ctx context.Context, authType string, secret Secret, address string, port int) ProbeResult
}

// TestWorker drains credential test jobs: looks up the secret in the
// local keystore, probes each target host, and posts per-host results.
type TestWorker struct {
	Client      TestAPI
	Keystore    *keystore.Keystore
	Prober      HostProber
	PollBackoff time.Duration
	// PerHostTimeout bounds each Probe call. Default 30s.
	PerHostTimeout time.Duration
}

// Run loops until ctx is cancelled.
func (w *TestWorker) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		job, err := w.Client.PollCredentialTest(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("poll credential test: %v", err)
			wait := w.PollBackoff
			if wait == 0 {
				wait = 5 * time.Second
			}
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

func (w *TestWorker) runOne(ctx context.Context, job *client.TestJobPayload) {
	authType, plaintext, err := w.Keystore.Get(ctx, job.SecretRef)
	if err != nil {
		_ = w.Client.SubmitCredentialTest(ctx, job.ID, nil, "keystore lookup failed: "+err.Error())
		return
	}
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()

	// Defensive: the auth_type stored alongside the secret must
	// match what the portal says the job needs. Mismatch => the
	// delivery pipeline desynced; surface loudly.
	if authType != job.AuthType {
		_ = w.Client.SubmitCredentialTest(ctx, job.ID, nil,
			"auth_type mismatch: job="+job.AuthType+" keystore="+authType)
		return
	}

	secret, err := ParseSecret(plaintext)
	if err != nil {
		_ = w.Client.SubmitCredentialTest(ctx, job.ID, nil, "parse secret: "+err.Error())
		return
	}
	defer secret.Zero()

	perHost := w.PerHostTimeout
	if perHost == 0 {
		perHost = 30 * time.Second
	}

	results := make([]client.SubmittedTestResult, 0, len(job.Hosts))
	for i := range job.Hosts {
		if ctx.Err() != nil {
			return
		}
		host := &job.Hosts[i]
		pctx, cancel := context.WithTimeout(ctx, perHost)
		pr := w.Prober.Probe(pctx, job.AuthType, secret, host.Address, host.Port)
		cancel()
		results = append(results, client.SubmittedTestResult{
			HostID:    host.ID,
			Success:   pr.Success,
			LatencyMs: pr.LatencyMs,
			Error:     pr.Error,
		})
	}
	if err := w.Client.SubmitCredentialTest(ctx, job.ID, results, ""); err != nil {
		log.Printf("submit credential test %s: %v", job.ID, err)
	}
}
