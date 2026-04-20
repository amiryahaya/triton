package scanresults

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strings"
	"time"
)

// responseBodySnippetLimit bounds the number of bytes we slurp from a
// failed push response before truncating. 512 B is enough for the
// Report Server's { "error": "…" } bodies + the first sentence of a
// stack trace, without blowing up the dead-letter reason column on
// long HTML error pages.
const responseBodySnippetLimit = 512

// maxAttempts is the cut-off at which a failing row is dead-lettered.
// Mirrors the partial index `idx_manage_queue_due` (attempt_count < 10)
// so the 10th retry still lands in the work set; once attempt_count
// reaches 10 after the Defer we promote to dead-letter.
const maxAttempts = 10

// DrainConfig wires the push-to-Report-Server goroutine.
type DrainConfig struct {
	Store     Store
	ReportURL string
	Client    *http.Client

	// Batch is the per-tick ClaimDue limit. Default 100.
	Batch int

	// Interval is how long the drain sleeps between ticks. Default 5s.
	Interval time.Duration
}

// Drain is the background loop that walks the queue, pushes each row
// to the upstream Report Server, and records success/failure state.
//
// One drain per Manage instance. Safe against concurrent runs against
// the same queue (the claim+update cadence tolerates overlap) but
// there's no reason to run more than one in a single process.
type Drain struct {
	cfg DrainConfig
}

// NewDrain applies defaults and returns a ready Drain. Batch is
// clamped to (0, 500]; Interval defaults to 5s.
func NewDrain(cfg DrainConfig) *Drain {
	if cfg.Batch <= 0 {
		cfg.Batch = 100
	}
	if cfg.Batch > 500 {
		cfg.Batch = 500
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Drain{cfg: cfg}
}

// Run blocks until ctx is cancelled, invoking drainOnce on each tick.
// Errors inside drainOnce are logged but never fatal: a transient DB
// fault must not kill the goroutine.
func (d *Drain) Run(ctx context.Context) {
	t := time.NewTicker(d.cfg.Interval)
	defer t.Stop()

	// Fire an immediate tick on entry so startup isn't gated on the
	// first Interval. Respect ctx.Done between the initial tick and
	// the ticker loop for clean shutdown.
	if err := d.drainOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("manageserver/scanresults: drainOnce: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.drainOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("manageserver/scanresults: drainOnce: %v", err)
			}
		}
	}
}

// drainOnce claims up to Batch due rows and attempts to push each one.
// On success: Delete the row + RecordPushSuccess.
// On retryable failure (5xx / network): Defer with exponential backoff,
// or DeadLetter if we've exceeded maxAttempts. Either way
// RecordPushFailure is called.
// On non-retryable failure (4xx): DeadLetter immediately.
//
// ctx.Done is honoured between rows so shutdown isn't blocked by a
// large backlog — the loop returns ctx.Err() as soon as the parent
// signals cancel.
func (d *Drain) drainOnce(ctx context.Context) error {
	rows, err := d.cfg.Store.ClaimDue(ctx, d.cfg.Batch)
	if err != nil {
		return fmt.Errorf("claim due: %w", err)
	}
	for i := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		d.handleRow(ctx, rows[i])
	}
	return nil
}

// handleRow pushes a single row and dispatches to the right terminal
// state based on the HTTP response. Errors are swallowed (already
// logged inside the helpers) so the loop continues on the next row.
//
// For non-success responses, the body snippet returned by pushOne is
// folded into the reason string stashed on the queue row and the
// dead-letter row so operators have the Report Server's error message
// right there in the DB — no need to grep service logs.
func (d *Drain) handleRow(ctx context.Context, row QueueRow) {
	statusCode, bodySnippet, pushErr := d.pushOne(ctx, row)

	switch {
	case pushErr == nil && statusCode >= 200 && statusCode < 300:
		if err := d.cfg.Store.Delete(ctx, row.ID); err != nil {
			log.Printf("manageserver/scanresults: delete after success: %v", err)
			return
		}
		if err := d.cfg.Store.RecordPushSuccess(ctx, nil); err != nil {
			log.Printf("manageserver/scanresults: record success: %v", err)
		}

	case pushErr == nil && statusCode >= 400 && statusCode < 500 &&
		statusCode != http.StatusUnauthorized &&
		statusCode != http.StatusForbidden &&
		statusCode != http.StatusTooManyRequests:
		// 4xx (except 401/403/429) = non-retryable. Straight to
		// dead-letter. 401/403 might be transient (token rotation
		// in-flight) and 429 is a backoff hint — all three fall
		// through to the retryable branch.
		reason := formatHTTPFailure(statusCode, bodySnippet)
		if err := d.cfg.Store.DeadLetter(ctx, row.ID, reason); err != nil {
			log.Printf("manageserver/scanresults: dead-letter after 4xx: %v", err)
		}
		if err := d.cfg.Store.RecordPushFailure(ctx, reason); err != nil {
			log.Printf("manageserver/scanresults: record failure (4xx): %v", err)
		}

	default:
		// Retryable: 5xx, 401/403/429, or network/transport error.
		var reason string
		switch {
		case pushErr != nil:
			reason = pushErr.Error()
		default:
			reason = formatHTTPFailure(statusCode, bodySnippet)
		}
		d.retryOrDeadLetter(ctx, row, reason)
	}
}

// formatHTTPFailure combines an HTTP status code with a (possibly
// empty) response body snippet into a single reason string. Used for
// both last_error column writes and dead_letter_reason so operators
// see the upstream error message directly.
func formatHTTPFailure(statusCode int, bodySnippet []byte) string {
	trimmed := strings.TrimSpace(string(bodySnippet))
	if trimmed == "" {
		return fmt.Sprintf("HTTP %d", statusCode)
	}
	return fmt.Sprintf("HTTP %d: %s", statusCode, trimmed)
}

// retryOrDeadLetter runs after a retryable push failure. If the next
// attempt would push attempt_count to ≥ maxAttempts, the row is
// dead-lettered instead of deferred. Either branch updates license
// state so /push-status surfaces sustained outages.
func (d *Drain) retryOrDeadLetter(ctx context.Context, row QueueRow, reason string) {
	if err := d.cfg.Store.RecordPushFailure(ctx, reason); err != nil {
		log.Printf("manageserver/scanresults: record failure: %v", err)
	}

	// After this failure attempt_count will become row.AttemptCount+1.
	// The partial index / ClaimDue predicate is `< maxAttempts`, so
	// once the post-increment value equals maxAttempts we promote to
	// dead-letter rather than leave an unreachable row sitting in the
	// queue forever.
	if row.AttemptCount+1 >= maxAttempts {
		if err := d.cfg.Store.DeadLetter(ctx, row.ID, "max retries exceeded: "+reason); err != nil {
			log.Printf("manageserver/scanresults: dead-letter after max retries: %v", err)
		}
		return
	}

	backoff := backoffFor(row.AttemptCount)
	if err := d.cfg.Store.Defer(ctx, row.ID, time.Now().Add(backoff), reason); err != nil {
		log.Printf("manageserver/scanresults: defer row: %v", err)
	}
}

// backoffFor computes the exponential backoff for a given attempt
// count (0-indexed: attempt 0 has failed, scheduling the retry for
// attempt 1). Doubles from 10 s; capped at 30 min to avoid overflow
// and to make sure the Postgres TIMESTAMPTZ stays reasonable.
//
// Pattern: 10, 20, 40, 80, 160, 320, 640, 1280, 1800 (cap), ...
func backoffFor(prevAttempts int) time.Duration {
	if prevAttempts < 0 {
		prevAttempts = 0
	}
	base := 10 * time.Second
	// 1 << 20 = ~1M; plenty of headroom before the math blows up,
	// but we still cap explicitly below.
	shift := prevAttempts
	if shift > 20 {
		shift = 20
	}
	mul := time.Duration(math.Pow(2, float64(shift)))
	d := base * mul
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

// pushOne fires a single HTTP POST to ReportURL + the /api/v1/scans
// path. Returns (statusCode, bodySnippet, err) where:
//   - err is the transport error (non-nil ⇒ statusCode is zero, snippet nil)
//   - bodySnippet is the first responseBodySnippetLimit bytes of the
//     response body, used to surface the Report Server's error message
//     in dead-letter reason strings. Empty on 2xx / successful drain.
//
// Body is the opaque payload_json from the queue row.
func (d *Drain) pushOne(ctx context.Context, row QueueRow) (statusCode int, bodySnippet []byte, err error) {
	url := d.cfg.ReportURL + "/api/v1/scans"
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewReader(row.PayloadJSON))
	if reqErr != nil {
		return 0, nil, fmt.Errorf("build request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, doErr := d.cfg.Client.Do(req)
	if doErr != nil {
		return 0, nil, doErr
	}
	defer func() { _ = resp.Body.Close() }()

	// Slurp up to responseBodySnippetLimit bytes for the reason string,
	// then drain the rest so connection-reuse works. On 2xx we don't
	// need the snippet but reading is cheap and uniform.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, responseBodySnippetLimit))
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, snippet, nil
}

// BuildHTTPClient assembles an *http.Client with the TLS bundle in
// creds: client cert for mTLS, CA cert for server verification. The
// client has a 30s overall timeout; individual requests get their own
// ctx from Drain.
func BuildHTTPClient(creds PushCreds) (*http.Client, error) {
	clientCert, err := tls.X509KeyPair([]byte(creds.ClientCertPEM), []byte(creds.ClientKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse client cert/key: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(creds.CACertPEM)) {
		return nil, errors.New("ca_cert_pem: no parseable certificates")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
