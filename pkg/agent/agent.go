package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// Default retry tuning for scan submission. Exposed as fields on
// Client so tests can collapse the backoff to near-zero without
// waiting tens of seconds per case.
const (
	defaultRetryMaxAttempts    = 3
	defaultRetryInitialBackoff = 1 * time.Second
	// maxRetryAfter caps a pathological Retry-After value so a
	// misbehaving server can't force the agent to block for hours.
	maxRetryAfter = 5 * time.Minute
)

// Client submits scan results to a remote report server.
type Client struct {
	ServerURL    string
	LicenseToken string // Ed25519-signed licence token for tenant identification
	HTTPClient   *http.Client

	// RetryMaxAttempts is the total number of submit attempts,
	// including the first. Default is defaultRetryMaxAttempts (3).
	// Set to 1 to disable retries entirely.
	RetryMaxAttempts int
	// RetryInitialBackoff is the wait after the first failed attempt;
	// each subsequent wait quadruples (1s → 4s → 16s by default).
	// Tests override this to keep the retry path fast.
	RetryInitialBackoff time.Duration
}

// New creates a new agent Client. The API key parameter was removed in
// Phase 4 — agents now authenticate via license tokens (set the
// LicenseToken field directly) or submit unauthenticated to single-
// tenant deployments.
func New(serverURL string) *Client {
	return &Client{
		ServerURL: strings.TrimRight(serverURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
		RetryMaxAttempts:    defaultRetryMaxAttempts,
		RetryInitialBackoff: defaultRetryInitialBackoff,
	}
}

// SubmitResponse is the response from the server after submitting a scan.
type SubmitResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Submit posts a ScanResult to the server's /api/v1/scans endpoint
// with retries on transient failures. The store layer already upserts
// on scan.ID (ON CONFLICT DO UPDATE), so a retry that double-delivers
// produces no duplicate rows — idempotency is a property of the
// server-side contract, not something the client needs to signal.
//
// Retry policy: up to RetryMaxAttempts total attempts (default 3) for
// network errors, 5xx responses, and 429. Backoff is exponential
// starting from RetryInitialBackoff (default 1s) and quadrupling each
// step. 429 responses honor a capped Retry-After header instead of
// the backoff schedule. 4xx responses other than 429 are NOT retried
// because they are client-side contract errors that retries will not
// fix (and retries on 401/403 can trip server-side rate limiters).
//
// The context is propagated into every HTTP request so a SIGTERM
// during a large upload unblocks immediately instead of waiting for
// the HTTP client timeout.
func (c *Client) Submit(ctx context.Context, result *model.ScanResult) (*SubmitResponse, error) {
	body, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshaling scan result: %w", err)
	}

	maxAttempts := c.RetryMaxAttempts
	if maxAttempts < 1 {
		maxAttempts = defaultRetryMaxAttempts
	}
	backoff := c.RetryInitialBackoff
	if backoff <= 0 {
		backoff = defaultRetryInitialBackoff
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Fast-path: if the caller already canceled, stop before
		// even constructing the request. ctx.Err() returns the
		// cancellation reason (context.Canceled / DeadlineExceeded).
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		resp, retryAfter, retryable, err := c.submitOnce(ctx, body)
		if err == nil {
			return resp, nil
		}
		lastErr = err

		if !retryable || attempt == maxAttempts {
			break
		}

		wait := backoff
		if retryAfter > 0 {
			wait = retryAfter
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		// Exponential backoff: 1s, 4s, 16s. 429 Retry-After paths
		// don't double — they use whatever the server requested.
		if retryAfter == 0 {
			backoff *= 4
		}
	}

	if lastErr == nil {
		// Defensive: the loop above always assigns lastErr on
		// failure, but if maxAttempts is zero-ish and we fall
		// through without iterating, return a clear marker.
		return nil, fmt.Errorf("submit: no attempts made")
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

// submitOnce performs a single POST attempt and classifies the
// outcome. Returns:
//   - resp: parsed SubmitResponse on success (HTTP 201)
//   - retryAfter: server-requested wait from a 429 header, or 0
//   - retryable: true if the failure is worth retrying
//   - err: non-nil on any non-success outcome
func (c *Client) submitOnce(ctx context.Context, body []byte) (*SubmitResponse, time.Duration, bool, error) {
	url := c.ServerURL + "/api/v1/scans"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		// Request construction errors are never retryable — they
		// indicate a bug in the client, not a transient condition.
		return nil, 0, false, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.LicenseToken != "" {
		req.Header.Set("X-Triton-License-Token", c.LicenseToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		// Network-layer errors (DNS, connection refused, TLS
		// handshake, timeout) are all transient from the client's
		// perspective. Context cancellation is NOT retryable —
		// the caller asked us to stop.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, 0, false, err
		}
		return nil, 0, true, fmt.Errorf("sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		// A partial-read failure mid-response is transient.
		return nil, 0, true, fmt.Errorf("reading response: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusCreated:
		var sr SubmitResponse
		if err := json.Unmarshal(respBody, &sr); err != nil {
			return nil, 0, false, fmt.Errorf("decoding response: %w", err)
		}
		return &sr, 0, false, nil

	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, parseRetryAfter(resp.Header.Get("Retry-After")), true,
			fmt.Errorf("server returned 429: %s", truncateBody(respBody))

	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		return nil, 0, true,
			fmt.Errorf("server returned %d: %s", resp.StatusCode, truncateBody(respBody))

	default:
		// All other 4xx: contract errors (bad request, unauthorized,
		// forbidden, not found, payload too large). Retrying won't
		// fix them and can trip rate limiters on the server side.
		return nil, 0, false,
			fmt.Errorf("server returned %d: %s", resp.StatusCode, truncateBody(respBody))
	}
}

// parseRetryAfter understands the two forms of the Retry-After header:
// delta-seconds (an integer) and HTTP-date (RFC7231). Unknown or
// missing values return 0, which callers interpret as "use the
// default backoff". Values above maxRetryAfter are capped.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		d := time.Duration(secs) * time.Second
		if d > maxRetryAfter {
			return maxRetryAfter
		}
		return d
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d <= 0 {
			return 0
		}
		if d > maxRetryAfter {
			return maxRetryAfter
		}
		return d
	}
	return 0
}

// truncateBody limits error messages to a sensible length so a
// multi-megabyte HTML error page from an upstream proxy doesn't
// pollute the agent's log output.
func truncateBody(b []byte) string {
	const limit = 256
	if len(b) <= limit {
		return string(b)
	}
	return string(b[:limit]) + "...(truncated)"
}

// Healthcheck checks if the server is reachable.
func (c *Client) Healthcheck() error {
	return c.HealthcheckWithContext(context.Background())
}

// HealthcheckWithContext is the context-aware variant of Healthcheck.
// Prefer this in continuous-mode agents so a SIGTERM during the
// check doesn't hang waiting for the HTTP client timeout.
func (c *Client) HealthcheckWithContext(ctx context.Context) error {
	url := c.ServerURL + "/api/v1/health"
	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		return fmt.Errorf("creating health request: %w", err)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain body to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}
