package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"
)

// CommandPoller is the client-side half of the Report Server's agent
// control channel. Callers construct one per agent lifetime, call Poll
// in a loop (or until ctx cancel), and PostResult after acting on each
// dispatched command.
type CommandPoller struct {
	BaseURL      string // Report Server URL, matching Client.BaseURL
	LicenseToken string // same token used for /submit
	MachineID    string // SHA3-256 hex from license.MachineFingerprint()
	Hostname     string // hint — helps admins identify agents in the fleet view
	HTTPClient   *http.Client

	// PollDeadline bounds a single poll's HTTP round-trip. Production
	// defaults to 35s so the server's 30s long-poll timeout always
	// arrives first. Tests can shrink it.
	PollDeadline time.Duration
}

// PollResponse is the decoded JSON from a 200 OK poll. On 204 the caller
// gets (nil, nil) and should reconnect immediately.
type PollResponse struct {
	State    PollState     `json:"state"`
	Commands []PollCommand `json:"commands,omitempty"`
}

// PollState carries the persistent agent-side state the server reports
// on every poll. Zero PausedUntil means "not paused" — same as an
// absent key.
type PollState struct {
	PausedUntil time.Time `json:"pausedUntil,omitempty"`
}

// PollCommand is a transient at-most-once imperative.
type PollCommand struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Args      json.RawMessage `json:"args,omitempty"`
	IssuedAt  time.Time       `json:"issuedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
}

func (c *CommandPoller) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	deadline := c.PollDeadline
	if deadline <= 0 {
		deadline = 35 * time.Second
	}
	return &http.Client{Timeout: deadline}
}

// Poll issues one long-poll GET and returns the decoded response, or nil
// when the server responds 204 (no state, no commands). Respects ctx
// cancellation. A non-2xx response returns an error.
func (c *CommandPoller) Poll(ctx context.Context) (*PollResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/api/v1/agent/commands/poll", nil)
	if err != nil {
		return nil, fmt.Errorf("build poll request: %w", err)
	}
	req.Header.Set("X-Triton-License-Token", c.LicenseToken)
	req.Header.Set("X-Triton-Machine-ID", c.MachineID)
	if c.Hostname != "" {
		req.Header.Set("X-Triton-Hostname", c.Hostname)
	}
	req.Header.Set("X-Triton-Agent-OS", runtime.GOOS)
	req.Header.Set("X-Triton-Agent-Arch", runtime.GOARCH)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("poll status %d: %s", resp.StatusCode, body)
	}
	var pr PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("decode poll: %w", err)
	}
	return &pr, nil
}

// PostResult tells the server how a dispatched command completed.
// status must be "executed" or "rejected"; meta is opaque JSON.
func (c *CommandPoller) PostResult(ctx context.Context, commandID, status string, meta json.RawMessage) error {
	body := map[string]any{"status": status}
	if len(meta) > 0 {
		body["meta"] = meta
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/agent/commands/"+commandID+"/result", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("build result request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Triton-License-Token", c.LicenseToken)
	req.Header.Set("X-Triton-Machine-ID", c.MachineID)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("result status %d: %s", resp.StatusCode, msg)
	}
	return nil
}
