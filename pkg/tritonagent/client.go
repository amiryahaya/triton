// Package tritonagent implements the triton-agent daemon's core logic:
// mTLS client, heartbeat loop, on-demand scan execution, and scan result
// submission to the Manage Server's mTLS gateway.
package tritonagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// AgentCommand describes a scan the agent should execute, received from
// the Manage Server's agent gateway via GET /agents/commands.
type AgentCommand struct {
	ScanProfile string   `json:"scan_profile"`
	JobID       string   `json:"job_id,omitempty"`
	Paths       []string `json:"paths,omitempty"`
}

// Client is the mTLS HTTP client that talks to the Manage Server's agent gateway.
type Client struct {
	ManageURL string
	HostID    string
	HTTP      *http.Client
}

// NewClient creates a Client configured with mTLS credentials. The certPath
// and keyPath are the agent's per-host cert/key; caPath is the Manage Server's
// CA cert used as trust root.
func NewClient(manageURL, certPath, keyPath, caPath, hostID string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load agent cert: %w", err)
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("load manage server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("no valid certificates in CA file %s", caPath)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}

	return &Client{
		ManageURL: manageURL,
		HostID:    hostID,
		HTTP: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   45 * time.Second,
		},
	}, nil
}

// Heartbeat calls POST /agents/phone-home on the Manage Server gateway.
func (c *Client) Heartbeat(ctx context.Context) error {
	return c.postJSON(ctx, "/agents/phone-home", map[string]string{"host_id": c.HostID})
}

// PollCommand calls GET /agents/commands. Returns nil if no command is
// pending (204 No Content).
func (c *Client) PollCommand(ctx context.Context) (*AgentCommand, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.ManageURL+"/agents/commands", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var cmd AgentCommand
		if err := json.NewDecoder(resp.Body).Decode(&cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("poll command: HTTP %d: %s", resp.StatusCode, b)
	}
}

// SubmitScan calls POST /agents/scans with an envelope containing the job ID
// and the scan result JSON.
func (c *Client) SubmitScan(ctx context.Context, jobID string, scanResult []byte) error {
	type envelope struct {
		JobID      string          `json:"job_id,omitempty"`
		ScanResult json.RawMessage `json:"scan_result"`
	}
	raw, err := json.Marshal(envelope{JobID: jobID, ScanResult: json.RawMessage(scanResult)})
	if err != nil {
		return fmt.Errorf("marshal scan envelope: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.ManageURL+"/agents/scans", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("submit scan: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, path string, body any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.ManageURL+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}
