// Package tritonagent implements the triton-agent daemon's core logic:
// mTLS client, heartbeat loop, on-demand scan execution, and findings
// submission to the engine's agent gateway.
package tritonagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ErrUnauthorized is returned when the engine responds with HTTP 401,
// indicating the agent is not registered (e.g. after an engine restart
// that cleared its in-memory agent store). The agent loop should
// re-register when it receives this error.
var ErrUnauthorized = errors.New("unauthorized")

// ScanCommand describes a scan the agent should execute, received from
// the engine's agent gateway via GET /agent/scan.
type ScanCommand struct {
	ScanProfile string   `json:"scan_profile"`
	Paths       []string `json:"paths,omitempty"`
}

// Client is the mTLS HTTP client that talks to the engine's agent gateway.
type Client struct {
	EngineURL string
	HostID    string
	HTTP      *http.Client
}

// NewClient creates a Client configured with mTLS credentials. The certPath
// and keyPath are the agent's per-host cert/key; caPath is the engine's own
// cert used as trust root.
func NewClient(engineURL, certPath, keyPath, caPath, hostID string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load agent cert: %w", err)
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("load engine CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("no valid certificates in CA file %s", caPath)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		// engine-ca.crt is the engine's own self-signed cert which IS the
		// TLS server cert. A self-signed cert verifies against a pool
		// containing itself, so RootCAs validation passes without
		// InsecureSkipVerify.
		MinVersion: tls.VersionTLS12,
	}

	return &Client{
		EngineURL: engineURL,
		HostID:    hostID,
		HTTP: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   45 * time.Second,
		},
	}, nil
}

// Register calls POST /agent/register on the engine gateway.
func (c *Client) Register(ctx context.Context, version string) error {
	body := map[string]string{"host_id": c.HostID, "version": version}
	return c.postJSON(ctx, "/agent/register", body)
}

// Heartbeat calls POST /agent/heartbeat on the engine gateway.
func (c *Client) Heartbeat(ctx context.Context) error {
	return c.postJSON(ctx, "/agent/heartbeat", nil)
}

// PollScan calls GET /agent/scan. Returns nil if no scan is pending (204).
func (c *Client) PollScan(ctx context.Context) (*ScanCommand, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.EngineURL+"/agent/scan", http.NoBody)
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
		var cmd ScanCommand
		if err := json.NewDecoder(resp.Body).Decode(&cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("poll scan: HTTP %d: %s", resp.StatusCode, b)
	}
}

// SubmitFindings calls POST /agent/submit with the scan result JSON.
func (c *Client) SubmitFindings(ctx context.Context, scanResult []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", c.EngineURL+"/agent/submit", bytes.NewReader(scanResult))
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
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("submit findings: HTTP %d", resp.StatusCode)
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
	req, err := http.NewRequestWithContext(ctx, "POST", c.EngineURL+path, bodyReader)
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
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%s: %w", path, ErrUnauthorized)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}
