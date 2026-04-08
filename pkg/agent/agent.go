package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// Client submits scan results to a remote report server.
type Client struct {
	ServerURL    string
	LicenseToken string // Ed25519-signed licence token for tenant identification
	HTTPClient   *http.Client
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
	}
}

// SubmitResponse is the response from the server after submitting a scan.
type SubmitResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Submit posts a ScanResult to the server's /api/v1/scans endpoint.
func (c *Client) Submit(result *model.ScanResult) (*SubmitResponse, error) {
	body, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshaling scan result: %w", err)
	}

	url := c.ServerURL + "/api/v1/scans"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.LicenseToken != "" {
		req.Header.Set("X-Triton-License-Token", c.LicenseToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var sr SubmitResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &sr, nil
}

// Healthcheck checks if the server is reachable.
func (c *Client) Healthcheck() error {
	url := c.ServerURL + "/api/v1/health"
	resp, err := c.HTTPClient.Get(url)
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
