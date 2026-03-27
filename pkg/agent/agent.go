package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// Client submits scan results to a remote Triton server.
type Client struct {
	ServerURL    string
	APIKey       string
	LicenseToken string // Ed25519-signed licence token for tenant identification
	HTTPClient   *http.Client

	// Keycloak client credentials (optional).
	KeycloakTokenURL     string // e.g., http://keycloak:8080/realms/platform/protocol/openid-connect/token
	KeycloakClientID     string
	KeycloakClientSecret string

	// cached OIDC token
	oidcToken       string
	oidcTokenExpiry time.Time
	mu              sync.Mutex
}

// New creates a new agent Client.
func New(serverURL, apiKey string) *Client {
	return &Client{
		ServerURL: strings.TrimRight(serverURL, "/"),
		APIKey:    apiKey,
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

// ensureOIDCToken obtains or refreshes a client-credentials OIDC access token.
func (c *Client) ensureOIDCToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.oidcToken != "" && time.Now().Before(c.oidcTokenExpiry.Add(-30*time.Second)) {
		return c.oidcToken, nil
	}

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.KeycloakClientID},
		"client_secret": {c.KeycloakClientSecret},
	}

	resp, err := c.HTTPClient.PostForm(c.KeycloakTokenURL, data)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}

	c.oidcToken = tokenResp.AccessToken
	expiry := tokenResp.ExpiresIn
	if expiry <= 0 {
		expiry = 300 // default 5 min if not specified
	}
	c.oidcTokenExpiry = time.Now().Add(time.Duration(expiry) * time.Second)
	return c.oidcToken, nil
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
	if c.KeycloakTokenURL != "" {
		token, err := c.ensureOIDCToken()
		if err != nil {
			return nil, fmt.Errorf("obtaining OIDC token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	} else if c.APIKey != "" {
		req.Header.Set("X-Triton-API-Key", c.APIKey)
	}
	// License token always set for tenant identification.
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
