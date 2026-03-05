package license

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

// ServerClient communicates with the Triton License Server.
type ServerClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewServerClient creates a new license server client.
func NewServerClient(baseURL string) *ServerClient {
	return &ServerClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ActivateResponse is the response from the activate endpoint.
type ActivateResponse struct {
	Token        string `json:"token"`
	ActivationID string `json:"activationID"`
	Tier         string `json:"tier"`
	Seats        int    `json:"seats"`
	SeatsUsed    int    `json:"seatsUsed"`
	ExpiresAt    string `json:"expiresAt"`
}

// ValidateResponse is the response from the validate endpoint.
type ValidateResponse struct {
	Valid     bool   `json:"valid"`
	Reason    string `json:"reason,omitempty"`
	Tier      string `json:"tier,omitempty"`
	Seats     int    `json:"seats,omitempty"`
	SeatsUsed int    `json:"seatsUsed,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// Activate registers this machine with the license server.
func (c *ServerClient) Activate(licenseID string) (*ActivateResponse, error) {
	hostname, _ := os.Hostname()
	body := map[string]string{
		"licenseID": licenseID,
		"machineID": MachineFingerprint(),
		"hostname":  hostname,
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/api/v1/license/activate", "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("connecting to license server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("all seats are occupied")
	}
	if resp.StatusCode == http.StatusForbidden {
		var errResp map[string]string
		_ = json.Unmarshal(respBody, &errResp)
		return nil, fmt.Errorf("activation denied: %s", errResp["error"])
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("license not found")
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var result ActivateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return &result, nil
}

// Deactivate unregisters this machine from the license server.
func (c *ServerClient) Deactivate(licenseID string) error {
	body := map[string]string{
		"licenseID": licenseID,
		"machineID": MachineFingerprint(),
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/api/v1/license/deactivate", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("connecting to license server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("deactivation failed (status %d): %s", resp.StatusCode, string(respBody))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// Validate checks token validity against the license server.
func (c *ServerClient) Validate(licenseID, token string) (*ValidateResponse, error) {
	body := map[string]string{
		"licenseID": licenseID,
		"machineID": MachineFingerprint(),
		"token":     token,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/api/v1/license/validate", "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("connecting to license server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("validation request failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result ValidateResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body) // drain for connection reuse
	return &result, nil
}

// Health checks if the license server is reachable.
func (c *ServerClient) Health() error {
	resp, err := c.httpClient.Get(c.baseURL + "/api/v1/health")
	if err != nil {
		return fmt.Errorf("connecting to license server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("license server unhealthy (status %d)", resp.StatusCode)
	}
	return nil
}
