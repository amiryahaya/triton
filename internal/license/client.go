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

	"github.com/amiryahaya/triton/pkg/licensestore"
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
//
// The v2 fields (Features, Limits, SoftBufferPct, ProductScope) are additive
// — pre-v2 licence servers omit them and the zero value is correct.
// Consumers such as the Manage Server inspect Features.Manage after
// activation to enforce product-scope client-side.
type ActivateResponse struct {
	Token        string `json:"token"`
	ActivationID string `json:"activationID"`
	Tier         string `json:"tier"`
	Seats        int    `json:"seats"`
	SeatsUsed    int    `json:"seatsUsed"`
	ExpiresAt    string `json:"expiresAt"`

	// v2 fields (additive; zero-value when the server is pre-v2).
	Features      licensestore.Features `json:"features"`
	Limits        licensestore.Limits   `json:"limits"`
	SoftBufferPct int                   `json:"soft_buffer_pct"`
	ProductScope  string                `json:"product_scope"`
}

// ValidateResponse is the response from the validate endpoint.
type ValidateResponse struct {
	Valid     bool   `json:"valid"`
	Reason    string `json:"reason,omitempty"`
	Tier      string `json:"tier,omitempty"`
	OrgID     string `json:"orgID,omitempty"`
	OrgName   string `json:"orgName,omitempty"`
	Seats     int    `json:"seats,omitempty"`
	SeatsUsed int    `json:"seatsUsed,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	// CacheTTL is the maximum age in seconds the caller may treat this
	// result as authoritative. Honored by the report server's Phase 2.1
	// validation cache. Server-owned policy — do not override on the client.
	CacheTTL int `json:"cacheTTL,omitempty"`

	// Schedule is the server-pushed cron expression override. Empty
	// means "no override — agent uses its local agent.yaml
	// schedule/interval." See
	// docs/plans/2026-04-19-portal-pushed-schedule-design.md.
	Schedule string `json:"schedule,omitempty"`

	// ScheduleJitterSeconds is the jitter bound in seconds. 0 disables.
	// Only meaningful when Schedule is non-empty.
	ScheduleJitterSeconds int `json:"scheduleJitterSeconds,omitempty"`
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

// ActivateForTenant activates a licence with a custom machineID.
// The Report Portal uses machineID = instanceID + "/" + tenantID so that
// each (deployment, tenant) pair occupies a unique activation seat.
func (c *ServerClient) ActivateForTenant(licenceKey, machineID string) (*ActivateResponse, error) {
	body := map[string]string{
		"licenseID": licenceKey,
		"machineID": machineID,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}
	resp, err := c.httpClient.Post(c.baseURL+"/api/v1/license/activate",
		"application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("connecting to licence server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusConflict:
		return nil, fmt.Errorf("no seats available")
	case http.StatusForbidden:
		var e map[string]string
		_ = json.Unmarshal(respBody, &e)
		return nil, fmt.Errorf("activation denied: %s", e["error"])
	case http.StatusNotFound:
		return nil, fmt.Errorf("licence not found")
	case http.StatusCreated:
		// ok
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, respBody)
	}
	var result ActivateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return &result, nil
}

// DeactivateForTenant releases a tenant activation seat using a custom machineID.
func (c *ServerClient) DeactivateForTenant(licenceKey, machineID string) error {
	body := map[string]string{"licenseID": licenceKey, "machineID": machineID}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}
	resp, err := c.httpClient.Post(c.baseURL+"/api/v1/license/deactivate",
		"application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("connecting to licence server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deactivation failed (status %d)", resp.StatusCode)
	}
	return nil
}

// ValidateForTenant validates a cached activation token with a custom machineID.
func (c *ServerClient) ValidateForTenant(licenceID, token, machineID string) (*ValidateResponse, error) {
	body := map[string]string{
		"licenseID": licenceID,
		"machineID": machineID,
		"token":     token,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}
	resp, err := c.httpClient.Post(c.baseURL+"/api/v1/license/validate",
		"application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("connecting to licence server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("validate failed (status %d): %s", resp.StatusCode, respBody)
	}
	var result ValidateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
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
