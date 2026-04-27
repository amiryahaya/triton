package scanrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// ErrJobGone is returned by Claim when the job is not found or already claimed.
// The caller should exit 0 — both are clean conditions.
var ErrJobGone = errors.New("scanrunner: job not found or already claimed")

// ClaimResp is the JSON body returned by POST /api/v1/worker/jobs/{id}/claim.
type ClaimResp struct {
	JobID          uuid.UUID  `json:"job_id"`
	HostID         uuid.UUID  `json:"host_id"`
	Profile        string     `json:"profile"`
	PortOverride   []uint16   `json:"port_override,omitempty"`
	CredentialsRef *uuid.UUID `json:"credentials_ref,omitempty"`
}

// HostInfo holds the fields RunOne needs from GET /api/v1/worker/hosts/{id}.
type HostInfo struct {
	ID       uuid.UUID `json:"id"`
	Hostname string    `json:"hostname"`
	IP       string    `json:"ip"`
}

// ManageClient makes authenticated requests to the manage server Worker API.
type ManageClient struct {
	base string
	key  string
	http *http.Client
}

// NewManageClient constructs a ManageClient with a 30 s timeout.
func NewManageClient(baseURL, workerKey string) *ManageClient {
	return &ManageClient{
		base: baseURL,
		key:  workerKey,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *ManageClient) req(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Worker-Key", c.key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// Claim claims the job. Returns ErrJobGone on 404 or 409.
func (c *ManageClient) Claim(ctx context.Context, jobID uuid.UUID) (ClaimResp, error) {
	resp, err := c.req(ctx, http.MethodPost, fmt.Sprintf("/api/v1/worker/jobs/%s/claim", jobID), nil)
	if err != nil {
		return ClaimResp{}, err
	}
	defer resp.Body.Close() //nolint:errcheck // body close error is not actionable
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusConflict {
		return ClaimResp{}, ErrJobGone
	}
	if resp.StatusCode != http.StatusOK {
		return ClaimResp{}, fmt.Errorf("claim: status %d", resp.StatusCode)
	}
	var cr ClaimResp
	err = json.NewDecoder(resp.Body).Decode(&cr)
	return cr, err
}

// Heartbeat renews running_heartbeat_at.
func (c *ManageClient) Heartbeat(ctx context.Context, jobID uuid.UUID) error {
	resp, err := c.req(ctx, http.MethodPatch, fmt.Sprintf("/api/v1/worker/jobs/%s/heartbeat", jobID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // body close error is not actionable
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("heartbeat: status %d", resp.StatusCode)
	}
	return nil
}

// Complete marks the job completed.
func (c *ManageClient) Complete(ctx context.Context, jobID uuid.UUID) error {
	resp, err := c.req(ctx, http.MethodPost, fmt.Sprintf("/api/v1/worker/jobs/%s/complete", jobID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // body close error is not actionable
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("complete: status %d", resp.StatusCode)
	}
	return nil
}

// Fail marks the job failed with an error message.
func (c *ManageClient) Fail(ctx context.Context, jobID uuid.UUID, errMsg string) error {
	resp, err := c.req(ctx, http.MethodPost, fmt.Sprintf("/api/v1/worker/jobs/%s/fail", jobID),
		map[string]string{"error": errMsg})
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // body close error is not actionable
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("fail: status %d", resp.StatusCode)
	}
	return nil
}

// GetHost fetches host info by ID (uses X-Worker-Key for auth).
func (c *ManageClient) GetHost(ctx context.Context, hostID uuid.UUID) (HostInfo, error) {
	resp, err := c.req(ctx, http.MethodGet, fmt.Sprintf("/api/v1/worker/hosts/%s", hostID), nil)
	if err != nil {
		return HostInfo{}, err
	}
	defer resp.Body.Close() //nolint:errcheck // body close error is not actionable
	if resp.StatusCode != http.StatusOK {
		return HostInfo{}, fmt.Errorf("get host: status %d", resp.StatusCode)
	}
	var h HostInfo
	err = json.NewDecoder(resp.Body).Decode(&h)
	return h, err
}

// SubmitResult posts a ScanResult to POST /api/v1/worker/jobs/{id}/submit on
// the Manage Server. The endpoint marks the job complete and enqueues the
// result for drain to the Report Server.
func (c *ManageClient) SubmitResult(ctx context.Context, jobID uuid.UUID, result *model.ScanResult) error {
	resp, err := c.req(ctx, http.MethodPost, fmt.Sprintf("/api/v1/worker/jobs/%s/submit", jobID), result)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // body close error is not actionable
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("submit result: status %d", resp.StatusCode)
	}
	return nil
}
