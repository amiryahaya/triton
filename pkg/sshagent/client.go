package sshagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

const maxResponseBody = 1 << 20 // 1 MB

// CredPayload is the credential section of a job response from the Manage Server.
type CredPayload struct {
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	PrivateKey []byte `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Port       int    `json:"port,omitempty"`
}

// JobPayload is the job description returned by GET /api/v1/worker/jobs/{id}.
type JobPayload struct {
	ID          string      `json:"id"`
	ScanProfile string      `json:"scan_profile"`
	TargetHost  string      `json:"target_host"`
	Hostname    string      `json:"hostname"`
	Credentials CredPayload `json:"credentials"`
}

// Client is the HTTP client for the Manage Server worker API.
type Client struct {
	baseURL   string
	workerKey string
	http      *http.Client
}

// NewClient returns a Client for manageURL authenticated with workerKey.
func NewClient(manageURL, workerKey string) *Client {
	return &Client{
		baseURL:   manageURL,
		workerKey: workerKey,
		http:      &http.Client{Timeout: 60 * time.Second},
	}
}

// GetJob fetches the job description for jobID from the Manage Server.
func (c *Client) GetJob(ctx context.Context, jobID uuid.UUID) (*JobPayload, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/api/v1/worker/jobs/"+jobID.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Worker-Key", c.workerKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get job: HTTP %d", resp.StatusCode)
	}
	var p JobPayload
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&p); err != nil {
		return nil, fmt.Errorf("decode job: %w", err)
	}
	return &p, nil
}

// SubmitResult posts the completed ScanResult to the Manage Server.
func (c *Client) SubmitResult(ctx context.Context, jobID uuid.UUID, result *model.ScanResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/worker/jobs/"+jobID.String()+"/submit",
		bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("X-Worker-Key", c.workerKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer drainClose(resp)
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("submit result: HTTP %d", resp.StatusCode)
	}
	return nil
}

func drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
	_ = resp.Body.Close()
}
