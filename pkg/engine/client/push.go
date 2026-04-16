package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// PushJobPayload is the engine-local wire shape for a pulled push job.
// Mirrors the portal's agent push job poll response.
type PushJobPayload struct {
	ID                  string           `json:"id"`
	CredentialSecretRef string           `json:"credential_secret_ref"`
	CredentialAuthType  string           `json:"credential_auth_type"`
	Hosts               []PushHostTarget `json:"hosts"`
}

// PushHostTarget is one host in a push job.
type PushHostTarget struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
}

// PushProgressUpdate is a per-host push status event posted to the
// /progress endpoint while the job runs.
type PushProgressUpdate struct {
	HostID      string `json:"host_id"`
	Status      string `json:"status"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Error       string `json:"error,omitempty"`
}

// PollPushJob long-polls the portal for a queued push job assigned to
// this engine. On HTTP 200 it decodes and returns the job. On 204 (no
// work) it returns (nil, nil).
func (c *Client) PollPushJob(ctx context.Context) (*PushJobPayload, error) {
	url := c.PortalURL + "/api/v1/engine/agent-push/poll"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.longPollClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll push job: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
		var p PushJobPayload
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&p); err != nil {
			return nil, fmt.Errorf("decode push job: %w", err)
		}
		return &p, nil
	case http.StatusNoContent:
		return nil, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return nil, fmt.Errorf("poll push job: unexpected status %d: %s", resp.StatusCode, string(b))
	}
}

// SubmitPushProgress posts a batch of per-host progress updates for a
// push job. Expected server response is 204.
func (c *Client) SubmitPushProgress(ctx context.Context, jobID string, updates []PushProgressUpdate) error {
	if updates == nil {
		updates = []PushProgressUpdate{}
	}
	return c.postJSONNoContent(ctx, "/api/v1/engine/agent-push/"+jobID+"/progress", updates)
}

// FinishPushJob posts the terminal status for a push job. Expected
// server response is 204.
func (c *Client) FinishPushJob(ctx context.Context, jobID, status, errMsg string) error {
	body := map[string]string{"status": status}
	if errMsg != "" {
		body["error"] = errMsg
	}
	return c.postJSONNoContent(ctx, "/api/v1/engine/agent-push/"+jobID+"/finish", body)
}

// registerAgentBody is the POST body for /engine/agent-push/agents/register.
type registerAgentBody struct {
	HostID          string `json:"host_id"`
	CertFingerprint string `json:"cert_fingerprint"`
	Version         string `json:"version,omitempty"`
}

// RegisterAgent notifies the portal that the agent was successfully
// installed on a host. Expected server response is 204.
func (c *Client) RegisterAgent(ctx context.Context, hostID, certFingerprint, version string) error {
	body := registerAgentBody{
		HostID:          hostID,
		CertFingerprint: certFingerprint,
		Version:         version,
	}
	return c.postJSONNoContent(ctx, "/api/v1/engine/agent-push/agents/register", body)
}
