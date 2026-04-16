package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ScanJobPayload is the engine-local wire shape for a pulled scan job.
// Mirrors the portal's scan job poll response.
type ScanJobPayload struct {
	ID                  string           `json:"id"`
	ScanProfile         string           `json:"scan_profile"`
	CredentialSecretRef *string          `json:"credential_secret_ref,omitempty"`
	CredentialAuthType  string           `json:"credential_auth_type,omitempty"`
	Hosts               []ScanHostTarget `json:"hosts"`
}

// ScanHostTarget is one host in a scan job.
type ScanHostTarget struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
}

// ScanProgressUpdate is a per-host progress/terminal update posted to the
// /progress endpoint while the job runs.
type ScanProgressUpdate struct {
	HostID        string `json:"host_id"`
	Status        string `json:"status"`
	FindingsCount int    `json:"findings_count"`
	Error         string `json:"error,omitempty"`
}

// PollScanJob long-polls the portal for a queued scan job assigned to this
// engine. On HTTP 200 it decodes and returns the job. On 204 (no work) it
// returns (nil, nil). Any other status — or transport error — returns a
// non-nil error.
func (c *Client) PollScanJob(ctx context.Context) (*ScanJobPayload, error) {
	url := c.PortalURL + "/api/v1/engine/scans/poll"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.longPollClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll scan job: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
		var p ScanJobPayload
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&p); err != nil {
			return nil, fmt.Errorf("decode scan job: %w", err)
		}
		return &p, nil
	case http.StatusNoContent:
		return nil, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return nil, fmt.Errorf("poll scan job: unexpected status %d: %s", resp.StatusCode, string(b))
	}
}

// SubmitScanProgress posts a batch of per-host progress updates for a scan
// job. Expected server response is 204.
func (c *Client) SubmitScanProgress(ctx context.Context, jobID string, updates []ScanProgressUpdate) error {
	if updates == nil {
		updates = []ScanProgressUpdate{}
	}
	return c.postJSONNoContent(ctx, "/api/v1/engine/scans/"+jobID+"/progress", updates)
}

// submitScanFindingsBody is the POST body for /engine/scans/{id}/submit.
// scan_result is json.RawMessage so we can forward the scanner's *model.ScanResult
// verbatim without a re-encode round trip.
type submitScanFindingsBody struct {
	HostID        string          `json:"host_id"`
	FindingsCount int             `json:"findings_count"`
	ScanResult    json.RawMessage `json:"scan_result"`
}

// uploadTimeout bounds a SubmitScanFindings round-trip. Comprehensive
// scan payloads can reach tens of megabytes; the default 30s
// requestTimeout on c.HTTP is not enough for a slow WAN link.
const uploadTimeout = 5 * time.Minute

// uploadClient reuses the mTLS-configured transport from c.HTTP but
// raises the per-request timeout to uploadTimeout so large scan-result
// uploads don't get aborted mid-stream.
func (c *Client) uploadClient() *http.Client {
	return &http.Client{
		Timeout:   uploadTimeout,
		Transport: c.HTTP.Transport,
	}
}

// SubmitScanFindings posts the full scan result for one host. Expected server
// response is 204. scanResult should be the marshaled bytes of a
// *model.ScanResult; the portal persists it verbatim.
func (c *Client) SubmitScanFindings(ctx context.Context, jobID, hostID string, scanResult []byte, findings int) error {
	body := submitScanFindingsBody{
		HostID:        hostID,
		FindingsCount: findings,
		ScanResult:    json.RawMessage(scanResult),
	}
	return c.postJSONNoContentWithClient(ctx, c.uploadClient(), "/api/v1/engine/scans/"+jobID+"/submit", body)
}

// FinishScanJob posts the terminal status for a scan job. status is expected
// to be "completed" or "failed"; errMsg is optional context on failure.
// Expected server response is 204.
func (c *Client) FinishScanJob(ctx context.Context, jobID, status, errMsg string) error {
	body := map[string]string{"status": status}
	if errMsg != "" {
		body["error"] = errMsg
	}
	return c.postJSONNoContent(ctx, "/api/v1/engine/scans/"+jobID+"/finish", body)
}

// postJSONNoContent marshals body to JSON, POSTs it to c.PortalURL+path,
// expects HTTP 204, and returns any deviation as an error. Centralizes the
// request boilerplate shared by the scan-job helpers.
func (c *Client) postJSONNoContent(ctx context.Context, path string, body any) error {
	return c.postJSONNoContentWithClient(ctx, c.HTTP, path, body)
}

// postJSONNoContentWithClient is postJSONNoContent with caller-supplied
// *http.Client so SubmitScanFindings can use a longer upload timeout
// without affecting the smaller Progress / Finish payloads.
func (c *Client) postJSONNoContentWithClient(ctx context.Context, hc *http.Client, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal %s body: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.PortalURL+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return fmt.Errorf("post %s: unexpected status %d: %s", path, resp.StatusCode, string(b))
	}
	return nil
}
