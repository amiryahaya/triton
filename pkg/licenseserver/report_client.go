package licenseserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// ReportAPIClient pushes provisioning calls from the license server to the
// report server. It is the client-side counterpart to the report server's
// POST /api/v1/admin/orgs endpoint (Phase 1.5b).
//
// Usage: create once at server startup via NewReportAPIClient(url, serviceKey)
// and reuse for all provisioning calls. Nil is a valid zero-value meaning
// "no report server configured" — in that case, license server handlers
// skip provisioning entirely.
type ReportAPIClient struct {
	baseURL    string
	serviceKey string
	httpClient *http.Client
}

// NewReportAPIClient constructs a client. If baseURL or serviceKey is empty,
// returns nil — callers should check and skip provisioning if so.
func NewReportAPIClient(baseURL, serviceKey string) *ReportAPIClient {
	if baseURL == "" || serviceKey == "" {
		return nil
	}
	return &ReportAPIClient{
		baseURL:    baseURL,
		serviceKey: serviceKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// ProvisionOrgRequest mirrors the report server's provisionOrgRequest
// (pkg/server/handlers_admin.go). Kept as a separate type on the client
// side to avoid coupling the two packages.
type ProvisionOrgRequest struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	AdminEmail        string `json:"admin_email"`
	AdminName         string `json:"admin_name"`
	AdminTempPassword string `json:"admin_temp_password"`
}

// ProvisionOrgResponse captures the fields the license server cares
// about from the report server's response. Extra fields are ignored.
type ProvisionOrgResponse struct {
	Org struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"org"`
	AdminUserID   string `json:"admin_user_id"`
	AlreadyExists bool   `json:"already_exists"`
}

// ProvisionOrg calls the report server's provisioning endpoint.
//
// Idempotency: if the org already exists on the report server with the
// same ID+name, the call succeeds with AlreadyExists=true (no new user
// is created). This makes retry safe.
//
// Errors are returned for: network failure, non-2xx response, or a
// response body that can't be parsed. Callers should decide whether
// to surface the failure to the admin (hard dependency) or log and
// continue (best effort) — this function does not decide.
func (c *ReportAPIClient) ProvisionOrg(ctx context.Context, req ProvisionOrgRequest) (*ProvisionOrgResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshalling provision request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/admin/orgs", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building provision request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Triton-Service-Key", c.serviceKey)
	// Propagate the incoming request ID across the cross-server hop so
	// logs/traces can correlate the license-server request with the
	// report-server request it triggered. Chi's RequestID middleware
	// populates the context; this header is non-sensitive and safe to
	// forward (it's already exposed on the original request's response).
	if reqID := middleware.GetReqID(ctx); reqID != "" {
		httpReq.Header.Set("X-Request-ID", reqID)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Wrap both the sentinel (so callers can errors.Is-check for
		// "unreachable" specifically) and the underlying error (so
		// logs show the actual network failure). Multi-%w is Go 1.20+.
		return nil, fmt.Errorf("%w: %w", ErrReportServerUnreachable, err)
	}
	defer func() {
		// Drain the body so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Cap response body to 64 KB — provisioning responses are small, and
	// an unbounded Read would be a DoS vector if the report server is
	// compromised.
	limited := io.LimitReader(resp.Body, 64<<10)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading provision response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provision failed: status %d: %s", resp.StatusCode, string(respBody))
	}

	var out ProvisionOrgResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parsing provision response: %w", err)
	}
	out.AlreadyExists = resp.StatusCode == http.StatusOK // 200 means idempotent retry
	return &out, nil
}

// (GenerateTempPassword moved to internal/auth in Phase 5 Sprint 2 so
// the license server and report server share one canonical helper.
// Callers in this package now use auth.GenerateTempPassword(24).)

// Error sentinel callers can check for when they want to distinguish
// "report server unreachable" from other failures.
var ErrReportServerUnreachable = errors.New("report server unreachable")
