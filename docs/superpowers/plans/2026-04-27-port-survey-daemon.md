# Port Survey Daemon Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evolve port survey from in-process execution (PR #102) into a standalone `triton-portscan` binary spawned one-per-host by the manage server, with a pluggable Scanner interface and generic job-type dispatcher.

**Architecture:** `pkg/scanrunner` is the shared foundation (Scanner interface, RunOne lifecycle, HTTP clients). `cmd/triton-portscan` is the one-shot binary: claim job → resolve host → scan → submit to report server → exit. `pkg/manageserver/scanjobs/dispatcher.go` polls queued port_survey jobs, samples host load via gopsutil, and spawns subprocesses. Four new Worker API endpoints (`/v1/worker/…`) let the binary claim and report job state.

**Tech Stack:** Go 1.25, chi/v5, pgx/v5, fingerprintx, gopsutil/v3

---

## File Map

**Created:**
- `pkg/scanrunner/scanner.go` — Scanner interface + Target/Finding/TLSCertInfo/Credentials
- `pkg/scanrunner/mapper.go` — `ToScanResult(hostname, ip, profile string, findings []Finding) *model.ScanResult`
- `pkg/scanrunner/mapper_test.go`
- `pkg/scanrunner/client.go` — ManageClient + ReportClient HTTP wrappers
- `pkg/scanrunner/client_test.go`
- `pkg/scanrunner/runner.go` — `RunOne(ctx, jobID, manage, report, scanner) error`
- `pkg/scanrunner/runner_test.go`
- `pkg/manageserver/scanjobs/dispatcher.go` — generic job-type → binary dispatcher
- `pkg/manageserver/scanjobs/dispatcher_test.go`
- `pkg/manageserver/scanjobs/worker_handlers.go` — claim/heartbeat/complete/fail + WorkerKeyAuth
- `pkg/manageserver/scanjobs/worker_handlers_test.go`
- `cmd/triton-portscan/main.go` — binary entry point

**Modified:**
- `pkg/manageserver/portscan/scanner.go` → renamed `fingerprintx.go`; `Scanner` → `FingerprintxScanner`; implements `scanrunner.Scanner`
- `pkg/manageserver/portscan/tls.go` — return type `*scanrunner.TLSCertInfo`
- `pkg/manageserver/portscan/portlists.go` — unchanged
- `pkg/manageserver/scanjobs/store.go` — add `ErrAlreadyClaimed`, `ListQueued`, `ClaimByID`
- `pkg/manageserver/scanjobs/postgres.go` — implement `ListQueued`, `ClaimByID`; filter `ClaimNext` to `job_type='filesystem'`
- `pkg/manageserver/scanjobs/types.go` — add `PortOverride []uint16` to `Job` and `PortSurveyEnqueueReq`
- `pkg/manageserver/scanjobs/routes.go` — add `MountWorkerRoutes`
- `pkg/manageserver/scanjobs/orchestrator.go` — remove `PortScanFunc` field and its dispatch branch
- `pkg/manageserver/server.go` — add `WorkerKey` to config, remove `PortScanFunc` wiring, wire Dispatcher
- `pkg/managestore/migrations.go` — add v15: `port_override INTEGER[]` on `manage_scan_jobs`
- `Makefile` — add `triton-portscan` build target
- `pkg/manageserver/ui/src/components/PortSurveyEnqueueForm.vue` — port override field + comprehensive warning

**Deleted:**
- `pkg/manageserver/portscan/scan_func.go`
- `pkg/manageserver/portscan/result_mapper.go`
- `pkg/manageserver/portscan/result_mapper_test.go` (empty — tests live in `pkg/scanrunner/`)

---

## Task 1: `pkg/scanrunner/scanner.go` — Scanner interface + shared types

**Files:**
- Create: `pkg/scanrunner/scanner.go`

- [ ] **Step 1: Create the file**

```go
// Package scanrunner is the shared foundation for all external scan binaries
// (triton-portscan, future triton-sshscan). It provides the Scanner pluggable
// interface, RunOne lifecycle, and HTTP client wrappers.
package scanrunner

import (
	"context"
	"time"
)

// Scanner is the pluggable scan engine contract.
// FingerprintxScanner implements this; future: NmapScanner, SSHAgentlessScanner.
type Scanner interface {
	Scan(ctx context.Context, target Target, onFinding func(Finding)) error
}

// Target describes a single host to scan.
type Target struct {
	IP           string
	Profile      string     // "quick" | "standard" | "comprehensive"
	RateLimit    int        // max new TCP connections/sec; 0 = profile default
	PortOverride []uint16   // non-nil overrides profile port list; nil = profile default
	Credentials  *Credentials // nil for port survey; non-nil for SSH agentless
}

// Credentials holds optional SSH/auth material for agentless scan types.
type Credentials struct {
	Username   string
	Password   string
	PrivateKey []byte
	Port       int // default 22 for SSH
}

// Finding is one detected service on a host port.
type Finding struct {
	Port    uint16
	Service string      // "ssh", "https", "smtp" etc.
	Banner  string      // version string / banner
	TLSCert *TLSCertInfo // non-nil when TLS certificate was extracted
}

// TLSCertInfo holds crypto-relevant fields from a TLS certificate.
type TLSCertInfo struct {
	Subject      string
	Issuer       string
	Algorithm    string // "RSA", "ECDSA"
	KeyBits      int
	NotBefore    time.Time
	NotAfter     time.Time
	SANs         []string
	SerialNumber string
	IsSelfSigned bool
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./pkg/scanrunner/...
```
Expected: no errors (package has no tests yet; that's fine).

- [ ] **Step 3: Commit**

```bash
git add pkg/scanrunner/scanner.go
git commit -m "feat(scanrunner): Scanner interface + shared types"
```

---

## Task 2: `pkg/scanrunner/mapper.go` — Finding[] → model.ScanResult

**Files:**
- Create: `pkg/scanrunner/mapper.go`
- Create: `pkg/scanrunner/mapper_test.go`

- [ ] **Step 1: Write the failing test**

```go
// pkg/scanrunner/mapper_test.go
package scanrunner_test

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/scanrunner"
)

func TestToScanResult_TLSCertFinding(t *testing.T) {
	nb := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	findings := []scanrunner.Finding{
		{
			Port:    443,
			Service: "https",
			Banner:  "nginx/1.25",
			TLSCert: &scanrunner.TLSCertInfo{
				Subject:      "example.com",
				Issuer:       "Let's Encrypt",
				Algorithm:    "RSA",
				KeyBits:      2048,
				NotBefore:    nb,
				NotAfter:     na,
				SANs:         []string{"example.com", "www.example.com"},
				SerialNumber: "12345",
				IsSelfSigned: false,
			},
		},
	}

	result := scanrunner.ToScanResult("example.com", "192.168.1.1", "standard", findings)

	if result.ID == "" {
		t.Error("result ID should not be empty")
	}
	if result.Metadata.Hostname != "example.com" {
		t.Errorf("hostname: got %q, want %q", result.Metadata.Hostname, "example.com")
	}
	if result.Metadata.ScanProfile != "standard" {
		t.Errorf("profile: got %q, want %q", result.Metadata.ScanProfile, "standard")
	}
	// Expect 2 findings: TLS cert + service
	if len(result.Findings) != 2 {
		t.Fatalf("findings count: got %d, want 2", len(result.Findings))
	}
	// TLS finding must have correct endpoint
	tlsFinding := result.Findings[0]
	if tlsFinding.Source.Endpoint != "tcp://192.168.1.1:443" {
		t.Errorf("endpoint: got %q, want %q", tlsFinding.Source.Endpoint, "tcp://192.168.1.1:443")
	}
	if tlsFinding.Source.DetectionMethod != "tls-handshake" {
		t.Errorf("detection method: got %q", tlsFinding.Source.DetectionMethod)
	}
}

func TestToScanResult_SSHFinding(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 22, Service: "ssh", Banner: "OpenSSH_9.3"},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "quick", findings)
	if len(result.Findings) != 1 {
		t.Fatalf("findings count: got %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.CryptoAsset == nil {
		t.Fatal("CryptoAsset should not be nil for SSH finding")
	}
	if f.CryptoAsset.Algorithm != "SSH" {
		t.Errorf("algorithm: got %q, want SSH", f.CryptoAsset.Algorithm)
	}
	if f.CryptoAsset.Subject != "OpenSSH_9.3" {
		t.Errorf("subject: got %q, want OpenSSH_9.3", f.CryptoAsset.Subject)
	}
}

func TestToScanResult_NoFindings(t *testing.T) {
	result := scanrunner.ToScanResult("host", "10.0.0.1", "quick", nil)
	if result == nil {
		t.Fatal("result should not be nil even with no findings")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestToScanResult_HTTPWithoutBannerSkipped(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 80, Service: "http", Banner: ""}, // no banner → skip service finding
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for http with empty banner, got %d", len(result.Findings))
	}
}

func TestClassifyKeySize_RSA(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 443, TLSCert: &scanrunner.TLSCertInfo{Algorithm: "RSA", KeyBits: 1024}},
	}
	result := scanrunner.ToScanResult("h", "1.2.3.4", "quick", findings)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].CryptoAsset.PQCStatus != "DEPRECATED" {
		t.Errorf("RSA-1024 should be DEPRECATED, got %s", result.Findings[0].CryptoAsset.PQCStatus)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./pkg/scanrunner/... -run TestToScanResult -v
```
Expected: FAIL — `ToScanResult` undefined.

- [ ] **Step 3: Implement mapper.go**

```go
// pkg/scanrunner/mapper.go
package scanrunner

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// ToScanResult converts port scan findings into a model.ScanResult ready for
// report server submission. hostname is the display label; ip builds endpoints.
func ToScanResult(hostname, ip, profile string, findings []Finding) *model.ScanResult {
	result := &model.ScanResult{
		ID: uuid.NewString(),
		Metadata: model.ScanMetadata{
			Timestamp:   time.Now(),
			Hostname:    hostname,
			ScanProfile: profile,
		},
		Findings: make([]model.Finding, 0, len(findings)),
	}

	for i := range findings {
		f := &findings[i]
		endpoint := fmt.Sprintf("tcp://%s:%d", ip, f.Port)

		if f.TLSCert != nil {
			nb := f.TLSCert.NotBefore
			na := f.TLSCert.NotAfter
			asset := &model.CryptoAsset{
				ID:        uuid.NewString(),
				Algorithm: f.TLSCert.Algorithm,
				KeySize:   f.TLSCert.KeyBits,
				Subject:   f.TLSCert.Subject,
				Issuer:    f.TLSCert.Issuer,
				NotBefore: &nb,
				NotAfter:  &na,
				SANs:      f.TLSCert.SANs,
				PQCStatus: classifyKeySize(f.TLSCert.Algorithm, f.TLSCert.KeyBits),
				Function:  "authentication",
				State:     "IN_TRANSIT",
			}
			result.Findings = append(result.Findings, model.Finding{
				ID:       uuid.NewString(),
				Category: int(model.CategoryActiveNetwork),
				Source: model.FindingSource{
					Type:            "network",
					Endpoint:        endpoint,
					DetectionMethod: "tls-handshake",
				},
				CryptoAsset: asset,
				Confidence:  0.95,
				Module:      "port_survey",
				Timestamp:   time.Now(),
			})
		}

		if asset := serviceToAsset(f); asset != nil {
			result.Findings = append(result.Findings, model.Finding{
				ID:       uuid.NewString(),
				Category: int(model.CategoryActiveNetwork),
				Source: model.FindingSource{
					Type:            "network",
					Endpoint:        endpoint,
					DetectionMethod: "banner-grab",
				},
				CryptoAsset: asset,
				Confidence:  0.85,
				Module:      "port_survey",
				Timestamp:   time.Now(),
			})
		}
	}
	return result
}

func serviceToAsset(f *Finding) *model.CryptoAsset {
	if f.Service == "" {
		return nil
	}
	proto := strings.ToLower(f.Service)
	switch proto {
	case "ssh":
		return &model.CryptoAsset{
			ID:        uuid.NewString(),
			Algorithm: "SSH",
			Subject:   f.Banner,
			PQCStatus: model.PQCStatusTransitional,
			Function:  "authentication",
			State:     "IN_TRANSIT",
		}
	case "http", "https":
		if f.Banner == "" {
			return nil
		}
		return &model.CryptoAsset{
			ID:        uuid.NewString(),
			Algorithm: strings.ToUpper(proto),
			Subject:   f.Banner,
			PQCStatus: model.PQCStatusTransitional,
			Function:  "encryption",
			State:     "IN_TRANSIT",
		}
	}
	return nil
}

func classifyKeySize(algo string, bits int) string {
	switch strings.ToUpper(algo) {
	case "RSA":
		if bits >= 2048 {
			return model.PQCStatusTransitional
		}
		return model.PQCStatusDeprecated
	case "ECDSA", "EC":
		if bits >= 256 {
			return model.PQCStatusTransitional
		}
		return model.PQCStatusDeprecated
	}
	return model.PQCStatusTransitional
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/scanrunner/... -run TestToScanResult -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanrunner/mapper.go pkg/scanrunner/mapper_test.go
git commit -m "feat(scanrunner): ToScanResult mapper with tests"
```

---

## Task 3: `pkg/scanrunner/client.go` — ManageClient + ReportClient

**Files:**
- Create: `pkg/scanrunner/client.go`
- Create: `pkg/scanrunner/client_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// pkg/scanrunner/client_test.go
package scanrunner_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanrunner"
)

func TestManageClient_Claim_OK(t *testing.T) {
	jobID := uuid.New()
	hostID := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Worker-Key") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanrunner.ClaimResp{
			JobID:   jobID,
			HostID:  hostID,
			Profile: "standard",
		})
	}))
	defer srv.Close()

	c := scanrunner.NewManageClient(srv.URL, "secret")
	resp, err := c.Claim(context.Background(), jobID)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if resp.JobID != jobID {
		t.Errorf("job id mismatch")
	}
	if resp.Profile != "standard" {
		t.Errorf("profile: got %q, want standard", resp.Profile)
	}
}

func TestManageClient_Claim_JobGone(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusConflict} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		c := scanrunner.NewManageClient(srv.URL, "key")
		_, err := c.Claim(context.Background(), uuid.New())
		if err == nil || err != scanrunner.ErrJobGone {
			t.Errorf("status %d: expected ErrJobGone, got %v", status, err)
		}
		srv.Close()
	}
}

func TestManageClient_Heartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := scanrunner.NewManageClient(srv.URL, "key")
	if err := c.Heartbeat(context.Background(), uuid.New()); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
}

func TestManageClient_Complete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := scanrunner.NewManageClient(srv.URL, "key")
	if err := c.Complete(context.Background(), uuid.New()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestManageClient_Fail(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := scanrunner.NewManageClient(srv.URL, "key")
	if err := c.Fail(context.Background(), uuid.New(), "scan error"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if gotBody["error"] != "scan error" {
		t.Errorf("body error field: got %q, want scan error", gotBody["error"])
	}
}

func TestManageClient_GetHost(t *testing.T) {
	hostID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanrunner.HostInfo{
			ID:       hostID,
			Hostname: "srv1",
			IP:       "10.0.0.5",
		})
	}))
	defer srv.Close()

	c := scanrunner.NewManageClient(srv.URL, "key")
	h, err := c.GetHost(context.Background(), hostID)
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.IP != "10.0.0.5" {
		t.Errorf("IP: got %q, want 10.0.0.5", h.IP)
	}
}

func TestReportClient_Submit(t *testing.T) {
	var submitted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/scans" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		submitted = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := scanrunner.NewReportClient(srv.URL, "my-token")
	if err := c.Submit(context.Background(), &model.ScanResult{ID: uuid.NewString()}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !submitted {
		t.Error("report server was not called")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./pkg/scanrunner/... -run TestManageClient -v
```
Expected: FAIL — `NewManageClient` undefined.

- [ ] **Step 3: Implement client.go**

```go
// pkg/scanrunner/client.go
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

// ClaimResp is the JSON body returned by POST /v1/worker/jobs/{id}/claim.
type ClaimResp struct {
	JobID          uuid.UUID  `json:"job_id"`
	HostID         uuid.UUID  `json:"host_id"`
	Profile        string     `json:"profile"`
	PortOverride   []uint16   `json:"port_override,omitempty"`
	CredentialsRef *uuid.UUID `json:"credentials_ref,omitempty"`
}

// HostInfo holds the fields RunOne needs from GET /v1/admin/hosts/{id}.
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
	resp, err := c.req(ctx, http.MethodPost, fmt.Sprintf("/v1/worker/jobs/%s/claim", jobID), nil)
	if err != nil {
		return ClaimResp{}, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusConflict {
		return ClaimResp{}, ErrJobGone
	}
	if resp.StatusCode != http.StatusOK {
		return ClaimResp{}, fmt.Errorf("claim: status %d", resp.StatusCode)
	}
	var cr ClaimResp
	return cr, json.NewDecoder(resp.Body).Decode(&cr)
}

// Heartbeat renews running_heartbeat_at.
func (c *ManageClient) Heartbeat(ctx context.Context, jobID uuid.UUID) error {
	resp, err := c.req(ctx, http.MethodPatch, fmt.Sprintf("/v1/worker/jobs/%s/heartbeat", jobID), nil)
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("heartbeat: status %d", resp.StatusCode)
	}
	return nil
}

// Complete marks the job completed.
func (c *ManageClient) Complete(ctx context.Context, jobID uuid.UUID) error {
	resp, err := c.req(ctx, http.MethodPost, fmt.Sprintf("/v1/worker/jobs/%s/complete", jobID), nil)
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("complete: status %d", resp.StatusCode)
	}
	return nil
}

// Fail marks the job failed with an error message.
func (c *ManageClient) Fail(ctx context.Context, jobID uuid.UUID, errMsg string) error {
	resp, err := c.req(ctx, http.MethodPost, fmt.Sprintf("/v1/worker/jobs/%s/fail", jobID),
		map[string]string{"error": errMsg})
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("fail: status %d", resp.StatusCode)
	}
	return nil
}

// GetHost fetches host info by ID (uses X-Worker-Key for auth).
func (c *ManageClient) GetHost(ctx context.Context, hostID uuid.UUID) (HostInfo, error) {
	resp, err := c.req(ctx, http.MethodGet, fmt.Sprintf("/v1/admin/hosts/%s", hostID), nil)
	if err != nil {
		return HostInfo{}, err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return HostInfo{}, fmt.Errorf("get host: status %d", resp.StatusCode)
	}
	var h HostInfo
	return h, json.NewDecoder(resp.Body).Decode(&h)
}

// ReportClient submits scan results directly to the report server.
type ReportClient struct {
	base  string
	token string
	http  *http.Client
}

// NewReportClient constructs a ReportClient with a 60 s timeout.
func NewReportClient(baseURL, licenseToken string) *ReportClient {
	return &ReportClient{
		base:  baseURL,
		token: licenseToken,
		http:  &http.Client{Timeout: 60 * time.Second},
	}
}

// Submit posts a ScanResult to POST /api/v1/scans.
func (c *ReportClient) Submit(ctx context.Context, result *model.ScanResult) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/v1/scans", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Token", c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("submit: status %d", resp.StatusCode)
	}
	return nil
}

func drainClose(b io.ReadCloser) {
	_, _ = io.Copy(io.Discard, b)
	_ = b.Close()
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/scanrunner/... -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanrunner/client.go pkg/scanrunner/client_test.go
git commit -m "feat(scanrunner): ManageClient + ReportClient with tests"
```

---

## Task 4: `pkg/scanrunner/runner.go` — RunOne lifecycle

**Files:**
- Create: `pkg/scanrunner/runner.go`
- Create: `pkg/scanrunner/runner_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// pkg/scanrunner/runner_test.go
package scanrunner_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/scanrunner"
)

// stubScanner is a Scanner that returns preset findings or an error.
type stubScanner struct {
	findings []scanrunner.Finding
	err      error
}

func (s *stubScanner) Scan(_ context.Context, _ scanrunner.Target, onFinding func(scanrunner.Finding)) error {
	if s.err != nil {
		return s.err
	}
	for _, f := range s.findings {
		onFinding(f)
	}
	return nil
}

func buildManageServer(t *testing.T, jobID, hostID uuid.UUID, completedPtr *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/worker/jobs/"+jobID.String()+"/claim":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(scanrunner.ClaimResp{
				JobID: jobID, HostID: hostID, Profile: "standard",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/admin/hosts/"+hostID.String():
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(scanrunner.HostInfo{
				ID: hostID, Hostname: "host1", IP: "192.168.1.50",
			})
		case r.Method == http.MethodPatch:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/worker/jobs/"+jobID.String()+"/complete":
			if completedPtr != nil {
				*completedPtr = true
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/worker/jobs/"+jobID.String()+"/fail":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected manage request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRunOne_Success(t *testing.T) {
	jobID, hostID := uuid.New(), uuid.New()
	var completed, submitted bool

	manageSrv := buildManageServer(t, jobID, hostID, &completed)
	defer manageSrv.Close()

	reportSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		submitted = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer reportSrv.Close()

	manage := scanrunner.NewManageClient(manageSrv.URL, "key")
	report := scanrunner.NewReportClient(reportSrv.URL, "token")
	scanner := &stubScanner{findings: []scanrunner.Finding{{Port: 443, Service: "https", Banner: "nginx"}}}

	if err := scanrunner.RunOne(context.Background(), jobID, manage, report, scanner); err != nil {
		t.Fatalf("RunOne: %v", err)
	}
	if !submitted {
		t.Error("result not submitted to report server")
	}
	if !completed {
		t.Error("complete not called on manage server")
	}
}

func TestRunOne_JobGone_ExitsClean(t *testing.T) {
	manageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer manageSrv.Close()

	manage := scanrunner.NewManageClient(manageSrv.URL, "key")
	report := scanrunner.NewReportClient("http://127.0.0.1:1", "token")
	err := scanrunner.RunOne(context.Background(), uuid.New(), manage, report, &stubScanner{})
	if err != nil {
		t.Fatalf("expected nil for job-not-found, got: %v", err)
	}
}

func TestRunOne_ScanError_CallsFail(t *testing.T) {
	jobID, hostID := uuid.New(), uuid.New()
	var failCalled bool

	manageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/worker/jobs/"+jobID.String()+"/claim":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(scanrunner.ClaimResp{JobID: jobID, HostID: hostID, Profile: "quick"})
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(scanrunner.HostInfo{ID: hostID, IP: "10.0.0.1"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/worker/jobs/"+jobID.String()+"/fail":
			failCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer manageSrv.Close()

	manage := scanrunner.NewManageClient(manageSrv.URL, "key")
	report := scanrunner.NewReportClient("http://127.0.0.1:1", "token")
	scanner := &stubScanner{err: errors.New("port scan failed")}

	err := scanrunner.RunOne(context.Background(), jobID, manage, report, scanner)
	if err == nil {
		t.Fatal("expected non-nil error from scan failure")
	}
	if !failCalled {
		t.Error("Fail was not called on manage server after scan error")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./pkg/scanrunner/... -run TestRunOne -v
```
Expected: FAIL — `RunOne` undefined.

- [ ] **Step 3: Implement runner.go**

```go
// pkg/scanrunner/runner.go
package scanrunner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// RunOne executes the full lifecycle for one scan job:
// claim → resolve host → scan → submit → complete.
// Returns nil when the job is not found or already claimed (exit 0 case).
// Returns non-nil on scan or submission failure (caller should exit 1).
func RunOne(ctx context.Context, jobID uuid.UUID, manage *ManageClient, report *ReportClient, scanner Scanner) error {
	// Step 1: Claim.
	claim, err := manage.Claim(ctx, jobID)
	if err != nil {
		if errors.Is(err, ErrJobGone) {
			log.Printf("runner: job %s: not found or already claimed — exiting cleanly", jobID)
			return nil
		}
		return fmt.Errorf("runner: claim %s: %w", jobID, err)
	}

	// All failures from here must be reported to the manage server.
	fail := func(scanErr error) error {
		ctx2 := context.Background() // parent ctx may be cancelled
		if ferr := manage.Fail(ctx2, jobID, scanErr.Error()); ferr != nil {
			log.Printf("runner: report fail for %s: %v", jobID, ferr)
		}
		return scanErr
	}

	// Step 2: Resolve host IP.
	host, err := manage.GetHost(ctx, claim.HostID)
	if err != nil {
		return fail(fmt.Errorf("runner: get host %s: %w", claim.HostID, err))
	}
	if host.IP == "" {
		return fail(fmt.Errorf("runner: host %s has no IP address", claim.HostID))
	}

	// Step 3: Heartbeat goroutine.
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-tick.C:
				if err := manage.Heartbeat(hbCtx, jobID); err != nil {
					log.Printf("runner: heartbeat %s: %v", jobID, err)
				}
			}
		}
	}()

	// Step 4: Scan.
	target := Target{
		IP:           host.IP,
		Profile:      claim.Profile,
		PortOverride: claim.PortOverride,
	}
	var findings []Finding
	if err := scanner.Scan(ctx, target, func(f Finding) {
		findings = append(findings, f)
	}); err != nil {
		hbCancel()
		return fail(fmt.Errorf("runner: scan %s: %w", host.IP, err))
	}
	hbCancel()

	// Step 5: Map + submit.
	hostname := host.Hostname
	if hostname == "" {
		hostname = host.IP
	}
	result := ToScanResult(hostname, host.IP, claim.Profile, findings)
	if err := report.Submit(ctx, result); err != nil {
		return fail(fmt.Errorf("runner: submit %s: %w", jobID, err))
	}

	// Step 6: Mark complete (best-effort — result already submitted).
	if err := manage.Complete(ctx, jobID); err != nil {
		log.Printf("runner: complete %s: %v", jobID, err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/scanrunner/... -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanrunner/runner.go pkg/scanrunner/runner_test.go
git commit -m "feat(scanrunner): RunOne lifecycle with tests"
```

---

## Task 5: Refactor `pkg/manageserver/portscan/` — FingerprintxScanner

Replace the old in-process `Scanner` struct and helpers with `FingerprintxScanner` implementing `scanrunner.Scanner`. Remove `scan_func.go` and `result_mapper.go`.

**Files:**
- Rename/rewrite: `pkg/manageserver/portscan/scanner.go` → `fingerprintx.go`
- Modify: `pkg/manageserver/portscan/tls.go`
- Delete: `pkg/manageserver/portscan/scan_func.go`
- Delete: `pkg/manageserver/portscan/result_mapper.go`
- Delete: `pkg/manageserver/portscan/result_mapper_test.go`

- [ ] **Step 1: Delete the files to be removed**

```bash
rm pkg/manageserver/portscan/scan_func.go
rm pkg/manageserver/portscan/result_mapper.go
rm pkg/manageserver/portscan/result_mapper_test.go
```

- [ ] **Step 2: Update tls.go to return `*scanrunner.TLSCertInfo`**

Replace the full file content:

```go
package portscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/amiryahaya/triton/pkg/scanrunner"
)

// extractTLSCert dials ip:port with TLS, extracts the leaf certificate.
// Returns nil on any failure — TLS extraction is best-effort.
func extractTLSCert(ctx context.Context, ip string, port int, timeout time.Duration) *scanrunner.TLSCertInfo {
	_ = ctx
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp",
		fmt.Sprintf("%s:%d", ip, port),
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional audit scan
	)
	if err != nil {
		return nil
	}
	defer conn.Close() //nolint:errcheck

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	leaf := certs[0]

	info := &scanrunner.TLSCertInfo{
		Subject:      leaf.Subject.CommonName,
		Issuer:       leaf.Issuer.CommonName,
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		SANs:         leaf.DNSNames,
		SerialNumber: leaf.SerialNumber.String(),
		IsSelfSigned: leaf.Issuer.CommonName == leaf.Subject.CommonName,
	}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		info.Algorithm = "RSA"
		info.KeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.Algorithm = "ECDSA"
		info.KeyBits = pub.Params().BitSize
	default:
		info.Algorithm = fmt.Sprintf("%T", leaf.PublicKey)
	}
	return info
}
```

- [ ] **Step 3: Create fingerprintx.go (replace scanner.go)**

Delete `scanner.go` and create `fingerprintx.go`:

```bash
rm pkg/manageserver/portscan/scanner.go
```

```go
// pkg/manageserver/portscan/fingerprintx.go
package portscan

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/scanrunner"
)

// FingerprintxScanner implements scanrunner.Scanner using fingerprintx.
type FingerprintxScanner struct{}

// NewFingerprintxScanner returns a FingerprintxScanner ready to use.
func NewFingerprintxScanner() *FingerprintxScanner {
	return &FingerprintxScanner{}
}

// Scan probes the target using fingerprintx and calls onFinding for each result.
func (s *FingerprintxScanner) Scan(ctx context.Context, target scanrunner.Target, onFinding func(scanrunner.Finding)) error {
	addr, err := netip.ParseAddr(target.IP)
	if err != nil {
		return fmt.Errorf("portscan: invalid ip %q: %w", target.IP, err)
	}

	profile := scanjobs.Profile(target.Profile)
	ports := effectivePorts(profile, target.PortOverride)
	targets := make([]plugins.Target, len(ports))
	for i, p := range ports {
		targets[i] = plugins.Target{Address: netip.AddrPortFrom(addr, p)}
	}

	_, timeoutSec := profileParams(profile)
	cfg := scan.Config{
		DefaultTimeout: time.Duration(timeoutSec) * time.Second,
		FastMode:       profile == scanjobs.ProfileQuick,
		Verbose:        false,
		UDP:            false,
	}

	results, err := scan.ScanTargets(targets, cfg)
	if err != nil {
		return fmt.Errorf("portscan: fingerprintx %s: %w", target.IP, err)
	}

	for i := range results {
		svc := &results[i]
		f := scanrunner.Finding{
			Port:    uint16(svc.Port), //nolint:gosec // port always in [1,65535]
			Service: svc.Protocol,
			Banner:  svc.Version,
		}
		if isTLSService(svc) {
			f.TLSCert = extractTLSCert(ctx, target.IP, svc.Port,
				time.Duration(timeoutSec)*time.Second)
		}
		onFinding(f)
	}
	return nil
}

func effectivePorts(p scanjobs.Profile, override []uint16) []uint16 {
	if len(override) > 0 {
		return override
	}
	return Ports(p)
}

func profileParams(p scanjobs.Profile) (concurrency int, timeoutSec int) {
	switch p {
	case scanjobs.ProfileComprehensive:
		return 500, 5
	case scanjobs.ProfileStandard:
		return 200, 3
	default:
		return 50, 3
	}
}

func isTLSService(s *plugins.Service) bool {
	if s == nil {
		return false
	}
	switch s.Protocol {
	case plugins.ProtoHTTPS, "tls", plugins.ProtoSMTPS,
		plugins.ProtoIMAPS, plugins.ProtoPOP3S, "ftps",
		plugins.ProtoLDAPS, plugins.ProtoRDP:
		return true
	}
	return false
}
```

- [ ] **Step 4: Verify the portscan package compiles**

```bash
go build ./pkg/manageserver/portscan/...
```
Expected: no errors.

- [ ] **Step 5: Run full build**

```bash
go build ./...
```
Expected: errors in `server.go` (references `portscan.NewPortScanFunc` which was deleted) — that's fine, will be fixed in Task 10.

- [ ] **Step 6: Commit**

```bash
git add pkg/manageserver/portscan/
git commit -m "refactor(portscan): FingerprintxScanner implements scanrunner.Scanner; remove scan_func + result_mapper"
```

---

## Task 6: Schema v15 + Store.ListQueued + Store.ClaimByID + ClaimNext filesystem filter

**Files:**
- Modify: `pkg/managestore/migrations.go` — add v15
- Modify: `pkg/manageserver/scanjobs/types.go` — add `PortOverride` to `Job` + `PortSurveyEnqueueReq`
- Modify: `pkg/manageserver/scanjobs/store.go` — add `ErrAlreadyClaimed`, `ListQueued`, `ClaimByID`
- Modify: `pkg/manageserver/scanjobs/postgres.go` — implement both methods + update `ClaimNext`

- [ ] **Step 1: Write the failing tests**

```go
// pkg/manageserver/scanjobs/postgres_ext_test.go
//go:build integration

package scanjobs_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/managestore"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TRITON_TEST_DB_URL")
	if dsn == "" {
		dsn = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	ms, err := managestore.NewPostgresStore(pool)
	if err != nil {
		t.Fatalf("managestore: %v", err)
	}
	if err := ms.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := pool.Exec(context.Background(), "TRUNCATE manage_scan_jobs CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pool
}

func TestListQueued_FiltersJobType(t *testing.T) {
	pool := testPool(t)
	store := scanjobs.NewPostgresStore(pool)
	tenantID := uuid.New()
	hostID := uuid.New()

	// Insert one filesystem + one port_survey job
	insertJob := func(jobType string) {
		_, err := pool.Exec(context.Background(),
			`INSERT INTO manage_scan_jobs (id, tenant_id, host_id, profile, status, job_type)
			 VALUES ($1, $2, $3, 'standard', 'queued', $4)`,
			uuid.New(), tenantID, hostID, jobType)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insertJob("filesystem")
	insertJob("port_survey")

	jobs, err := store.ListQueued(context.Background(), []string{"port_survey"}, 10)
	if err != nil {
		t.Fatalf("ListQueued: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected 1 port_survey job, got %d", len(jobs))
	}
	if jobs[0].JobType != scanjobs.JobTypePortSurvey {
		t.Errorf("job type: got %q", jobs[0].JobType)
	}
}

func TestClaimByID_Transitions(t *testing.T) {
	pool := testPool(t)
	store := scanjobs.NewPostgresStore(pool)
	tenantID, hostID := uuid.New(), uuid.New()
	jobID := uuid.New()

	_, err := pool.Exec(context.Background(),
		`INSERT INTO manage_scan_jobs (id, tenant_id, host_id, profile, status, job_type)
		 VALUES ($1, $2, $3, 'standard', 'queued', 'port_survey')`,
		jobID, tenantID, hostID)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// First claim succeeds.
	job, err := store.ClaimByID(context.Background(), jobID, "worker-1")
	if err != nil {
		t.Fatalf("ClaimByID first: %v", err)
	}
	if job.Status != scanjobs.StatusRunning {
		t.Errorf("status: got %q, want running", job.Status)
	}

	// Second claim returns ErrAlreadyClaimed.
	_, err = store.ClaimByID(context.Background(), jobID, "worker-2")
	if !errors.Is(err, scanjobs.ErrAlreadyClaimed) {
		t.Errorf("second claim: expected ErrAlreadyClaimed, got %v", err)
	}

	// Missing job returns ErrNotFound.
	_, err = store.ClaimByID(context.Background(), uuid.New(), "worker-3")
	if !errors.Is(err, scanjobs.ErrNotFound) {
		t.Errorf("missing job: expected ErrNotFound, got %v", err)
	}
}

func TestClaimNext_FilesystemOnly(t *testing.T) {
	pool := testPool(t)
	store := scanjobs.NewPostgresStore(pool)
	tenantID, hostID := uuid.New(), uuid.New()

	// Insert a port_survey job — ClaimNext must not pick it up.
	_, err := pool.Exec(context.Background(),
		`INSERT INTO manage_scan_jobs (id, tenant_id, host_id, profile, status, job_type)
		 VALUES ($1, $2, $3, 'quick', 'queued', 'port_survey')`,
		uuid.New(), tenantID, hostID)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	_, ok, err := store.ClaimNext(context.Background(), "orchestrator-0")
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if ok {
		t.Error("ClaimNext should not claim a port_survey job")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test -tags integration -run "TestListQueued|TestClaimByID|TestClaimNext_Filesystem" ./pkg/manageserver/scanjobs/... -v
```
Expected: FAIL — methods not defined.

- [ ] **Step 3: Add migration v15 — `port_override INTEGER[]`**

In `pkg/managestore/migrations.go`, append to the `migrations` slice (after the v14 entry):

```go
	// Version 15: Port override for port_survey jobs.
	// port_override stores explicit port numbers when the operator specifies
	// a custom list; NULL means "use the profile default port list".
	`ALTER TABLE manage_scan_jobs
	 ADD COLUMN IF NOT EXISTS port_override INTEGER[];`,
```

- [ ] **Step 4: Update `types.go` — add PortOverride to Job and PortSurveyEnqueueReq**

```go
// In Job struct, add after ScheduledAt:
PortOverride   []uint16   `json:"port_override,omitempty"`

// PortSurveyEnqueueReq becomes:
type PortSurveyEnqueueReq struct {
	TenantID    uuid.UUID   `json:"-"`
	HostIDs     []uuid.UUID `json:"host_ids"`
	Profile     Profile     `json:"profile"`
	ScheduledAt *time.Time  `json:"scheduled_at,omitempty"`
	PortOverride []uint16   `json:"port_override,omitempty"`
}
```

- [ ] **Step 5: Update `store.go` — add ErrAlreadyClaimed, ListQueued, ClaimByID**

After `var ErrNotFound`:
```go
// ErrAlreadyClaimed is returned by ClaimByID when the job exists but is no
// longer in 'queued' status (already claimed by another worker or cancelled).
var ErrAlreadyClaimed = errors.New("scanjobs: job already claimed or not queued")
```

Add to the `Store` interface:
```go
// ListQueued returns up to limit queued jobs matching any of the given
// job_types, with scheduled_at <= NOW(), ordered by enqueued_at ascending.
// Used by the Dispatcher to find jobs to spawn. Does NOT lock rows —
// ClaimByID's WHERE status='queued' guard handles concurrent spawners.
ListQueued(ctx context.Context, jobTypes []string, limit int) ([]Job, error)

// ClaimByID atomically transitions the named job from queued → running.
// Returns ErrNotFound when no such job exists.
// Returns ErrAlreadyClaimed when the job is not in 'queued' status.
ClaimByID(ctx context.Context, id uuid.UUID, workerID string) (Job, error)
```

- [ ] **Step 6: Update `postgres.go` — implement ListQueued, ClaimByID, and filter ClaimNext**

Find the `ClaimNext` function and add `AND COALESCE(job_type,'filesystem') = 'filesystem'` to its WHERE clause.

The typical ClaimNext query looks like:
```sql
UPDATE manage_scan_jobs SET status='running', worker_id=$1, started_at=NOW(), running_heartbeat_at=NOW()
WHERE id = (
    SELECT id FROM manage_scan_jobs
    WHERE status='queued'
      AND (scheduled_at IS NULL OR scheduled_at <= NOW())
    ORDER BY enqueued_at
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING <cols>
```

Add `AND COALESCE(job_type,'filesystem') = 'filesystem'` to the inner SELECT.

Add the new implementations:

```go
// ListQueued returns queued jobs of the specified types ordered by enqueued_at.
func (s *PostgresStore) ListQueued(ctx context.Context, jobTypes []string, limit int) ([]Job, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+jobSelectCols+`
		FROM manage_scan_jobs
		WHERE status = 'queued'
		  AND COALESCE(job_type,'filesystem') = ANY($1)
		  AND (scheduled_at IS NULL OR scheduled_at <= NOW())
		ORDER BY enqueued_at
		LIMIT $2`,
		jobTypes, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// ClaimByID atomically claims the named job for the given worker.
func (s *PostgresStore) ClaimByID(ctx context.Context, id uuid.UUID, workerID string) (Job, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE manage_scan_jobs
		SET status = 'running',
		    worker_id = $2,
		    started_at = NOW(),
		    running_heartbeat_at = NOW()
		WHERE id = $1 AND status = 'queued'
		RETURNING `+jobSelectCols,
		id, workerID,
	)
	j, err := scanJob(row)
	if err == nil {
		return j, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Job{}, err
	}
	// Distinguish not-found from already-claimed.
	var count int
	if qerr := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_scan_jobs WHERE id = $1`, id).Scan(&count); qerr != nil {
		return Job{}, qerr
	}
	if count == 0 {
		return Job{}, ErrNotFound
	}
	return Job{}, ErrAlreadyClaimed
}
```

Also update `postgres.go`'s `scanJob` to scan the new `port_override` column. Add it to `jobSelectCols`:

```go
const jobSelectCols = `id, tenant_id, host_id, profile, credentials_ref, status, cancel_requested,
COALESCE(worker_id,''), enqueued_at, started_at, finished_at, running_heartbeat_at,
progress_text, error_message, COALESCE(job_type,'filesystem'), scheduled_at, port_override`
```

Update `scanJob` to scan the `port_override` column into `[]int32` and convert:

```go
// Add at the end of the var block inside scanJob:
var portOverride []int32

// Add port_override to the Scan call as last arg:
&portOverride,

// After Scan succeeds, convert:
for _, p := range portOverride {
    j.PortOverride = append(j.PortOverride, uint16(p)) //nolint:gosec
}
```

Also update `EnqueuePortSurvey` in `postgres.go` to insert `port_override` when set:

Find `EnqueuePortSurvey` and add `port_override` to the INSERT (use `NULL` when `req.PortOverride` is empty):

```go
// Convert []uint16 to []int32 for pgx:
var portOverride []int32
for _, p := range req.PortOverride {
    portOverride = append(portOverride, int32(p))
}
// Pass portOverride as parameter to INSERT; use NULL when nil
```

- [ ] **Step 7: Run integration tests**

```bash
go test -tags integration -run "TestListQueued|TestClaimByID|TestClaimNext_Filesystem" ./pkg/manageserver/scanjobs/... -v
```
Expected: all PASS.

- [ ] **Step 8: Run full unit test suite**

```bash
go test ./...
```
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add pkg/managestore/migrations.go \
        pkg/manageserver/scanjobs/types.go \
        pkg/manageserver/scanjobs/store.go \
        pkg/manageserver/scanjobs/postgres.go \
        pkg/manageserver/scanjobs/postgres_ext_test.go
git commit -m "feat(scanjobs): migration v15 port_override + Store.ListQueued + Store.ClaimByID + ClaimNext filesystem filter"
```

---

## Task 7: Worker API — handlers + WorkerKeyAuth middleware + routes

**Files:**
- Create: `pkg/manageserver/scanjobs/worker_handlers.go`
- Create: `pkg/manageserver/scanjobs/worker_handlers_test.go`
- Modify: `pkg/manageserver/scanjobs/routes.go`

- [ ] **Step 1: Write the failing tests**

```go
// pkg/manageserver/scanjobs/worker_handlers_test.go
package scanjobs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// stubWorkerStore implements only the Store methods needed by WorkerHandlers.
// Embed a failing base if other methods are called unexpectedly.
type stubWorkerStore struct {
	scanjobs.Store // embed for other methods (will panic if called)

	claimResult scanjobs.Job
	claimErr    error
	heartbeatErr error
	completeErr  error
	failErr      error
}

func (s *stubWorkerStore) ClaimByID(_ context.Context, _ uuid.UUID, _ string) (scanjobs.Job, error) {
	return s.claimResult, s.claimErr
}
func (s *stubWorkerStore) Heartbeat(_ context.Context, _ uuid.UUID, _ string) error {
	return s.heartbeatErr
}
func (s *stubWorkerStore) Complete(_ context.Context, _ uuid.UUID) error {
	return s.completeErr
}
func (s *stubWorkerStore) Fail(_ context.Context, _ uuid.UUID, _ string) error {
	return s.failErr
}

func routedRequest(method, path, body string, jobID uuid.UUID) (*httptest.ResponseRecorder, *http.Request) {
	var b *bytes.Reader
	if body != "" {
		b = bytes.NewReader([]byte(body))
	} else {
		b = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, b)
	r.Header.Set("X-Worker-Key", "test-key")
	r.Header.Set("Content-Type", "application/json")

	// Set chi URL param
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	return httptest.NewRecorder(), r
}

func TestWorkerClaim_OK(t *testing.T) {
	jobID, hostID := uuid.New(), uuid.New()
	store := &stubWorkerStore{
		claimResult: scanjobs.Job{
			ID: jobID, HostID: hostID, Profile: scanjobs.ProfileStandard,
			Status: scanjobs.StatusRunning,
		},
	}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/v1/worker/jobs/"+jobID.String()+"/claim", "", jobID)
	h.Claim(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var resp scanjobs.ClaimWorkerResp
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.HostID != hostID {
		t.Errorf("host_id mismatch")
	}
}

func TestWorkerClaim_AlreadyClaimed_Returns409(t *testing.T) {
	store := &stubWorkerStore{claimErr: scanjobs.ErrAlreadyClaimed}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/", "", uuid.New())
	h.Claim(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("status: got %d, want 409", w.Code)
	}
}

func TestWorkerClaim_NotFound_Returns404(t *testing.T) {
	store := &stubWorkerStore{claimErr: scanjobs.ErrNotFound}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/", "", uuid.New())
	h.Claim(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
}

func TestWorkerHeartbeat_OK(t *testing.T) {
	store := &stubWorkerStore{}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPatch, "/", "", uuid.New())
	h.Heartbeat(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
}

func TestWorkerComplete_OK(t *testing.T) {
	store := &stubWorkerStore{}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/", "", uuid.New())
	h.Complete(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
}

func TestWorkerFail_OK(t *testing.T) {
	store := &stubWorkerStore{}
	h := scanjobs.NewWorkerHandlers(store)
	w, r := routedRequest(http.MethodPost, "/", `{"error":"boom"}`, uuid.New())
	h.Fail(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
}

func TestWorkerKeyAuth_Rejects(t *testing.T) {
	r := chi.NewRouter()
	r.Use(scanjobs.WorkerKeyAuth("correct-key"))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Worker-Key", "wrong-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./pkg/manageserver/scanjobs/... -run TestWorker -v
```
Expected: FAIL — `NewWorkerHandlers` undefined.

- [ ] **Step 3: Implement worker_handlers.go**

```go
// pkg/manageserver/scanjobs/worker_handlers.go
package scanjobs

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ClaimWorkerResp is the JSON body returned by the claim endpoint.
type ClaimWorkerResp struct {
	JobID          uuid.UUID  `json:"job_id"`
	HostID         uuid.UUID  `json:"host_id"`
	Profile        string     `json:"profile"`
	PortOverride   []uint16   `json:"port_override,omitempty"`
	CredentialsRef *uuid.UUID `json:"credentials_ref,omitempty"`
}

// WorkerHandlers serves the /v1/worker/ route group.
type WorkerHandlers struct {
	store Store
}

// NewWorkerHandlers constructs WorkerHandlers.
func NewWorkerHandlers(store Store) *WorkerHandlers {
	return &WorkerHandlers{store: store}
}

// WorkerKeyAuth is middleware that validates the X-Worker-Key header.
func WorkerKeyAuth(key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Worker-Key") != key {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Claim handles POST /v1/worker/jobs/{id}/claim.
func (h *WorkerHandlers) Claim(w http.ResponseWriter, r *http.Request) {
	id, ok := parseJobID(w, r)
	if !ok {
		return
	}
	workerID := r.Header.Get("X-Worker-Key") // use key as worker identifier
	job, err := h.store.ClaimByID(r.Context(), id, workerID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrAlreadyClaimed) {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ClaimWorkerResp{ //nolint:errcheck
		JobID:          job.ID,
		HostID:         job.HostID,
		Profile:        string(job.Profile),
		PortOverride:   job.PortOverride,
		CredentialsRef: job.CredentialsRef,
	})
}

// Heartbeat handles PATCH /v1/worker/jobs/{id}/heartbeat.
func (h *WorkerHandlers) Heartbeat(w http.ResponseWriter, r *http.Request) {
	id, ok := parseJobID(w, r)
	if !ok {
		return
	}
	if err := h.store.Heartbeat(r.Context(), id, ""); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Complete handles POST /v1/worker/jobs/{id}/complete.
func (h *WorkerHandlers) Complete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseJobID(w, r)
	if !ok {
		return
	}
	if err := h.store.Complete(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type failBody struct {
	Error string `json:"error"`
}

// Fail handles POST /v1/worker/jobs/{id}/fail.
func (h *WorkerHandlers) Fail(w http.ResponseWriter, r *http.Request) {
	id, ok := parseJobID(w, r)
	if !ok {
		return
	}
	var body failBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.store.Fail(r.Context(), id, body.Error); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseJobID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := chi.URLParam(r, "id")
	id, err := uuid.Parse(raw)
	if err != nil {
		http.Error(w, "invalid job id", http.StatusBadRequest)
		return uuid.UUID{}, false
	}
	return id, true
}
```

- [ ] **Step 4: Add MountWorkerRoutes to routes.go**

```go
// MountWorkerRoutes wires the Worker API onto r under /v1/worker/.
// key is the shared X-Worker-Key secret.
//
// Route table:
//
//	POST   /jobs/{id}/claim     - claim a queued job → 200 ClaimWorkerResp | 404 | 409
//	PATCH  /jobs/{id}/heartbeat - renew running_heartbeat_at → 204
//	POST   /jobs/{id}/complete  - mark job completed → 204
//	POST   /jobs/{id}/fail      - mark job failed (body: {"error":"…"}) → 204
func MountWorkerRoutes(r chi.Router, h *WorkerHandlers, key string) {
	r.Group(func(r chi.Router) {
		r.Use(WorkerKeyAuth(key))
		r.Post("/jobs/{id}/claim", h.Claim)
		r.Patch("/jobs/{id}/heartbeat", h.Heartbeat)
		r.Post("/jobs/{id}/complete", h.Complete)
		r.Post("/jobs/{id}/fail", h.Fail)
	})
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./pkg/manageserver/scanjobs/... -run TestWorker -v
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/manageserver/scanjobs/worker_handlers.go \
        pkg/manageserver/scanjobs/worker_handlers_test.go \
        pkg/manageserver/scanjobs/routes.go
git commit -m "feat(scanjobs): Worker API — claim/heartbeat/complete/fail + WorkerKeyAuth middleware"
```

---

## Task 8: Orchestrator — remove PortScanFunc dispatch

**Files:**
- Modify: `pkg/manageserver/scanjobs/orchestrator.go`

- [ ] **Step 1: Remove `PortScanFunc` field from OrchestratorConfig**

In `orchestrator.go`, remove the `PortScanFunc ScanFunc` field (lines ~48-50) and its comment from `OrchestratorConfig`.

Before:
```go
// ScanFunc is the scanner invocation. nil → defaultScanFunc ...
ScanFunc ScanFunc

// PortScanFunc is the scanner for port_survey jobs. nil → port_survey
// jobs fail immediately with "PortScanFunc not configured".
PortScanFunc ScanFunc
```

After:
```go
// ScanFunc is the scanner invocation. nil → defaultScanFunc,
// which returns an error; production wiring must either supply
// a ScanFunc or use NewScanFunc() from scan_runner.go.
ScanFunc ScanFunc
```

- [ ] **Step 2: Remove port_survey dispatch from runOneJob**

Find the branch in `runOneJob` that dispatches to `PortScanFunc` when `j.JobType == JobTypePortSurvey`. It looks like:

```go
if j.JobType == JobTypePortSurvey {
    if o.cfg.PortScanFunc == nil {
        return nil, errors.New("PortScanFunc not configured")
    }
    return o.cfg.PortScanFunc(ctx, j)
}
```

Delete this block entirely. The orchestrator now only handles filesystem jobs (which `ClaimNext` already filters at the DB level).

- [ ] **Step 3: Build + test**

```bash
go build ./pkg/manageserver/...
go test ./pkg/manageserver/scanjobs/...
```
Expected: PASS. (server.go still broken — fixed in Task 10.)

- [ ] **Step 4: Commit**

```bash
git add pkg/manageserver/scanjobs/orchestrator.go
git commit -m "refactor(orchestrator): remove PortScanFunc — port_survey jobs handled by Dispatcher"
```

---

## Task 9: Dispatcher — gopsutil + subprocess spawner

**Files:**
- Create: `pkg/manageserver/scanjobs/dispatcher.go`
- Create: `pkg/manageserver/scanjobs/dispatcher_test.go`

- [ ] **Step 1: Add gopsutil dependency**

```bash
go get github.com/shirou/gopsutil/v3/cpu
go get github.com/shirou/gopsutil/v3/mem
go mod tidy
```

- [ ] **Step 2: Write the failing test (resource cap logic)**

```go
// pkg/manageserver/scanjobs/dispatcher_test.go
package scanjobs_test

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

func TestComputeCaps_HighLoad_Defers(t *testing.T) {
	caps, ok := scanjobs.ComputeCaps(75.0, 512, 80, 1024)
	if ok {
		t.Error("expected defer (ok=false) when CPU>70% and RAM<1GB")
	}
	_ = caps
}

func TestComputeCaps_LowLoad(t *testing.T) {
	caps, ok := scanjobs.ComputeCaps(30.0, 4096, 80, 1024)
	if !ok {
		t.Fatal("expected spawn (ok=true) for low load")
	}
	if caps.CPUPct > 50 {
		t.Errorf("CPU cap too high: %d > 50", caps.CPUPct)
	}
	if caps.MemMiB > 512 {
		t.Errorf("memory cap too high: %d > 512", caps.MemMiB)
	}
}

func TestComputeCaps_MediumLoad(t *testing.T) {
	caps, ok := scanjobs.ComputeCaps(60.0, 1500, 80, 1024)
	if !ok {
		t.Fatal("expected spawn for medium load")
	}
	if caps.CPUPct > 30 {
		t.Errorf("CPU cap: got %d, want <= 30", caps.CPUPct)
	}
}

func TestComputeCaps_HighCPULowRam_RespectsOperatorCeiling(t *testing.T) {
	caps, ok := scanjobs.ComputeCaps(75.0, 2048, 10, 64)
	if !ok {
		t.Fatal("expected spawn when RAM >= 1GB despite high CPU")
	}
	if caps.CPUPct > 10 {
		t.Errorf("operator ceiling violated: %d > 10", caps.CPUPct)
	}
	if caps.MemMiB > 64 {
		t.Errorf("operator ceiling violated: %d > 64", caps.MemMiB)
	}
}
```

- [ ] **Step 3: Run to confirm failure**

```bash
go test ./pkg/manageserver/scanjobs/... -run TestComputeCaps -v
```
Expected: FAIL — `ComputeCaps` undefined.

- [ ] **Step 4: Implement dispatcher.go**

```go
// pkg/manageserver/scanjobs/dispatcher.go
package scanjobs

import (
	"context"
	"log"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// DispatcherConfig controls the generic job-type → binary dispatcher.
type DispatcherConfig struct {
	// Executors maps job_type to the binary that handles it.
	// e.g. "port_survey" → ExecutorConfig{BinaryPath: "triton-portscan", ...}
	Executors map[string]ExecutorConfig

	Store         Store
	MaxConcurrent int           // hard ceiling across all executors; default 4
	PollInterval  time.Duration // default 5s
	MaxCPUPct     int           // operator ceiling for dynamic cap; default 80
	MaxMemoryMiB  int           // operator ceiling for dynamic cap; default 1024
}

// ExecutorConfig describes one binary executor.
type ExecutorConfig struct {
	BinaryPath   string // resolved via PATH or absolute
	ManageURL    string // manage server base URL (self)
	WorkerKey    string // X-Worker-Key secret
	ReportURL    string // report server base URL
	LicenseToken string // report server auth token
}

// ResourceCaps are the computed per-spawn limits passed as CLI flags.
type ResourceCaps struct {
	CPUPct int
	MemMiB int
}

// ComputeCaps is exported for testing. It encapsulates the dynamic-cap
// decision table given sampled cpuPct (0–100) and freeRAMMiB.
// maxCPUPct and maxMemMiB are the operator ceilings.
// Returns (caps, true) to spawn or (zero, false) to defer.
func ComputeCaps(cpuPct float64, freeRAMMiB int64, maxCPUPct, maxMemMiB int) (ResourceCaps, bool) {
	switch {
	case cpuPct > 70 && freeRAMMiB < 1024:
		return ResourceCaps{}, false
	case cpuPct > 70:
		return ResourceCaps{
			CPUPct: min(maxCPUPct, 15),
			MemMiB: min(maxMemMiB, 128),
		}, true
	case cpuPct >= 50:
		return ResourceCaps{
			CPUPct: min(maxCPUPct, 30),
			MemMiB: min(maxMemMiB, 256),
		}, true
	default:
		return ResourceCaps{
			CPUPct: min(maxCPUPct, 50),
			MemMiB: min(maxMemMiB, 512),
		}, true
	}
}

// Dispatcher polls the job queue, samples host load, and spawns one
// subprocess per job slot.
type Dispatcher struct {
	cfg DispatcherConfig

	mu      sync.Mutex
	running map[uuid.UUID]*exec.Cmd
}

// NewDispatcher applies defaults and returns a Dispatcher.
func NewDispatcher(cfg DispatcherConfig) *Dispatcher {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.MaxCPUPct <= 0 {
		cfg.MaxCPUPct = 80
	}
	if cfg.MaxMemoryMiB <= 0 {
		cfg.MaxMemoryMiB = 1024
	}
	return &Dispatcher{
		cfg:     cfg,
		running: make(map[uuid.UUID]*exec.Cmd),
	}
}

// Run polls until ctx is cancelled, then waits up to 30 s for in-flight
// processes to finish before sending SIGTERM to any remaining ones.
func (d *Dispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.gracefulShutdown()
			return
		case <-ticker.C:
			d.poll(ctx)
		}
	}
}

func (d *Dispatcher) poll(ctx context.Context) {
	d.mu.Lock()
	slots := d.cfg.MaxConcurrent - len(d.running)
	d.mu.Unlock()
	if slots <= 0 {
		return
	}

	jobTypes := make([]string, 0, len(d.cfg.Executors))
	for jt := range d.cfg.Executors {
		jobTypes = append(jobTypes, jt)
	}

	jobs, err := d.cfg.Store.ListQueued(ctx, jobTypes, slots)
	if err != nil {
		log.Printf("dispatcher: list queued: %v", err)
		return
	}

	for _, j := range jobs {
		excfg, ok := d.cfg.Executors[string(j.JobType)]
		if !ok {
			continue
		}
		cpuPct, freeRAMMiB := sampleHostLoad()
		caps, ok := ComputeCaps(cpuPct, freeRAMMiB, d.cfg.MaxCPUPct, d.cfg.MaxMemoryMiB)
		if !ok {
			log.Printf("dispatcher: host under pressure, deferring job %s", j.ID)
			break // stop spawning this poll cycle
		}
		d.spawn(ctx, j.ID, excfg, caps)
	}
}

func (d *Dispatcher) spawn(ctx context.Context, jobID uuid.UUID, excfg ExecutorConfig, caps ResourceCaps) {
	cmd := exec.CommandContext(ctx, excfg.BinaryPath,
		"--job-id", jobID.String(),
		"--manage-server", excfg.ManageURL,
		"--worker-key", excfg.WorkerKey,
		"--report-server", excfg.ReportURL,
		"--license-token", excfg.LicenseToken,
		"--max-cpu-percent", strconv.Itoa(caps.CPUPct),
		"--max-memory", strconv.Itoa(caps.MemMiB)+"MiB",
	)
	cmd.Stdout = newJobWriter(jobID, "out")
	cmd.Stderr = newJobWriter(jobID, "err")

	if err := cmd.Start(); err != nil {
		log.Printf("dispatcher: spawn job %s: %v", jobID, err)
		return
	}
	d.mu.Lock()
	d.running[jobID] = cmd
	d.mu.Unlock()

	go func() {
		defer func() {
			d.mu.Lock()
			delete(d.running, jobID)
			d.mu.Unlock()
		}()
		if err := cmd.Wait(); err != nil {
			log.Printf("dispatcher: job %s: %v", jobID, err)
		}
	}()
}

func (d *Dispatcher) gracefulShutdown() {
	deadline := time.After(30 * time.Second)
	poll := time.NewTicker(500 * time.Millisecond)
	defer poll.Stop()
	for {
		d.mu.Lock()
		n := len(d.running)
		d.mu.Unlock()
		if n == 0 {
			return
		}
		select {
		case <-deadline:
			d.mu.Lock()
			for _, cmd := range d.running {
				if cmd.Process != nil {
					_ = cmd.Process.Signal(syscall.SIGTERM)
				}
			}
			d.mu.Unlock()
			return
		case <-poll.C:
		}
	}
}

// sampleHostLoad returns current CPU percent and free RAM in MiB.
// On error returns conservative values (spawn allowed with tight caps).
func sampleHostLoad() (cpuPct float64, freeRAMMiB int64) {
	pcents, err := cpu.Percent(200*time.Millisecond, false)
	if err != nil || len(pcents) == 0 {
		return 50, 2048 // conservative unknown
	}
	vm, err := mem.VirtualMemory()
	if err != nil {
		return pcents[0], 2048
	}
	return pcents[0], int64(vm.Available) / (1024 * 1024)
}

// jobWriter is a log.Writer that prefixes output with the job ID.
type jobWriter struct {
	jobID  uuid.UUID
	stream string
}

func newJobWriter(jobID uuid.UUID, stream string) *jobWriter {
	return &jobWriter{jobID: jobID, stream: stream}
}

func (w *jobWriter) Write(p []byte) (int, error) {
	log.Printf("dispatcher[%s][%s]: %s", w.jobID, w.stream, p)
	return len(p), nil
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./pkg/manageserver/scanjobs/... -run TestComputeCaps -v
```
Expected: all PASS.

- [ ] **Step 6: Full package test**

```bash
go test ./pkg/manageserver/scanjobs/...
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/manageserver/scanjobs/dispatcher.go \
        pkg/manageserver/scanjobs/dispatcher_test.go \
        go.mod go.sum
git commit -m "feat(scanjobs): Dispatcher — gopsutil dynamic resource caps + subprocess spawner"
```

---

## Task 10: Server wiring — remove PortScanFunc, add WorkerKey + Dispatcher

**Files:**
- Modify: `pkg/manageserver/server.go`

- [ ] **Step 1: Find the Config struct and add WorkerKey**

Search `server.go` for the server `Config` struct. Add:
```go
// WorkerKey is the shared secret that authenticates triton-portscan
// and other external scan binaries against the Worker API (/v1/worker/).
WorkerKey string
```

- [ ] **Step 2: Remove PortScanFunc wiring and import**

In the `startScannerPipeline` (or equivalent) function around line 478:

Before:
```go
orch := scanjobs.NewOrchestrator(scanjobs.OrchestratorConfig{
    Store:        s.scanjobsStore,
    ResultStore:  s.resultsStore,
    Parallelism:  s.cfg.Parallelism,
    ScanFunc:     scanjobs.NewScanFunc(s.hostsStore),
    PortScanFunc: portscan.NewPortScanFunc(s.hostsStore),
    SourceID:     instanceID,
})
```

After:
```go
orch := scanjobs.NewOrchestrator(scanjobs.OrchestratorConfig{
    Store:       s.scanjobsStore,
    ResultStore: s.resultsStore,
    Parallelism: s.cfg.Parallelism,
    ScanFunc:    scanjobs.NewScanFunc(s.hostsStore),
    SourceID:    instanceID,
})
```

Remove the `portscan` import from `server.go` if it is no longer used.

- [ ] **Step 3: Add Dispatcher startup**

After the orchestrator goroutine block, add:

```go
if s.cfg.WorkerKey != "" {
    manageURL := "http://127.0.0.1:" + strconv.Itoa(s.cfg.Port) // self-reference
    disp := scanjobs.NewDispatcher(scanjobs.DispatcherConfig{
        Store: s.scanjobsStore,
        Executors: map[string]scanjobs.ExecutorConfig{
            "port_survey": {
                BinaryPath:   "triton-portscan",
                ManageURL:    manageURL,
                WorkerKey:    s.cfg.WorkerKey,
                ReportURL:    s.cfg.ReportURL,
                LicenseToken: s.cfg.LicenseToken,
            },
        },
    })
    wg.Add(1)
    go func() {
        defer wg.Done()
        disp.Run(ctx)
    }()
}
```

Ensure `s.cfg.Port`, `s.cfg.ReportURL`, and `s.cfg.LicenseToken` exist in the Config struct — add them if missing.

- [ ] **Step 4: Mount Worker routes**

Find where admin routes are mounted (typically in the router setup). Add:

```go
workerHandlers := scanjobs.NewWorkerHandlers(s.scanjobsStore)
r.Route("/v1/worker", func(r chi.Router) {
    scanjobs.MountWorkerRoutes(r, workerHandlers, s.cfg.WorkerKey)
})
```

- [ ] **Step 5: Build the full binary**

```bash
go build ./...
```
Expected: PASS — no undefined symbol errors.

- [ ] **Step 6: Run full test suite**

```bash
go test ./...
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/manageserver/server.go
git commit -m "feat(manageserver): wire Dispatcher + Worker API; remove in-process PortScanFunc"
```

---

## Task 11: `cmd/triton-portscan/main.go` — binary entry point

**Files:**
- Create: `cmd/triton-portscan/main.go`

- [ ] **Step 1: Create the file**

```go
// cmd/triton-portscan/main.go
// triton-portscan is a short-lived subprocess spawned by the manage server
// dispatcher. It claims one port survey job, scans the target host via
// fingerprintx, submits the ScanResult directly to the report server,
// then marks the job complete and exits.
//
// Exit codes:
//   0 — success, or job not found / already claimed (clean)
//   1 — scan or submission failed (job marked failed)
//   2 — startup error (bad flags, limits error)
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/runtime/limits"
	"github.com/amiryahaya/triton/pkg/manageserver/portscan"
	"github.com/amiryahaya/triton/pkg/scanrunner"
)

func main() {
	os.Exit(run())
}

func run() int {
	jobID := flag.String("job-id", "", "UUID of the job to claim (required)")
	manageServer := flag.String("manage-server", "", "Manage server base URL (required)")
	workerKey := flag.String("worker-key", "", "X-Worker-Key secret (required)")
	reportServer := flag.String("report-server", "", "Report server base URL (required)")
	licenseToken := flag.String("license-token", "", "Report server auth token (required)")
	maxCPUPct := flag.Int("max-cpu-percent", 0, "CPU cap 0–100 (0 = unlimited)")
	maxMemory := flag.String("max-memory", "", "Memory cap e.g. 256MiB (empty = unlimited)")
	flag.Parse()

	if *jobID == "" || *manageServer == "" || *workerKey == "" ||
		*reportServer == "" || *licenseToken == "" {
		log.Println("triton-portscan: missing required flags")
		flag.Usage()
		return 2
	}

	id, err := uuid.Parse(*jobID)
	if err != nil {
		log.Printf("triton-portscan: invalid --job-id: %v", err)
		return 2
	}

	lim := limits.Limits{MaxCPUPercent: *maxCPUPct}
	if *maxMemory != "" {
		lim.MaxMemoryBytes = parseMemory(*maxMemory)
		if lim.MaxMemoryBytes == 0 {
			log.Printf("triton-portscan: invalid --max-memory %q", *maxMemory)
			return 2
		}
	}
	ctx, cleanup := lim.Apply(context.Background())
	defer cleanup()

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	manage := scanrunner.NewManageClient(*manageServer, *workerKey)
	report := scanrunner.NewReportClient(*reportServer, *licenseToken)
	scanner := portscan.NewFingerprintxScanner()

	if err := scanrunner.RunOne(ctx, id, manage, report, scanner); err != nil {
		log.Printf("triton-portscan: %v", err)
		return 1
	}
	return 0
}

// parseMemory parses strings like "256MiB", "512MB", "1GiB" into bytes.
// Returns 0 on parse error.
func parseMemory(s string) int64 {
	var n int64
	var unit string
	if _, err := fmt.Sscanf(s, "%d%s", &n, &unit); err != nil {
		return 0
	}
	switch unit {
	case "MiB", "MB":
		return n * 1024 * 1024
	case "GiB", "GB":
		return n * 1024 * 1024 * 1024
	case "KiB", "KB":
		return n * 1024
	}
	return 0
}
```

Add the missing `"fmt"` import.

- [ ] **Step 2: Build the binary**

```bash
go build -o bin/triton-portscan ./cmd/triton-portscan/
```
Expected: `bin/triton-portscan` created.

- [ ] **Step 3: Smoke test — bad flags**

```bash
./bin/triton-portscan --help
./bin/triton-portscan; echo "exit: $?"
```
Expected: exits with code 2 when no flags given.

- [ ] **Step 4: Commit**

```bash
git add cmd/triton-portscan/main.go
git commit -m "feat(triton-portscan): standalone binary — claim → scan → submit → exit"
```

---

## Task 12: Makefile + build targets

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add triton-portscan to build targets**

Find the `build` target (typically `go build -o bin/triton ./...` or similar). Add a companion target:

```makefile
build-portscan: ## Build triton-portscan binary
	go build -o bin/triton-portscan ./cmd/triton-portscan/

build-all: build build-portscan build-licenseserver ## Build all binaries
```

Also ensure the cross-compile targets in `build-all` include `triton-portscan` if the pattern uses `./cmd/...`.

- [ ] **Step 2: Verify**

```bash
make build-portscan
ls -la bin/triton-portscan
```
Expected: binary present.

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "build: add triton-portscan Makefile target"
```

---

## Task 13: Frontend — port override field + comprehensive warning

**Files:**
- Modify: `pkg/manageserver/ui/src/components/PortSurveyEnqueueForm.vue`

- [ ] **Step 1: Read the current form**

```bash
cat pkg/manageserver/ui/src/components/PortSurveyEnqueueForm.vue
```

Identify:
- Where the profile select is rendered
- Where the submit payload is built (the `enqueuePortSurvey` store action call)

- [ ] **Step 2: Add port override field and comprehensive warning**

Below the profile `<select>` element, add:

```html
<!-- Comprehensive profile warning -->
<div v-if="form.profile === 'comprehensive'" class="form-warning">
  Comprehensive scan sends up to 200 TCP connections/second per host.
  Schedule during maintenance windows for sensitive targets.
</div>

<!-- Optional port override -->
<div class="form-group">
  <label for="portOverride">Specific ports (optional)</label>
  <input
    id="portOverride"
    v-model="form.portOverride"
    type="text"
    placeholder="e.g. 80,443,8080  (leave blank for profile default)"
    class="form-control"
  />
</div>
```

- [ ] **Step 3: Add `portOverride` to reactive form data**

In the `data()` / `ref` section:
```js
portOverride: '',
```

- [ ] **Step 4: Parse and include in submit payload**

In the submit handler (before calling the store action):

```js
const portOverride = this.form.portOverride
  .split(',')
  .map(s => parseInt(s.trim(), 10))
  .filter(n => !isNaN(n) && n > 0 && n <= 65535)

await store.enqueuePortSurvey({
  host_ids: this.form.hostIDs,
  profile: this.form.profile,
  scheduled_at: this.form.scheduledAt || null,
  port_override: portOverride.length > 0 ? portOverride : undefined,
})
```

- [ ] **Step 5: Add CSS for warning**

In the `<style>` section:
```css
.form-warning {
  background: #fff3cd;
  border: 1px solid #ffc107;
  border-radius: 4px;
  padding: 8px 12px;
  margin-bottom: 12px;
  font-size: 0.875rem;
  color: #664d03;
}
```

- [ ] **Step 6: Build the frontend**

```bash
cd pkg/manageserver/ui && npm run build
```
Expected: successful build, `dist/` updated.

- [ ] **Step 7: Start the dev server and verify**

```bash
cd pkg/manageserver/ui && npm run dev
```
Open `http://localhost:5173`, navigate to ScanJobs → Port Survey. Verify:
- Specific ports field appears
- Warning banner appears when "Comprehensive" is selected
- Warning disappears when another profile is selected

- [ ] **Step 8: Commit**

```bash
git add pkg/manageserver/ui/src/components/PortSurveyEnqueueForm.vue \
        pkg/manageserver/ui/dist/
git commit -m "feat(ui): port override field + comprehensive scan warning in PortSurveyEnqueueForm"
```

---

## Self-Review Checklist

After completing all tasks, verify:

- [ ] `go build ./...` — no errors
- [ ] `go test ./...` — all unit tests pass
- [ ] `go test -tags integration ./...` — integration tests pass (requires Postgres)
- [ ] `make lint` — no lint warnings
- [ ] `bin/triton-portscan --help` — flags documented
- [ ] Worker API endpoints return correct status codes (200/204/404/409)
- [ ] Dispatcher defers spawning when CPU > 70% AND RAM < 1 GB
- [ ] `ClaimNext` no longer picks up `port_survey` jobs (verified by `TestClaimNext_FilesystemOnly`)
- [ ] Frontend: comprehensive warning visible, port override field accepts comma-separated ports
