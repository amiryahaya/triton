package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPollScanJob_ReturnsJob(t *testing.T) {
	secretRef := "sr-123"
	payload := ScanJobPayload{
		ID:                  "job-1",
		ScanProfile:         "standard",
		CredentialSecretRef: &secretRef,
		CredentialAuthType:  "ssh-password",
		Hosts: []ScanHostTarget{
			{ID: "h1", Address: "10.0.0.1", Port: 22, Hostname: "db-01", OS: "linux"},
		},
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/engine/scans/poll" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer ts.Close()

	c := newDirectClient(ts)
	got, err := c.PollScanJob(context.Background())
	if err != nil {
		t.Fatalf("PollScanJob: %v", err)
	}
	if got == nil || got.ID != "job-1" || got.ScanProfile != "standard" {
		t.Errorf("payload = %+v", got)
	}
	if got.CredentialSecretRef == nil || *got.CredentialSecretRef != "sr-123" {
		t.Errorf("secret ref = %v", got.CredentialSecretRef)
	}
	if len(got.Hosts) != 1 || got.Hosts[0].ID != "h1" {
		t.Errorf("hosts = %+v", got.Hosts)
	}
}

func TestPollScanJob_204Empty(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	got, err := c.PollScanJob(context.Background())
	if err != nil {
		t.Fatalf("PollScanJob: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestPollScanJob_BadStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	if _, err := c.PollScanJob(context.Background()); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestSubmitScanProgress_PostsExpectedBody(t *testing.T) {
	var gotPath string
	var gotBody []ScanProgressUpdate
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	updates := []ScanProgressUpdate{
		{HostID: "h1", Status: "completed", FindingsCount: 42},
		{HostID: "h2", Status: "failed", Error: "timeout"},
	}
	if err := c.SubmitScanProgress(context.Background(), "job-1", updates); err != nil {
		t.Fatalf("SubmitScanProgress: %v", err)
	}
	if gotPath != "/api/v1/engine/scans/job-1/progress" {
		t.Errorf("path = %q", gotPath)
	}
	if len(gotBody) != 2 || gotBody[0].FindingsCount != 42 || gotBody[1].Status != "failed" {
		t.Errorf("body = %+v", gotBody)
	}
}

func TestSubmitScanFindings_EmbedsRawScanResult(t *testing.T) {
	var gotPath string
	var gotBody submitScanFindingsBody
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)

	// Arbitrary JSON blob the engine will forward verbatim.
	raw := []byte(`{"id":"scan-1","findings":[{"type":"cert"}]}`)
	if err := c.SubmitScanFindings(context.Background(), "job-1", "h1", raw, 1); err != nil {
		t.Fatalf("SubmitScanFindings: %v", err)
	}
	if gotPath != "/api/v1/engine/scans/job-1/submit" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody.HostID != "h1" || gotBody.FindingsCount != 1 {
		t.Errorf("body = %+v", gotBody)
	}
	// Round-trip the RawMessage and confirm it still decodes.
	var inner map[string]any
	if err := json.Unmarshal(gotBody.ScanResult, &inner); err != nil {
		t.Fatalf("inner decode: %v (raw=%s)", err, gotBody.ScanResult)
	}
	if inner["id"] != "scan-1" {
		t.Errorf("inner = %+v", inner)
	}
}

func TestFinishScanJob_PostsStatusAndError(t *testing.T) {
	var gotPath string
	var gotBody map[string]string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	if err := c.FinishScanJob(context.Background(), "job-1", "failed", "2 of 3 hosts failed"); err != nil {
		t.Fatalf("FinishScanJob: %v", err)
	}
	if gotPath != "/api/v1/engine/scans/job-1/finish" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody["status"] != "failed" || gotBody["error"] != "2 of 3 hosts failed" {
		t.Errorf("body = %+v", gotBody)
	}
}

func TestFinishScanJob_OmitsEmptyError(t *testing.T) {
	var gotBody map[string]string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	c := newDirectClient(ts)
	if err := c.FinishScanJob(context.Background(), "job-1", "completed", ""); err != nil {
		t.Fatalf("FinishScanJob: %v", err)
	}
	if _, has := gotBody["error"]; has {
		t.Errorf("expected no error field when empty, got %+v", gotBody)
	}
	if gotBody["status"] != "completed" {
		t.Errorf("status = %q", gotBody["status"])
	}
}
