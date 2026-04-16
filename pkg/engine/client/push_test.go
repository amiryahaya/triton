package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPollPushJob_ReturnsJob(t *testing.T) {
	payload := PushJobPayload{
		ID:                  "pj-1",
		CredentialSecretRef: "sr-1",
		CredentialAuthType:  "bootstrap-admin",
		Hosts: []PushHostTarget{
			{ID: "h1", Address: "10.0.0.1", Port: 22, Hostname: "web-01"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c := &Client{PortalURL: srv.URL, HTTP: srv.Client()}
	got, err := c.PollPushJob(context.Background())
	if err != nil {
		t.Fatalf("PollPushJob: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil job")
	}
	if got.ID != "pj-1" {
		t.Errorf("ID = %q, want pj-1", got.ID)
	}
	if len(got.Hosts) != 1 {
		t.Errorf("Hosts len = %d, want 1", len(got.Hosts))
	}
}

func TestPollPushJob_204Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &Client{PortalURL: srv.URL, HTTP: srv.Client()}
	got, err := c.PollPushJob(context.Background())
	if err != nil {
		t.Fatalf("PollPushJob: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestPollPushJob_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &Client{PortalURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.PollPushJob(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestSubmitPushProgress_PostsExpectedBody(t *testing.T) {
	var gotBody []PushProgressUpdate
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &Client{PortalURL: srv.URL, HTTP: srv.Client()}
	updates := []PushProgressUpdate{
		{HostID: "h1", Status: "completed", Fingerprint: "fp1"},
	}
	if err := c.SubmitPushProgress(context.Background(), "pj-1", updates); err != nil {
		t.Fatalf("SubmitPushProgress: %v", err)
	}
	if len(gotBody) != 1 || gotBody[0].HostID != "h1" {
		t.Errorf("gotBody = %+v", gotBody)
	}
}

func TestFinishPushJob_PostsStatusAndError(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &Client{PortalURL: srv.URL, HTTP: srv.Client()}
	if err := c.FinishPushJob(context.Background(), "pj-1", "failed", "2 of 3 hosts failed"); err != nil {
		t.Fatalf("FinishPushJob: %v", err)
	}
	if gotBody["status"] != "failed" {
		t.Errorf("status = %q", gotBody["status"])
	}
	if gotBody["error"] != "2 of 3 hosts failed" {
		t.Errorf("error = %q", gotBody["error"])
	}
}

func TestFinishPushJob_OmitsEmptyError(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &Client{PortalURL: srv.URL, HTTP: srv.Client()}
	if err := c.FinishPushJob(context.Background(), "pj-1", "completed", ""); err != nil {
		t.Fatalf("FinishPushJob: %v", err)
	}
	if _, has := gotBody["error"]; has {
		t.Errorf("expected no error key, got %q", gotBody["error"])
	}
}

func TestRegisterAgent_PostsExpectedBody(t *testing.T) {
	var gotBody registerAgentBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &Client{PortalURL: srv.URL, HTTP: srv.Client()}
	if err := c.RegisterAgent(context.Background(), "h1", "fp123", "1.0.0"); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if gotBody.HostID != "h1" {
		t.Errorf("HostID = %q, want h1", gotBody.HostID)
	}
	if gotBody.CertFingerprint != "fp123" {
		t.Errorf("CertFingerprint = %q, want fp123", gotBody.CertFingerprint)
	}
	if gotBody.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", gotBody.Version)
	}
}
