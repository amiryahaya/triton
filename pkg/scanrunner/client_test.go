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

func TestManageClient_SubmitResult(t *testing.T) {
	jobID := uuid.New()
	var submitted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/api/v1/worker/jobs/" + jobID.String() + "/submit"
		if r.Method != http.MethodPost || r.URL.Path != wantPath {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Worker-Key"); got != "wk-secret" {
			t.Errorf("X-Worker-Key: got %q, want wk-secret", got)
		}
		submitted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := scanrunner.NewManageClient(srv.URL, "wk-secret")
	if err := c.SubmitResult(context.Background(), jobID, &model.ScanResult{ID: uuid.NewString()}); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}
	if !submitted {
		t.Error("manage server submit endpoint was not called")
	}
}
