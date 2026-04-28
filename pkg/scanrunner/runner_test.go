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

func TestRunOne_Success(t *testing.T) {
	jobID, hostID := uuid.New(), uuid.New()
	var submitted bool

	manageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/worker/jobs/"+jobID.String()+"/claim":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(scanrunner.ClaimResp{
				JobID: jobID, HostID: hostID, Profile: "standard",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/worker/hosts/"+hostID.String():
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(scanrunner.HostInfo{
				ID: hostID, Hostname: "host1", IP: "192.168.1.50",
			})
		case r.Method == http.MethodPatch:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/worker/jobs/"+jobID.String()+"/submit":
			submitted = true
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected manage request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer manageSrv.Close()

	manage := scanrunner.NewManageClient(manageSrv.URL, "key")
	scanner := &stubScanner{findings: []scanrunner.Finding{{Port: 443, Service: "https", Banner: "nginx"}}}

	if err := scanrunner.RunOne(context.Background(), jobID, manage, scanner); err != nil {
		t.Fatalf("RunOne: %v", err)
	}
	if !submitted {
		t.Error("result not submitted to manage server")
	}
}

func TestRunOne_JobGone_ExitsClean(t *testing.T) {
	manageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer manageSrv.Close()

	manage := scanrunner.NewManageClient(manageSrv.URL, "key")
	err := scanrunner.RunOne(context.Background(), uuid.New(), manage, &stubScanner{})
	if err != nil {
		t.Fatalf("expected nil for job-not-found, got: %v", err)
	}
}

func TestRunOne_ScanError_CallsFail(t *testing.T) {
	jobID, hostID := uuid.New(), uuid.New()
	var failCalled bool

	manageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/worker/jobs/"+jobID.String()+"/claim":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(scanrunner.ClaimResp{JobID: jobID, HostID: hostID, Profile: "quick"})
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(scanrunner.HostInfo{ID: hostID, IP: "10.0.0.1"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/worker/jobs/"+jobID.String()+"/fail":
			failCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer manageSrv.Close()

	manage := scanrunner.NewManageClient(manageSrv.URL, "key")
	scanner := &stubScanner{err: errors.New("port scan failed")}

	err := scanrunner.RunOne(context.Background(), jobID, manage, scanner)
	if err == nil {
		t.Fatal("expected non-nil error from scan failure")
	}
	if !failCalled {
		t.Error("Fail was not called on manage server after scan error")
	}
}
