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

func buildManageServer(t *testing.T, jobID, hostID uuid.UUID, completedPtr, failPtr *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/worker/jobs/"+jobID.String()+"/complete":
			if completedPtr != nil {
				*completedPtr = true
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/worker/jobs/"+jobID.String()+"/fail":
			if failPtr != nil {
				*failPtr = true
			} else {
				t.Errorf("unexpected fail call: %s %s", r.Method, r.URL.Path)
			}
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

	manageSrv := buildManageServer(t, jobID, hostID, &completed, nil)
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

func TestRunOne_TargetHasCredentialField(t *testing.T) {
	target := scanrunner.Target{
		IP:      "10.0.0.1",
		Profile: "standard",
		Credential: &scanrunner.CredentialSecret{
			Username: "ubuntu",
			Password: "pw",
		},
		AccessPort: 22,
	}
	if target.Credential == nil {
		t.Error("Credential field is nil")
	}
	if target.AccessPort != 22 {
		t.Errorf("AccessPort: got %d, want 22", target.AccessPort)
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
