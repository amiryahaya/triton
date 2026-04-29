// pkg/scanrunner/runner_test.go
package scanrunner_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestRunOne_TargetHasCredentialField(t *testing.T) {
	target := scanrunner.Target{
		IP:      "10.0.0.1",
		Profile: "standard",
		Credential: &scanrunner.CredentialSecret{
			Username: "ubuntu",
			Password: "pw",
		},
		SSHPort: 22,
	}
	if target.Credential == nil {
		t.Error("Credential field is nil")
	}
	if target.SSHPort != 22 {
		t.Errorf("SSHPort: got %d, want 22", target.SSHPort)
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

// capturingScanner captures the Target it receives so tests can inspect it.
type capturingScanner struct {
	received scanrunner.Target
}

func (s *capturingScanner) Scan(_ context.Context, t scanrunner.Target, _ func(scanrunner.Finding)) error {
	s.received = t
	return nil
}

func TestRunOne_CredentialFetched(t *testing.T) {
	jobID := uuid.New()
	hostID := uuid.New()
	credID := uuid.New()

	scanner := &capturingScanner{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/claim"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"job_id":          jobID,
				"host_id":         hostID,
				"profile":         "standard",
				"credentials_ref": credID,
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/hosts/"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"id": hostID, "hostname": "web-01", "ip": "10.0.0.1", "access_port": 22,
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/credentials/"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"username": "ubuntu", "password": "secret",
			})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/heartbeat"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/submit"):
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	manage := scanrunner.NewManageClient(srv.URL, "key")

	if err := scanrunner.RunOne(context.Background(), jobID, manage, scanner); err != nil {
		t.Fatalf("RunOne: %v", err)
	}
	if scanner.received.Credential == nil {
		t.Fatal("Credential is nil — RunOne did not fetch the credential")
	}
	if scanner.received.Credential.Username != "ubuntu" {
		t.Errorf("Credential.Username = %q, want %q", scanner.received.Credential.Username, "ubuntu")
	}
}
