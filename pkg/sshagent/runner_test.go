package sshagent_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/sshagent"
)

func TestRunOne_SubmitsResult(t *testing.T) {
	jobID := uuid.New()

	var submitted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/worker/jobs/" + jobID.String():
			json.NewEncoder(w).Encode(sshagent.JobPayload{
				ID:          jobID.String(),
				ScanProfile: "standard",
				TargetHost:  "192.168.1.1",
				Hostname:    "server1",
				Credentials: sshagent.CredPayload{Username: "root", Password: "pass"},
			})
		case "/api/v1/worker/jobs/" + jobID.String() + "/submit":
			submitted, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	mc := sshagent.NewClient(srv.URL, "worker-key")

	stubScanner := &stubSSHScanner{result: &model.ScanResult{
		ID: uuid.NewString(),
		Metadata: model.ScanMetadata{Hostname: "server1"},
	}}

	err := sshagent.RunOne(context.Background(), jobID, mc, stubScanner)
	if err != nil {
		t.Fatal(err)
	}
	if len(submitted) == 0 {
		t.Error("expected result to be submitted")
	}
	var got model.ScanResult
	if err := json.Unmarshal(submitted, &got); err != nil {
		t.Errorf("submitted body is not valid ScanResult: %v", err)
	}
}

type stubSSHScanner struct{ result *model.ScanResult }

func (s *stubSSHScanner) Scan(_ context.Context, _, _ string, _ sshagent.Credentials, _ string) (*model.ScanResult, error) {
	return s.result, nil
}
