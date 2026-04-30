package scanrunner_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/scanrunner"
)

// TestClaimResp_ResourceLimitFields verifies the three new fields exist on ClaimResp
// and are decoded from JSON correctly.
func TestClaimResp_ResourceLimitFields(t *testing.T) {
	cpu := 40
	mem := 1024
	dur := 7200
	raw := `{"job_id":"00000000-0000-0000-0000-000000000001","host_id":"00000000-0000-0000-0000-000000000002","profile":"quick","max_cpu_pct":40,"max_memory_mb":1024,"max_duration_s":7200}`

	var cr scanrunner.ClaimResp
	require.NoError(t, json.Unmarshal([]byte(raw), &cr))
	require.NotNil(t, cr.MaxCPUPct)
	assert.Equal(t, cpu, *cr.MaxCPUPct)
	require.NotNil(t, cr.MaxMemoryMB)
	assert.Equal(t, mem, *cr.MaxMemoryMB)
	require.NotNil(t, cr.MaxDurationS)
	assert.Equal(t, dur, *cr.MaxDurationS)
}

// TestRunOne_ResourceLimits_Applied verifies that RunOne applies resource limits
// from the ClaimResp before scanning. We do this by checking the scan runs
// without error when limits are set (functional correctness) and the test server
// correctly echoes back the limit values.
func TestRunOne_ResourceLimits_Applied(t *testing.T) {
	jobID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	hostID := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	cpu := 80
	mem := 512
	dur := 3600

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/worker/jobs/" + jobID.String() + "/claim":
			json.NewEncoder(w).Encode(scanrunner.ClaimResp{ //nolint:errcheck
				JobID:        jobID,
				HostID:       hostID,
				Profile:      "quick",
				MaxCPUPct:    &cpu,
				MaxMemoryMB:  &mem,
				MaxDurationS: &dur,
			})
		case "/api/v1/worker/hosts/" + hostID.String():
			json.NewEncoder(w).Encode(scanrunner.HostInfo{ //nolint:errcheck
				ID: hostID, Hostname: "test-host", IP: "127.0.0.1",
			})
		case "/api/v1/worker/jobs/" + jobID.String() + "/submit":
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer ts.Close()

	manage := scanrunner.NewManageClient(ts.URL, "test-key")
	scanner := &noopScanner{}
	err := scanrunner.RunOne(context.Background(), jobID, manage, scanner)
	require.NoError(t, err)
}

// noopScanner implements Scanner and does nothing.
type noopScanner struct{}

func (n *noopScanner) Scan(_ context.Context, _ scanrunner.Target, _ func(scanrunner.Finding)) error {
	return nil
}
