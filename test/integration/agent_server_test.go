//go:build integration

package integration_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/model"
)

// C1: agent.Submit → GET /scans/{id} → findings match
func TestAgent_SubmitAndRetrieve(t *testing.T) {
	serverURL, _ := requireServer(t)

	client := agent.New(serverURL, "")
	scan := makeScanResult("agent-submit-1", "agent-host", 10)

	resp, err := client.Submit(scan)
	require.NoError(t, err)
	assert.Equal(t, scan.ID, resp.ID)

	got := getScan(t, serverURL, scan.ID)
	assert.Equal(t, scan.ID, got.ID)
	assert.Equal(t, len(scan.Findings), len(got.Findings))
}

// C2: Start server → agent.Healthcheck → no error
func TestAgent_HealthcheckOK(t *testing.T) {
	serverURL, _ := requireServer(t)

	client := agent.New(serverURL, "")
	err := client.Healthcheck()
	assert.NoError(t, err)
}

// C3: No server → agent.Healthcheck → error
func TestAgent_HealthcheckServerDown(t *testing.T) {
	client := agent.New("http://127.0.0.1:19999", "")
	err := client.Healthcheck()
	assert.Error(t, err)
}

// C4: Server with auth → agent Submit with correct key → 201
func TestAgent_AuthSuccess(t *testing.T) {
	serverURL, _ := requireServerWithAuth(t, []string{"agent-key-good"})

	client := agent.New(serverURL, "agent-key-good")
	scan := makeScanResult("agent-auth-ok", "auth-host", 5)

	resp, err := client.Submit(scan)
	require.NoError(t, err)
	assert.Equal(t, scan.ID, resp.ID)
}

// C5: Server with auth → agent Submit with wrong key → error
func TestAgent_AuthFailure(t *testing.T) {
	serverURL, _ := requireServerWithAuth(t, []string{"agent-key-good"})

	client := agent.New(serverURL, "wrong-key")
	scan := makeScanResult("agent-auth-fail", "auth-host", 5)

	_, err := client.Submit(scan)
	assert.Error(t, err, "should fail with wrong API key")
}

// C6: 1000-finding scan → Submit → Retrieve → all findings preserved
func TestAgent_LargeScan(t *testing.T) {
	serverURL, _ := requireServer(t)

	client := agent.New(serverURL, "")
	scan := makeScanResult("agent-large", "large-host", 1000)

	resp, err := client.Submit(scan)
	require.NoError(t, err)
	assert.Equal(t, scan.ID, resp.ID)

	got := getScan(t, serverURL, scan.ID)
	assert.Equal(t, 1000, len(got.Findings), "all 1000 findings should be preserved")
}

// C7: 5 goroutines submitting concurrently → all saved correctly
func TestAgent_ParallelSubmissions(t *testing.T) {
	serverURL, _ := requireServer(t)

	const n = 5
	var wg sync.WaitGroup
	errs := make([]error, n)
	scans := make([]*model.ScanResult, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		scans[i] = makeScanResult("", "parallel-host", 10)
		go func(idx int) {
			defer wg.Done()
			client := agent.New(serverURL, "")
			_, errs[idx] = client.Submit(scans[idx])
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "agent %d should submit without error", i)
	}

	// Verify all scans were saved
	for i := 0; i < n; i++ {
		got := getScan(t, serverURL, scans[i].ID)
		assert.Equal(t, 10, len(got.Findings))
	}
}
