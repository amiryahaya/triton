//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// E1: RegisterDefaultModules → 16 workers → no data races
func TestConcurrent_MultiModuleScan(t *testing.T) {
	cfg := config.Load("comprehensive")
	cfg.Workers = 16
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 5},
	}
	// Limit to file-based modules only (no network/process)
	cfg.Modules = []string{
		"certificates", "keys", "libraries", "binaries",
		"scripts", "webapp", "configs", "packages",
	}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	progressCh := make(chan scanner.Progress, 200)
	result := eng.Scan(context.Background(), progressCh)

	require.NotNil(t, result)
	assert.NotEmpty(t, result.Findings)
	assert.Equal(t, len(result.Findings), result.Summary.TotalFindings)
}

// E2: 10 agent goroutines → all scans saved, no duplicates
func TestConcurrent_MultiAgentSubmit(t *testing.T) {
	serverURL, _ := requireServer(t)

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	scans := make([]*model.ScanResult, n)

	for i := 0; i < n; i++ {
		scans[i] = makeScanResult("", "concurrent-host", 20)
	}

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client := agent.New(serverURL)
			_, errs[idx] = client.Submit(scans[idx])
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "agent %d should submit without error", i)
	}

	// Verify all scans exist
	for i := 0; i < n; i++ {
		got := getScan(t, serverURL, scans[i].ID)
		assert.Equal(t, 20, len(got.Findings), "agent %d scan should have all findings", i)
	}
}

// E3: One goroutine scanning, another reading store → no deadlocks
func TestConcurrent_ParallelScanAndRead(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	// Pre-populate some data
	seedIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		s := makeScanResult("", "rw-host", 10)
		seedIDs[i] = s.ID
		require.NoError(t, db.SaveScan(ctx, s))
	}

	var wg sync.WaitGroup
	writeErrs := make([]error, 5)
	readErrs := make([]error, 5)

	// Writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s := makeScanResult("", "rw-host", 10)
			writeErrs[idx] = db.SaveScan(ctx, s)
		}(i)
	}

	// Readers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, readErrs[idx] = db.GetScan(ctx, seedIDs[idx], "")
		}(i)
	}

	wg.Wait()

	for i := 0; i < 5; i++ {
		assert.NoError(t, writeErrs[i], "writer %d should succeed", i)
		assert.NoError(t, readErrs[i], "reader %d should succeed", i)
	}
}

// E4: 50 concurrent API requests (GET/POST mix) → all valid responses
func TestConcurrent_ServerUnderLoad(t *testing.T) {
	serverURL, _ := requireServer(t)

	// Pre-populate
	seedIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		s := makeScanResult("", "load-host", 10)
		seedIDs[i] = s.ID
		submitScan(t, serverURL, s)
	}

	const n = 50
	var wg sync.WaitGroup
	results := make([]int, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			var resp *http.Response
			var err error

			switch idx % 5 {
			case 0: // List scans
				resp, err = http.Get(serverURL + "/api/v1/scans")
			case 1: // Get specific scan
				resp, err = http.Get(serverURL + "/api/v1/scans/" + seedIDs[idx%5])
			case 2: // Health
				resp, err = http.Get(serverURL + "/api/v1/health")
			case 3: // Aggregate
				resp, err = http.Get(serverURL + "/api/v1/aggregate")
			case 4: // Machines
				resp, err = http.Get(serverURL + "/api/v1/machines")
			}

			if err != nil {
				results[idx] = -1
				return
			}
			resp.Body.Close()
			results[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	for i, code := range results {
		assert.True(t, code >= 200 && code < 500,
			"request %d should return valid status, got %d", i, code)
	}
}

// E5: 10 writers + 10 readers → no errors, no data corruption
func TestConcurrent_StoreConcurrentWrites(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	const writers = 10
	const readers = 10

	// Pre-populate for readers
	seedIDs := make([]string, readers)
	for i := 0; i < readers; i++ {
		s := makeScanResult("", "store-host", 5)
		seedIDs[i] = s.ID
		require.NoError(t, db.SaveScan(ctx, s))
	}

	var wg sync.WaitGroup
	writeErrs := make([]error, writers)
	readErrs := make([]error, readers)

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s := makeScanResult("", "store-host", 5)
			writeErrs[idx] = db.SaveScan(ctx, s)
		}(i)
	}

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			got, err := db.GetScan(ctx, seedIDs[idx], "")
			readErrs[idx] = err
			if err == nil {
				assert.Equal(t, 5, len(got.Findings), "reader %d should get correct finding count", idx)
			}
		}(i)
	}

	wg.Wait()

	for i := 0; i < writers; i++ {
		assert.NoError(t, writeErrs[i], "writer %d should succeed", i)
	}
	for i := 0; i < readers; i++ {
		assert.NoError(t, readErrs[i], "reader %d should succeed", i)
	}
}
