package scanner

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() *config.Config {
	return &config.Config{
		Profile: "quick",
		Workers: 4,
		ScanTargets: []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: "/tmp/test", Depth: 3},
		},
	}
}

func makeFinding(id string) *model.Finding {
	return &model.Finding{
		ID:       id,
		Category: 5,
		Source:   model.FindingSource{Type: "file", Path: "/test/" + id},
		Module:   "mock",
	}
}

func TestNewEngine(t *testing.T) {
	eng := New(testConfig())

	require.NotNil(t, eng)
	assert.Empty(t, eng.modules)
}

func TestRegisterModule(t *testing.T) {
	eng := New(testConfig())

	mock := &MockModule{name: "test-module"}
	eng.RegisterModule(mock)

	assert.Len(t, eng.modules, 1)
	assert.Equal(t, "test-module", eng.modules[0].Name())
}

func TestRegisterDefaultModules(t *testing.T) {
	eng := New(testConfig())
	eng.RegisterDefaultModules()

	// Should register all 11 modules
	assert.Len(t, eng.modules, 11)

	names := make(map[string]bool)
	for _, m := range eng.modules {
		names[m.Name()] = true
	}

	// Phase 1 & 2
	assert.True(t, names["certificates"])
	assert.True(t, names["keys"])
	assert.True(t, names["packages"])
	assert.True(t, names["libraries"])
	assert.True(t, names["binaries"])
	assert.True(t, names["kernel"])

	// Phase 3
	assert.True(t, names["scripts"])
	assert.True(t, names["webapp"])
	assert.True(t, names["processes"])
	assert.True(t, names["network"])
	assert.True(t, names["protocol"])
}

func TestScanWithNoModules(t *testing.T) {
	eng := New(testConfig())

	ctx := context.Background()
	progressCh := make(chan Progress, 10)
	result := eng.Scan(ctx, progressCh)

	require.NotNil(t, result)
	assert.Empty(t, result.Findings)
}

func TestScanWithMockModule(t *testing.T) {
	eng := New(testConfig())

	mock := &MockModule{
		name:       "mock",
		targetType: model.TargetFilesystem,
		findings: []*model.Finding{
			makeFinding("f-1"),
			makeFinding("f-2"),
			makeFinding("f-3"),
		},
	}
	eng.RegisterModule(mock)

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	result := eng.Scan(ctx, progressCh)

	assert.Len(t, result.Findings, 3)
}

func TestScanConcurrency(t *testing.T) {
	cfg := testConfig()
	cfg.Workers = 4
	eng := New(cfg)

	// 3 modules, each emitting 5 findings
	for i := 0; i < 3; i++ {
		var findings []*model.Finding
		for j := 0; j < 5; j++ {
			findings = append(findings, makeFinding(fmt.Sprintf("m%d-f%d", i, j)))
		}
		eng.RegisterModule(&MockModule{
			name:       fmt.Sprintf("mock-%d", i),
			targetType: model.TargetFilesystem,
			findings:   findings,
		})
	}

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	result := eng.Scan(ctx, progressCh)

	assert.Len(t, result.Findings, 15)
}

func TestScanContextCancellation(t *testing.T) {
	eng := New(testConfig())

	eng.RegisterModule(&MockModule{
		name:       "slow-module",
		targetType: model.TargetFilesystem,
		scanDelay:  5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	progressCh := make(chan Progress, 100)

	done := make(chan struct{})
	go func() {
		eng.Scan(ctx, progressCh)
		close(done)
	}()

	select {
	case <-done:
		// Completed without hanging
	case <-time.After(2 * time.Second):
		t.Fatal("Scan did not respect context cancellation")
	}
}

func TestScanProgressReporting(t *testing.T) {
	eng := New(testConfig())

	eng.RegisterModule(&MockModule{
		name:       "mock",
		targetType: model.TargetFilesystem,
		findings:   []*model.Finding{makeFinding("f-1")},
	})

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	eng.Scan(ctx, progressCh)

	// Collect all progress messages
	var messages []Progress
	for p := range progressCh {
		messages = append(messages, p)
	}

	require.NotEmpty(t, messages)

	// Last message should be complete
	last := messages[len(messages)-1]
	assert.True(t, last.Complete)
	assert.NotNil(t, last.Result)
}

func TestScanTargetRouting(t *testing.T) {
	cfg := testConfig()
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: "/etc", Depth: 3},
		{Type: model.TargetNetwork, Value: "192.168.1.0/24", Depth: 0},
	}
	eng := New(cfg)

	fsModule := &MockModule{
		name:       "fs-module",
		targetType: model.TargetFilesystem,
		findings:   []*model.Finding{makeFinding("fs-1")},
	}
	netModule := &MockModule{
		name:       "net-module",
		targetType: model.TargetNetwork,
		findings:   []*model.Finding{makeFinding("net-1")},
	}

	eng.RegisterModule(fsModule)
	eng.RegisterModule(netModule)

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	result := eng.Scan(ctx, progressCh)

	// Both modules should have produced findings
	assert.Len(t, result.Findings, 2)
}

func TestResultsAddFindingConcurrency(t *testing.T) {
	result := &model.ScanResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			f := model.Finding{
				ID:       fmt.Sprintf("f-%d", idx),
				Category: 5,
			}
			mu.Lock()
			result.Findings = append(result.Findings, f)
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	assert.Len(t, result.Findings, 100)
}

func TestScanModuleErrorReported(t *testing.T) {
	eng := New(testConfig())

	eng.RegisterModule(&MockModule{
		name:       "failing-module",
		targetType: model.TargetFilesystem,
		scanErr:    fmt.Errorf("disk read error"),
	})

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	eng.Scan(ctx, progressCh)

	// Collect progress messages and check for error
	var foundError bool
	for p := range progressCh {
		if p.Error != nil {
			foundError = true
			assert.Contains(t, p.Error.Error(), "failing-module")
			assert.Contains(t, p.Error.Error(), "disk read error")
		}
	}
	assert.True(t, foundError, "module error should be reported via progress channel")
}

func TestScanWithZeroWorkers(t *testing.T) {
	cfg := testConfig()
	cfg.Workers = 0
	eng := New(cfg)

	eng.RegisterModule(&MockModule{
		name:       "mock",
		targetType: model.TargetFilesystem,
		findings:   []*model.Finding{makeFinding("f-1")},
	})

	ctx := context.Background()
	progressCh := make(chan Progress, 100)

	// Should not deadlock — workers=0 is clamped to 1
	done := make(chan struct{})
	go func() {
		eng.Scan(ctx, progressCh)
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("Scan with Workers=0 should not deadlock")
	}
}

func TestScanResultMetadata(t *testing.T) {
	eng := New(testConfig())
	eng.RegisterModule(&MockModule{
		name:       "mock",
		targetType: model.TargetFilesystem,
	})

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	result := eng.Scan(ctx, progressCh)

	assert.NotEmpty(t, result.ID)
	assert.NotEmpty(t, result.Metadata.Hostname)
	assert.NotEmpty(t, result.Metadata.OS)
	assert.Equal(t, "quick", result.Metadata.ScanProfile)
	assert.True(t, result.Metadata.Duration > 0)
}
