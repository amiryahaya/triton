package config

import (
	"runtime"
	"testing"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadQuickProfile(t *testing.T) {
	cfg := Load("quick")

	assert.Equal(t, "quick", cfg.Profile)
	assert.Equal(t, 3, cfg.MaxDepth)
	assert.Contains(t, cfg.Modules, "certificates")
	assert.Contains(t, cfg.Modules, "keys")
	assert.Contains(t, cfg.Modules, "packages")

	maxWorkers := 4
	if maxWorkers > runtime.NumCPU() {
		maxWorkers = runtime.NumCPU()
	}
	assert.Equal(t, maxWorkers, cfg.Workers)
}

func TestLoadStandardProfile(t *testing.T) {
	cfg := Load("standard")

	assert.Equal(t, "standard", cfg.Profile)
	assert.Equal(t, 10, cfg.MaxDepth)
	assert.Contains(t, cfg.Modules, "certificates")
	assert.Contains(t, cfg.Modules, "libraries")
	assert.Contains(t, cfg.Modules, "binaries")
	assert.Contains(t, cfg.Modules, "scripts")
	assert.Contains(t, cfg.Modules, "webapp")
}

func TestLoadComprehensiveProfile(t *testing.T) {
	cfg := Load("comprehensive")

	assert.Equal(t, "comprehensive", cfg.Profile)
	assert.Equal(t, -1, cfg.MaxDepth)
	assert.LessOrEqual(t, cfg.Workers, runtime.NumCPU())
	assert.Contains(t, cfg.Modules, "kernel")
	assert.Contains(t, cfg.Modules, "binaries")
	assert.Contains(t, cfg.Modules, "scripts")
	assert.Contains(t, cfg.Modules, "webapp")
	assert.Contains(t, cfg.Modules, "processes")
	assert.Contains(t, cfg.Modules, "network")
	assert.Contains(t, cfg.Modules, "protocol")

	// Should have process and network targets
	hasProcess := false
	hasNetwork := false
	for _, t := range cfg.ScanTargets {
		if t.Type == model.TargetProcess {
			hasProcess = true
		}
		if t.Type == model.TargetNetwork {
			hasNetwork = true
		}
	}
	assert.True(t, hasProcess, "comprehensive profile should include process targets")
	assert.True(t, hasNetwork, "comprehensive profile should include network targets")
}

func TestLoadUnknownProfileFallback(t *testing.T) {
	cfg := Load("nonexistent")

	assert.Equal(t, "standard", cfg.Profile)
	assert.Equal(t, 10, cfg.MaxDepth)
}

func TestWorkersCappedByCPU(t *testing.T) {
	cfg := Load("comprehensive")
	assert.LessOrEqual(t, cfg.Workers, runtime.NumCPU())
}

func TestDefaultScanTargets(t *testing.T) {
	cfg := Load("quick")

	require.NotEmpty(t, cfg.ScanTargets)

	// All targets should be filesystem type
	for _, target := range cfg.ScanTargets {
		assert.Equal(t, model.TargetFilesystem, target.Type)
		assert.NotEmpty(t, target.Value)
	}
}

func TestDefaultExcludePatterns(t *testing.T) {
	patterns := defaultExcludePatterns()

	assert.Contains(t, patterns, "/proc")
	assert.Contains(t, patterns, "/sys")
	assert.Contains(t, patterns, ".git")
	assert.Contains(t, patterns, "node_modules")
}

func TestDefaultIncludePatterns(t *testing.T) {
	patterns := defaultIncludePatterns()

	assert.Contains(t, patterns, "*.pem")
	assert.Contains(t, patterns, "*.crt")
	assert.Contains(t, patterns, "*.key")
	assert.Contains(t, patterns, "*.cer")
}
