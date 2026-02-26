package scanner

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestWalkTargetDepthEnforcement(t *testing.T) {
	// Create a nested directory structure:
	// tmpDir/
	//   level1/
	//     level2/
	//       level3/
	//         deep.pem
	//     shallow.pem
	//   root.pem
	tmpDir := t.TempDir()

	mkFile := func(relPath string) {
		abs := filepath.Join(tmpDir, relPath)
		os.MkdirAll(filepath.Dir(abs), 0755)
		os.WriteFile(abs, []byte("data"), 0644)
	}

	mkFile("root.pem")
	mkFile("level1/shallow.pem")
	mkFile("level1/level2/mid.pem")
	mkFile("level1/level2/level3/deep.pem")

	tests := []struct {
		name     string
		depth    int
		expected int
	}{
		{"depth 1 — root only", 1, 1},
		{"depth 2 — root + level1", 2, 2},
		{"depth 3 — root + level1 + level2", 3, 3},
		{"depth -1 — unlimited", -1, 4},
		{"depth 0 — unlimited", 0, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var found []string
			err := walkTarget(walkerConfig{
				target: model.ScanTarget{
					Type:  model.TargetFilesystem,
					Value: tmpDir,
					Depth: tt.depth,
				},
				config:    &config.Config{},
				matchFile: func(path string) bool { return filepath.Ext(path) == ".pem" },
				processFile: func(path string) error {
					found = append(found, path)
					return nil
				},
			})
			require.NoError(t, err)
			assert.Len(t, found, tt.expected, "depth=%d should find %d files, got %v", tt.depth, tt.expected, found)
		})
	}
}

func TestWalkTargetMaxFileSize(t *testing.T) {
	tmpDir := t.TempDir()

	// Small file (10 bytes)
	smallFile := filepath.Join(tmpDir, "small.pem")
	os.WriteFile(smallFile, make([]byte, 10), 0644)

	// Large file (1000 bytes)
	largeFile := filepath.Join(tmpDir, "large.pem")
	os.WriteFile(largeFile, make([]byte, 1000), 0644)

	var found []string
	err := walkTarget(walkerConfig{
		target: model.ScanTarget{
			Type:  model.TargetFilesystem,
			Value: tmpDir,
			Depth: -1,
		},
		config: &config.Config{
			MaxFileSize: 500, // Only files under 500 bytes
		},
		matchFile: func(path string) bool { return true },
		processFile: func(path string) error {
			found = append(found, filepath.Base(path))
			return nil
		},
	})
	require.NoError(t, err)

	assert.Len(t, found, 1)
	assert.Contains(t, found, "small.pem")
}

func TestWalkTargetExcludePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	os.MkdirAll(filepath.Join(tmpDir, ".git", "objects"), 0755)
	os.WriteFile(filepath.Join(tmpDir, ".git", "config.pem"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "good.pem"), []byte("data"), 0644)

	var found []string
	err := walkTarget(walkerConfig{
		target: model.ScanTarget{
			Type:  model.TargetFilesystem,
			Value: tmpDir,
			Depth: -1,
		},
		config: &config.Config{
			ExcludePatterns: []string{".git"},
		},
		matchFile: func(path string) bool { return filepath.Ext(path) == ".pem" },
		processFile: func(path string) error {
			found = append(found, filepath.Base(path))
			return nil
		},
	})
	require.NoError(t, err)

	assert.Len(t, found, 1)
	assert.Contains(t, found, "good.pem")
}

func TestShouldSkipDir(t *testing.T) {
	cfg := &config.Config{
		ExcludePatterns: []string{".git", "node_modules", "/proc"},
	}

	assert.True(t, shouldSkipDir("/project/.git", cfg))
	assert.True(t, shouldSkipDir("/project/node_modules", cfg))
	assert.True(t, shouldSkipDir("/proc/1234", cfg))
	assert.False(t, shouldSkipDir("/etc/ssl", cfg))
	assert.False(t, shouldSkipDir("/etc/ssl", nil))
}

func TestWalkerFileCounters(t *testing.T) {
	tmpDir := t.TempDir()

	// Create mixed files: 3 .pem (match), 2 .txt (no match)
	os.WriteFile(filepath.Join(tmpDir, "a.pem"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "b.pem"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "c.pem"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "d.txt"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "e.txt"), []byte("data"), 0644)

	var scanned, matched int64
	err := walkTarget(walkerConfig{
		target: model.ScanTarget{
			Type:  model.TargetFilesystem,
			Value: tmpDir,
			Depth: -1,
		},
		config:       &config.Config{},
		matchFile:    func(path string) bool { return filepath.Ext(path) == ".pem" },
		processFile:  func(path string) error { return nil },
		filesScanned: &scanned,
		filesMatched: &matched,
	})
	require.NoError(t, err)

	assert.Equal(t, int64(5), atomic.LoadInt64(&scanned), "all 5 files should be scanned")
	assert.Equal(t, int64(3), atomic.LoadInt64(&matched), "only 3 .pem files should match")
}

func TestWalkerFileCountersNil(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "a.pem"), []byte("data"), 0644)

	// nil counters should not panic
	var found []string
	err := walkTarget(walkerConfig{
		target: model.ScanTarget{
			Type:  model.TargetFilesystem,
			Value: tmpDir,
			Depth: -1,
		},
		config:    &config.Config{},
		matchFile: func(path string) bool { return true },
		processFile: func(path string) error {
			found = append(found, path)
			return nil
		},
		// filesScanned and filesMatched are nil — should work fine
	})
	require.NoError(t, err)
	assert.Len(t, found, 1)
}
