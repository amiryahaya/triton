package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// walkerConfig holds common filesystem walk parameters.
type walkerConfig struct {
	target      model.ScanTarget
	config      *config.Config
	matchFile   func(path string) bool
	processFile func(path string) error
}

// walkTarget walks a scan target, enforcing depth limits, file size limits,
// and exclude patterns. For each matching file, it calls processFile.
func walkTarget(wc walkerConfig) error {
	rootDepth := strings.Count(filepath.Clean(wc.target.Value), string(filepath.Separator))

	return filepath.Walk(wc.target.Value, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors, continue scanning
		}

		if info.IsDir() {
			// Enforce max depth
			if wc.target.Depth > 0 {
				currentDepth := strings.Count(filepath.Clean(path), string(filepath.Separator))
				if currentDepth-rootDepth >= wc.target.Depth {
					return filepath.SkipDir
				}
			}

			// Check exclude patterns
			if shouldSkipDir(path, wc.config) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip files that don't match
		if !wc.matchFile(path) {
			return nil
		}

		// Enforce max file size
		if wc.config != nil && wc.config.MaxFileSize > 0 && info.Size() > wc.config.MaxFileSize {
			return nil
		}

		return wc.processFile(path)
	})
}

// shouldSkipDir checks if a directory should be excluded from scanning.
func shouldSkipDir(path string, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, exclude := range cfg.ExcludePatterns {
		if strings.Contains(path, exclude) {
			return true
		}
	}
	return false
}
