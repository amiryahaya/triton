package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// walkerConfig holds common filesystem walk parameters.
type walkerConfig struct {
	target       model.ScanTarget
	config       *config.Config
	matchFile    func(path string) bool
	processFile  func(path string) error
	filesScanned *int64 // atomic: every non-dir file visited (nil = disabled)
	filesMatched *int64 // atomic: files passing matchFile filter (nil = disabled)
	filesSkipped *int64 // atomic: files skipped by incremental hash check (nil = disabled)
	store        store.Store
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

		// Count every non-dir file visited
		if wc.filesScanned != nil {
			atomic.AddInt64(wc.filesScanned, 1)
		}

		// Skip files that don't match
		if !wc.matchFile(path) {
			return nil
		}

		// Count files passing the match filter
		if wc.filesMatched != nil {
			atomic.AddInt64(wc.filesMatched, 1)
		}

		// Enforce max file size
		if wc.config != nil && wc.config.MaxFileSize > 0 && info.Size() > wc.config.MaxFileSize {
			return nil
		}

		// Incremental scanning: skip unchanged files
		if wc.store != nil && wc.config != nil && wc.config.Incremental {
			skip, newHash := checkFileChanged(wc.store, path)
			if skip {
				if wc.filesSkipped != nil {
					atomic.AddInt64(wc.filesSkipped, 1)
				}
				return nil
			}
			// Process the file, then update hash on success.
			if err := wc.processFile(path); err != nil {
				return err
			}
			if newHash != "" {
				_ = wc.store.SetFileHash(context.Background(), path, newHash)
			}
			return nil
		}

		return wc.processFile(path)
	})
}

// checkFileChanged computes the SHA-256 hash of a file and compares it with
// the stored hash. Returns (true, "") if unchanged (skip), or (false, newHash)
// if the file needs processing.
func checkFileChanged(s store.Store, path string) (skip bool, newHash string) {
	hash, err := hashFile(path)
	if err != nil {
		return false, "" // Can't hash → process anyway
	}

	storedHash, _, err := s.GetFileHash(context.Background(), path)
	if err == nil && storedHash == hash {
		return true, "" // Unchanged
	}
	return false, hash
}

// hashFile computes the SHA-256 hex digest of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
