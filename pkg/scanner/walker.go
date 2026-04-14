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

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/store"
)

// walkerConfig holds common filesystem walk parameters.
type walkerConfig struct {
	ctx          context.Context
	target       model.ScanTarget
	config       *scannerconfig.Config
	reader       fsadapter.FileReader // nil = use LocalReader (local scan)
	matchFile    func(path string) bool
	processFile  func(ctx context.Context, reader fsadapter.FileReader, path string) error
	filesScanned *int64 // atomic: every non-dir file visited (nil = disabled)
	filesMatched *int64 // atomic: files passing matchFile filter (nil = disabled)
	filesSkipped *int64 // atomic: files skipped by incremental hash check (nil = disabled)
	store        store.Store
}

// walkTarget walks a scan target, enforcing depth limits, file size limits,
// and exclude patterns. For each matching file, it calls processFile.
func walkTarget(wc walkerConfig) error {
	ctx := wc.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	reader := wc.reader
	if reader == nil {
		reader = fsadapter.NewLocalReader()
	}

	rootDepth := strings.Count(filepath.Clean(wc.target.Value), string(filepath.Separator))

	return reader.Walk(ctx, wc.target.Value, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		if d.IsDir() {
			if wc.target.Depth > 0 {
				currentDepth := strings.Count(filepath.Clean(path), string(filepath.Separator))
				if currentDepth-rootDepth >= wc.target.Depth {
					return filepath.SkipDir
				}
			}
			if shouldSkipDir(path, wc.config) {
				return filepath.SkipDir
			}
			return nil
		}

		if wc.filesScanned != nil {
			atomic.AddInt64(wc.filesScanned, 1)
		}

		if !wc.matchFile(path) {
			return nil
		}

		if wc.filesMatched != nil {
			atomic.AddInt64(wc.filesMatched, 1)
		}

		if wc.config != nil && wc.config.MaxFileSize > 0 {
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Size() > wc.config.MaxFileSize {
				return nil
			}
		}

		if wc.store != nil && wc.config != nil && wc.config.Incremental {
			skip, newHash := checkFileChanged(ctx, wc.store, path)
			if skip {
				if wc.filesSkipped != nil {
					atomic.AddInt64(wc.filesSkipped, 1)
				}
				return nil
			}
			if err := wc.processFile(ctx, reader, path); err != nil {
				return err
			}
			if newHash != "" {
				_ = wc.store.SetFileHash(ctx, path, newHash)
			}
			return nil
		}

		return wc.processFile(ctx, reader, path)
	})
}

// checkFileChanged computes the SHA-256 hash of a file and compares it with
// the stored hash. Returns (true, "") if unchanged (skip), or (false, newHash)
// if the file needs processing.
func checkFileChanged(ctx context.Context, s store.Store, path string) (skip bool, newHash string) {
	hash, err := hashFile(path)
	if err != nil {
		return false, "" // Can't hash → process anyway
	}

	storedHash, _, err := s.GetFileHash(ctx, path)
	if err == nil && storedHash == hash {
		return true, "" // Unchanged
	}
	return false, hash
}

// hashFile computes the SHA-256 hex digest of a file.
//
// NOTE: this uses os.Open directly and bypasses wc.reader.
// Incremental mode requires local filesystem access and is not
// compatible with agentless (SSH-based) scans. scanUnix sets
// DBUrl="" which keeps wc.store == nil, so this path is not taken
// on agentless scans.
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
func shouldSkipDir(path string, cfg *scannerconfig.Config) bool {
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
