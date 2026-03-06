package scanner

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// KernelModule scans kernel crypto modules (.ko files on Linux).
// Gracefully skips on macOS and Windows.
// Not safe for concurrent Scan calls on the same instance — the engine
// guarantees each module is called sequentially per target.
type KernelModule struct {
	config      *config.Config
	lastScanned int64
	lastMatched int64
	store       store.Store
}

func (m *KernelModule) SetStore(s store.Store) { m.store = s }

func NewKernelModule(cfg *config.Config) *KernelModule {
	return &KernelModule{config: cfg}
}

func (m *KernelModule) Name() string {
	return "kernel"
}

func (m *KernelModule) Category() model.ModuleCategory {
	return model.CategoryPassiveFile
}

func (m *KernelModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}

func (m *KernelModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *KernelModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	// Kernel module scanning only works on Linux
	if runtime.GOOS != "linux" {
		return nil
	}

	return m.scanKernelModules(ctx, target, findings)
}

// ScanWithOverride is for testing — allows scanning a directory regardless of OS.
func (m *KernelModule) ScanWithOverride(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return m.scanKernelModules(ctx, target, findings)
}

func (m *KernelModule) scanKernelModules(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    m.isKernelModule,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			found, err := m.scanKernelModuleFile(path)
			if err != nil {
				// Non-fatal: skip unreadable/corrupt modules but continue scanning.
				// Errors include permission denied, corrupt compressed streams, I/O errors.
				return nil //nolint:nilerr // intentionally non-fatal
			}

			for _, f := range found {
				select {
				case findings <- f:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	})
}

// isKernelModule checks if a file is a kernel module.
// Matches both uncompressed .ko and compressed variants (.ko.xz, .ko.gz, .ko.zst)
// used by modern Linux distributions (Fedora, Ubuntu 20.04+, RHEL 8+).
func (m *KernelModule) isKernelModule(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".ko") ||
		strings.HasSuffix(lower, ".ko.gz") ||
		strings.HasSuffix(lower, ".ko.xz") ||
		strings.HasSuffix(lower, ".ko.zst")
}

// maxKernelModuleReadSize limits how much of each kernel module we read.
const maxKernelModuleReadSize = 1 * 1024 * 1024 // 1MB

// decompressReadCloser wraps a decompressor and the underlying file so both get closed.
type decompressReadCloser struct {
	reader io.Reader
	closer io.Closer // underlying file
}

func (d *decompressReadCloser) Read(p []byte) (int, error) {
	return d.reader.Read(p)
}

func (d *decompressReadCloser) Close() error {
	return d.closer.Close()
}

// openKernelModule opens a kernel module, transparently decompressing if needed.
// MaxFileSize in config applies to the on-disk (compressed) size; the decompressed
// read is independently capped by maxKernelModuleReadSize via LimitReader.
func openKernelModule(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".ko.gz"):
		gr, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		// gzip.Reader implements io.Closer — must close to release resources.
		return &decompressReadCloser{reader: gr, closer: closerFunc(func() error {
			return errors.Join(gr.Close(), f.Close())
		})}, nil

	case strings.HasSuffix(lower, ".ko.xz"):
		xr, err := xz.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		// xz.Reader does not implement io.Closer — only the file needs closing.
		return &decompressReadCloser{reader: xr, closer: f}, nil

	case strings.HasSuffix(lower, ".ko.zst"):
		zr, err := zstd.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		// zstd.Decoder.Close() does not return error — call it then close the file.
		return &decompressReadCloser{reader: zr, closer: closerFunc(func() error {
			zr.Close()
			return f.Close()
		})}, nil

	default:
		return f, nil
	}
}

// closerFunc adapts a function to io.Closer.
type closerFunc func() error

func (fn closerFunc) Close() error { return fn() }

// scanKernelModuleFile reads a kernel module and looks for crypto patterns.
func (m *KernelModule) scanKernelModuleFile(path string) ([]*model.Finding, error) {
	rc, err := openKernelModule(path)
	if err != nil {
		return nil, fmt.Errorf("open kernel module %s: %w", path, err)
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(io.LimitReader(rc, maxKernelModuleReadSize))
	if err != nil {
		return nil, fmt.Errorf("read kernel module %s: %w", path, err)
	}

	// Extract printable strings
	content := ExtractPrintableStrings(data, 4)

	// Match crypto patterns
	algos := MatchCryptoInStrings(content)
	if len(algos) == 0 {
		return nil, nil
	}

	findings := make([]*model.Finding, 0, len(algos))
	for _, algo := range algos {
		asset := &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "Kernel crypto module",
			Algorithm: algo,
			Purpose:   "Kernel-level cryptographic implementation",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 4,
			Source: model.FindingSource{
				Type: "file",
				Path: path,
			},
			CryptoAsset: asset,
			Confidence:  0.65,
			Module:      "kernel",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}
