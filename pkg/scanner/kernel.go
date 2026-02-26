package scanner

import (
	"context"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/google/uuid"
)

// KernelModule scans kernel crypto modules (.ko files on Linux).
// Gracefully skips on macOS and Windows.
type KernelModule struct {
	config *config.Config
}

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
	return walkTarget(walkerConfig{
		target:    target,
		config:    m.config,
		matchFile: m.isKernelModule,
		processFile: func(path string) error {
			found, err := m.scanKernelModuleFile(path)
			if err != nil {
				return nil
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
// Only matches uncompressed .ko files — compressed variants (.ko.xz, .ko.gz, .ko.zst)
// require decompression which is not yet supported.
func (m *KernelModule) isKernelModule(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".ko")
}

// maxKernelModuleReadSize limits how much of each kernel module we read.
const maxKernelModuleReadSize = 1 * 1024 * 1024 // 1MB

// scanKernelModuleFile reads a kernel module and looks for crypto patterns.
func (m *KernelModule) scanKernelModuleFile(path string) ([]*model.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxKernelModuleReadSize))
	if err != nil {
		return nil, err
	}

	// Extract printable strings
	content := ExtractPrintableStrings(data, 4)

	// Match crypto patterns
	algos := MatchCryptoInStrings(content)
	if len(algos) == 0 {
		return nil, nil
	}

	var findings []*model.Finding
	for _, algo := range algos {
		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Function:  "Kernel crypto module",
			Algorithm: algo,
			Purpose:   "Kernel-level cryptographic implementation",
		}
		crypto.ClassifyCryptoAsset(asset)

		findings = append(findings, &model.Finding{
			ID:       uuid.New().String(),
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

