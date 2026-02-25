package scanner

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/google/uuid"
)

type PackageModule struct {
	config *config.Config
}

func NewPackageModule(cfg *config.Config) *PackageModule {
	return &PackageModule{config: cfg}
}

func (m *PackageModule) Name() string {
	return "packages"
}

func (m *PackageModule) Category() model.ModuleCategory {
	return model.CategoryPassiveFile
}

func (m *PackageModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}

func (m *PackageModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	switch runtime.GOOS {
	case "darwin":
		return m.scanMacPackages(ctx, findings)
	case "linux":
		return m.scanLinuxPackages(ctx, findings)
	default:
		return nil
	}
}

func (m *PackageModule) scanMacPackages(ctx context.Context, findings chan<- *model.Finding) error {
	cmd := exec.CommandContext(ctx, "brew", "list", "--versions")
	output, err := cmd.Output()
	if err != nil {
		return nil // Brew not installed or error
	}

	return m.parsePackageOutput(ctx, string(output), "brew", findings)
}

func (m *PackageModule) scanLinuxPackages(ctx context.Context, findings chan<- *model.Finding) error {
	// Try dpkg (Debian/Ubuntu)
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package} ${Version}\n")
	output, err := cmd.Output()
	if err == nil {
		return m.parsePackageOutput(ctx, string(output), "dpkg", findings)
	}

	// Try rpm (RHEL/CentOS/Fedora)
	cmd = exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n")
	output, err = cmd.Output()
	if err == nil {
		return m.parsePackageOutput(ctx, string(output), "rpm", findings)
	}

	return nil
}

func (m *PackageModule) parsePackageOutput(ctx context.Context, output, manager string, findings chan<- *model.Finding) error {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			sourcePath := manager + ":" + parts[0] + "@" + parts[1]
			select {
			case findings <- &model.Finding{
				ID:       uuid.New().String(),
				Category: 0,
				Source: model.FindingSource{
					Type: "file",
					Path: sourcePath,
				},
				Confidence: 1.0,
				Module:     "packages",
				Timestamp:  time.Now(),
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}
