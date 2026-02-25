package scanner

import (
	"context"
	"os/exec"
	"runtime"
	"strings"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
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

func (m *PackageModule) Scan(ctx context.Context, target string, findings chan<- *model.Finding) error {
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
	// Scan Homebrew packages
	cmd := exec.CommandContext(ctx, "brew", "list", "--versions")
	output, err := cmd.Output()
	if err != nil {
		return nil // Brew not installed or error
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			select {
			case findings <- &model.Finding{
				Type: "package",
				Component: &model.Component{
					Name:    parts[0],
					Version: parts[1],
					Type:    "brew",
				},
				Confidence: 1.0,
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

func (m *PackageModule) scanLinuxPackages(ctx context.Context, findings chan<- *model.Finding) error {
	// Try dpkg (Debian/Ubuntu)
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package} ${Version}\n")
	output, err := cmd.Output()
	if err == nil {
		return m.parseDpkgOutput(ctx, string(output), findings)
	}

	// Try rpm (RHEL/CentOS/Fedora)
	cmd = exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n")
	output, err = cmd.Output()
	if err == nil {
		return m.parseRpmOutput(ctx, string(output), findings)
	}

	return nil
}

func (m *PackageModule) parseDpkgOutput(ctx context.Context, output string, findings chan<- *model.Finding) error {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			select {
			case findings <- &model.Finding{
				Type: "package",
				Component: &model.Component{
					Name:    parts[0],
					Version: parts[1],
					Type:    "dpkg",
				},
				Confidence: 1.0,
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

func (m *PackageModule) parseRpmOutput(ctx context.Context, output string, findings chan<- *model.Finding) error {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			select {
			case findings <- &model.Finding{
				Type: "package",
				Component: &model.Component{
					Name:    parts[0],
					Version: parts[1],
					Type:    "rpm",
				},
				Confidence: 1.0,
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
