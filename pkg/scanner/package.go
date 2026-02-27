package scanner

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// cryptoPackageKeywords are keywords that indicate a package provides crypto functionality.
var cryptoPackageKeywords = []string{
	"openssl", "libssl", "gnutls", "nss", "crypto",
	"mbedtls", "wolfssl", "boringssl", "libressl",
	"gnupg", "gpg", "openssh", "libssh",
	"certbot", "ca-certificates", "p11-kit",
	"libgcrypt", "libsodium", "nettle",
	"openvpn", "strongswan", "ipsec", "wireguard",
	"java", "openjdk", // Java includes crypto
}

type PackageModule struct {
	config *config.Config
	once   sync.Once
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
	// Package listing is global (not per-target), so only run once
	// even though the engine calls Scan for each filesystem target.
	var scanErr error
	m.once.Do(func() {
		switch runtime.GOOS {
		case "darwin":
			scanErr = m.scanMacPackages(ctx, findings)
		case "linux":
			scanErr = m.scanLinuxPackages(ctx, findings)
		}
	})
	return scanErr
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
		if len(parts) < 2 {
			continue
		}

		pkgName := parts[0]
		pkgVersion := parts[1]

		// Filter to crypto-related packages only
		if !isCryptoPackage(pkgName) {
			continue
		}

		sourcePath := manager + ":" + pkgName + "@" + pkgVersion

		asset := &model.CryptoAsset{
			ID:        uuid.New().String(),
			Algorithm: pkgName,
			Function:  "Installed package",
			Library:   pkgName + " " + pkgVersion,
			Purpose:   "System package providing crypto functionality",
		}

		// Classify based on package name + version (replaces hardcoded TRANSITIONAL)
		crypto.ClassifyLibraryAsset(asset, pkgName, pkgVersion)

		select {
		case findings <- &model.Finding{
			ID:       uuid.New().String(),
			Category: 3, // crypto libraries category
			Source: model.FindingSource{
				Type: "file",
				Path: sourcePath,
			},
			CryptoAsset: asset,
			Confidence:  0.85,
			Module:      "packages",
			Timestamp:   time.Now(),
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// isCryptoPackage checks if a package name matches known crypto-related keywords.
func isCryptoPackage(name string) bool {
	lower := strings.ToLower(name)
	for _, keyword := range cryptoPackageKeywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}
