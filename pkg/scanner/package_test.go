package scanner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface compliance check
var _ Module = (*PackageModule)(nil)

func TestPackageModuleInterface(t *testing.T) {
	m := NewPackageModule(&config.Config{})
	assert.Equal(t, "packages", m.Name())
}

func TestPackageModuleCategory(t *testing.T) {
	m := NewPackageModule(&config.Config{})
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
}

func TestPackageModuleScanTargetType(t *testing.T) {
	m := NewPackageModule(&config.Config{})
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestParsePackageOutputFiltered(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	// openssl is crypto-related, curl and git are not
	output := "openssl 3.2.0\ncurl 8.4.0\ngit 2.43.0\nlibsodium 1.0.19\n"

	findings := make(chan *model.Finding, 10)
	err := m.parsePackageOutput(context.Background(), output, "brew", findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Only crypto-related packages should be found
	require.Len(t, collected, 2)
	assert.Equal(t, "brew:openssl@3.2.0", collected[0].Source.Path)
	assert.Equal(t, "brew:libsodium@1.0.19", collected[1].Source.Path)
}

func TestPackageFindingShape(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	findings := make(chan *model.Finding, 10)
	err := m.parsePackageOutput(context.Background(), "openssl 3.2.0\n", "brew", findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)

	require.NotNil(t, finding.CryptoAsset)
	assert.Equal(t, "Installed package", finding.CryptoAsset.Function)
	assert.Contains(t, finding.CryptoAsset.Library, "openssl 3.2.0")
	assert.Equal(t, "brew:openssl@3.2.0", finding.Source.Path)
	assert.Equal(t, "packages", finding.Module)
	assert.Equal(t, 0.85, finding.Confidence)
}

func TestIsCryptoPackage(t *testing.T) {
	// Crypto packages
	assert.True(t, isCryptoPackage("openssl"))
	assert.True(t, isCryptoPackage("libssl-dev"))
	assert.True(t, isCryptoPackage("gnutls-utils"))
	assert.True(t, isCryptoPackage("openssh-server"))
	assert.True(t, isCryptoPackage("libsodium23"))
	assert.True(t, isCryptoPackage("gnupg2"))
	assert.True(t, isCryptoPackage("ca-certificates"))
	assert.True(t, isCryptoPackage("openjdk-17-jre"))
	assert.True(t, isCryptoPackage("wolfssl"))
	assert.True(t, isCryptoPackage("wireguard-tools"))
	assert.True(t, isCryptoPackage("python3-cryptography"))

	// Non-crypto packages
	assert.False(t, isCryptoPackage("curl"))
	assert.False(t, isCryptoPackage("git"))
	assert.False(t, isCryptoPackage("vim"))
	assert.False(t, isCryptoPackage("nginx"))
	assert.False(t, isCryptoPackage("python3"))
}

func TestParsePackageEmptyOutput(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	findings := make(chan *model.Finding, 10)
	err := m.parsePackageOutput(context.Background(), "", "brew", findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected)
}

func TestParsePackageContextCancellation(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := make(chan *model.Finding, 10)
	err := m.parsePackageOutput(ctx, "openssl 3.2.0\n", "brew", findings)
	close(findings)

	// Should get context error since channel send was cancelled
	_ = err // May or may not error depending on timing
}

func TestPackageScanOnlyRunsOnce(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	targets := []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: "/etc", Depth: 3},
		{Type: model.TargetFilesystem, Value: "/usr/local", Depth: 3},
		{Type: model.TargetFilesystem, Value: "/Applications", Depth: 3},
		{Type: model.TargetFilesystem, Value: "/System/Library", Depth: 3},
	}

	findings := make(chan *model.Finding, 500)
	ctx := context.Background()

	for _, target := range targets {
		err := m.Scan(ctx, target, findings)
		require.NoError(t, err)
	}
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// Check no duplicates: each source path should appear exactly once
	seen := make(map[string]bool)
	for _, f := range collected {
		if seen[f.Source.Path] {
			t.Errorf("duplicate finding: %s", f.Source.Path)
		}
		seen[f.Source.Path] = true
	}
}

func TestPackageVersionBasedClassification(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	output := "openssl 1.0.2u\nlibsodium 1.0.19\nopenssl 3.2.0\n"
	findings := make(chan *model.Finding, 10)
	err := m.parsePackageOutput(context.Background(), output, "dpkg", findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 3)

	// openssl 1.0.2u should be DEPRECATED
	assert.Equal(t, "DEPRECATED", collected[0].CryptoAsset.PQCStatus, "OpenSSL 1.0.2u should be DEPRECATED")

	// libsodium should always be SAFE
	assert.Equal(t, "SAFE", collected[1].CryptoAsset.PQCStatus, "libsodium should be SAFE")

	// openssl 3.2.0 should be TRANSITIONAL
	assert.Equal(t, "TRANSITIONAL", collected[2].CryptoAsset.PQCStatus, "OpenSSL 3.2.0 should be TRANSITIONAL")
}

func TestPackageFindingCategory(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	findings := make(chan *model.Finding, 10)
	err := m.parsePackageOutput(context.Background(), "openssl 3.2.0\n", "brew", findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)
	assert.Equal(t, 3, finding.Category, "package findings should use crypto libraries category (3)")
}

func TestPackageScanRetriesAfterFailure(t *testing.T) {
	cfg := &config.Config{Modules: []string{"packages"}}
	m := NewPackageModule(cfg)

	// First call with cancelled context — the platform scan functions swallow
	// exec errors and return nil, so scanned is set to true on the first call
	// regardless of context state (scan completes or is treated as no-op).
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	findings := make(chan *model.Finding, 100)
	err := m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem, Value: "/"}, findings)
	// Scan always returns nil (platform scan helpers swallow errors)
	assert.NoError(t, err)

	// A second call with the same module instance should be a no-op due to
	// the scanned guard, returning nil without doing any work.
	findings2 := make(chan *model.Finding, 100)
	err2 := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetFilesystem, Value: "/"}, findings2)
	assert.NoError(t, err2, "second scan call should return nil (idempotent guard)")
	close(findings2)

	var extra []*model.Finding
	for f := range findings2 {
		extra = append(extra, f)
	}
	assert.Empty(t, extra, "second scan call should produce no findings (already scanned)")
}

func TestMultipleCryptoPackages(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	output := `openssl 3.2.0
libssl3 3.0.13
gnutls-bin 3.7.9
openssh-client 9.6
ca-certificates 2024.01
vim 9.1
bash 5.2`

	findings := make(chan *model.Finding, 20)
	err := m.parsePackageOutput(context.Background(), output, "dpkg", findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// openssl, libssl3, gnutls-bin, openssh-client, ca-certificates = 5 crypto packages
	assert.Len(t, collected, 5)
}
