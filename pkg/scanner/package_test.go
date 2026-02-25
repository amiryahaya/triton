package scanner

import (
	"context"
	"testing"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestParseBytesOutput(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	output := "openssl 3.2.0\ncurl 8.4.0\ngit 2.43.0\n"

	findings := make(chan *model.Finding, 10)
	err := m.parsePackageOutput(context.Background(), output, "brew", findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.Len(t, collected, 3)

	assert.Equal(t, "brew:openssl@3.2.0", collected[0].Source.Path)
	assert.Equal(t, "brew:curl@8.4.0", collected[1].Source.Path)
	assert.Equal(t, "brew:git@2.43.0", collected[2].Source.Path)
}

func TestPackageFindingShape(t *testing.T) {
	m := NewPackageModule(&config.Config{})

	findings := make(chan *model.Finding, 10)
	err := m.parsePackageOutput(context.Background(), "openssl 3.2.0\n", "brew", findings)
	require.NoError(t, err)
	close(findings)

	finding := <-findings
	require.NotNil(t, finding)

	assert.Nil(t, finding.CryptoAsset)
	assert.Equal(t, "brew:openssl@3.2.0", finding.Source.Path)
	assert.Equal(t, "packages", finding.Module)
	assert.Equal(t, 1.0, finding.Confidence)
}
