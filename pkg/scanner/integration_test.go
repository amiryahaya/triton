package scanner

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixturesDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "test", "fixtures")
}

func TestIntegrationEngineWithFixtures(t *testing.T) {
	cfg := &config.Config{
		Profile: "quick",
		Workers: 4,
		ScanTargets: []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 5},
		},
	}

	eng := New(cfg)
	eng.RegisterModule(NewCertificateModule(cfg))
	eng.RegisterModule(NewKeyModule(cfg))

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	result := eng.Scan(ctx, progressCh)

	require.NotNil(t, result)
	assert.NotEmpty(t, result.ID)
	assert.NotEmpty(t, result.Metadata.Hostname)
	assert.True(t, result.Metadata.Duration > 0)

	// Should find certificates and keys from fixtures
	assert.NotEmpty(t, result.Findings, "should have findings from fixture files")

	// Verify we have certificate findings
	var certFindings, keyFindings int
	for _, f := range result.Findings {
		switch f.Module {
		case "certificates":
			certFindings++
		case "keys":
			keyFindings++
		}
	}
	assert.True(t, certFindings > 0, "should find certificates from fixtures (found %d)", certFindings)
	assert.True(t, keyFindings > 0, "should find keys from fixtures (found %d)", keyFindings)

	// Verify finding structure
	for _, f := range result.Findings {
		assert.NotEmpty(t, f.ID, "every finding should have an ID")
		assert.NotEmpty(t, f.Source.Type, "every finding should have a source type")
		assert.NotEmpty(t, f.Source.Path, "every finding should have a source path")
		assert.NotEmpty(t, f.Module, "every finding should have a module name")
		assert.True(t, f.Confidence > 0, "every finding should have confidence > 0")
	}

	// Verify certificate findings have crypto assets with proper fields
	for _, f := range result.Findings {
		if f.Module == "certificates" {
			require.NotNil(t, f.CryptoAsset, "certificate findings must have CryptoAsset")
			assert.NotEmpty(t, f.CryptoAsset.Algorithm, "certificate should have algorithm")
			assert.True(t, f.CryptoAsset.KeySize > 0, "certificate should have key size")
			assert.NotEmpty(t, f.CryptoAsset.Subject, "certificate should have subject")
			assert.NotEmpty(t, f.CryptoAsset.Issuer, "certificate should have issuer")
		}
	}

	// Verify summary is computed
	assert.Equal(t, len(result.Findings), result.Summary.TotalFindings)
}

func TestIntegrationCertificateScanFixtures(t *testing.T) {
	certDir := filepath.Join(fixturesDir(), "certificates")
	cfg := &config.Config{}

	m := NewCertificateModule(cfg)
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: certDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// 6 PEM certs + 1 DER cert + 2 in chain.pem = 9 total
	assert.GreaterOrEqual(t, len(collected), 8, "should find at least 8 certificates")

	// Check algorithm diversity
	algos := make(map[string]bool)
	for _, f := range collected {
		if f.CryptoAsset != nil {
			algos[f.CryptoAsset.Algorithm] = true
		}
	}
	// Should have RSA, ECDSA, and Ed25519 certs
	assert.True(t, len(algos) >= 3, "should find at least 3 different algorithms, got: %v", algos)
}

func TestIntegrationKeyScanFixtures(t *testing.T) {
	keyDir := filepath.Join(fixturesDir(), "keys")
	cfg := &config.Config{}

	m := NewKeyModule(cfg)
	findings := make(chan *model.Finding, 50)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: keyDir, Depth: 1}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	// 5 key files
	assert.GreaterOrEqual(t, len(collected), 5, "should find at least 5 key files")

	// Check key type diversity
	keyTypes := make(map[string]bool)
	for _, f := range collected {
		if f.CryptoAsset != nil {
			keyTypes[f.CryptoAsset.Function] = true
		}
	}
	assert.True(t, len(keyTypes) >= 3, "should find at least 3 different key types, got: %v", keyTypes)
}

func TestIntegrationProgressReporting(t *testing.T) {
	cfg := &config.Config{
		Profile: "quick",
		Workers: 2,
		ScanTargets: []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 5},
		},
	}

	eng := New(cfg)
	eng.RegisterModule(NewCertificateModule(cfg))
	eng.RegisterModule(NewKeyModule(cfg))

	ctx := context.Background()
	progressCh := make(chan Progress, 100)
	eng.Scan(ctx, progressCh)

	var messages []Progress
	for p := range progressCh {
		messages = append(messages, p)
	}

	require.NotEmpty(t, messages)
	last := messages[len(messages)-1]
	assert.True(t, last.Complete)
	assert.NotNil(t, last.Result)
}

func TestRegisterDefaultModules(t *testing.T) {
	cfg := &config.Config{
		Profile: "quick",
		Workers: 2,
	}
	eng := New(cfg)
	eng.RegisterDefaultModules()

	assert.Len(t, eng.modules, 3)

	names := make([]string, len(eng.modules))
	for i, m := range eng.modules {
		names[i] = m.Name()
	}
	assert.Contains(t, names, "certificates")
	assert.Contains(t, names, "keys")
	assert.Contains(t, names, "packages")
}

func TestShouldRunModuleWithFilter(t *testing.T) {
	cfg := &config.Config{
		Modules: []string{"certificates"},
		Workers: 2,
	}
	eng := New(cfg)

	certModule := NewCertificateModule(cfg)
	keyModule := NewKeyModule(cfg)

	assert.True(t, eng.shouldRunModule(certModule))
	assert.False(t, eng.shouldRunModule(keyModule))
}
