//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

const testOCIImageRef = "cgr.dev/chainguard/static:latest"

func TestIntegration_OCIImage_RealPull(t *testing.T) {
	if os.Getenv("TRITON_SKIP_NETWORK_TESTS") != "" {
		t.Skip("TRITON_SKIP_NETWORK_TESTS set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := &scannerconfig.Config{
		Profile:         "standard",
		Modules:         []string{"certificates"},
		MaxFileSize:     100 * 1024 * 1024,
		MaxDepth:        -1,
		IncludePatterns: []string{"*.pem", "*.crt", "*.cer"},
		ExcludePatterns: []string{},
	}
	m := scanner.NewOCIImageModule(cfg)
	findings := make(chan *model.Finding, 256)

	done := make(chan error, 1)
	go func() {
		done <- m.Scan(ctx, model.ScanTarget{
			Type:  model.TargetOCIImage,
			Value: testOCIImageRef,
		}, findings)
		close(findings)
	}()

	var total, annotated int
	for f := range findings {
		total++
		if f.CryptoAsset != nil &&
			f.CryptoAsset.ImageRef != "" &&
			strings.HasPrefix(f.CryptoAsset.ImageDigest, "sha256:") {
			annotated++
		}
	}

	err := <-done
	require.NoError(t, err, "real image pull failed")
	assert.Greater(t, total, 0, "expected at least one finding from chainguard image")
	assert.Equal(t, total, annotated, "every finding must be annotated with ImageRef + ImageDigest")
}

func TestIntegration_OCIImage_InvalidRef(t *testing.T) {
	if os.Getenv("TRITON_SKIP_NETWORK_TESTS") != "" {
		t.Skip("TRITON_SKIP_NETWORK_TESTS set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := &scannerconfig.Config{
		Profile:     "standard",
		MaxFileSize: 100 * 1024 * 1024,
		MaxDepth:    -1,
	}
	m := scanner.NewOCIImageModule(cfg)
	findings := make(chan *model.Finding, 16)
	err := m.Scan(ctx, model.ScanTarget{
		Type:  model.TargetOCIImage,
		Value: "does.not.exist.example.invalid/nothing:nothing",
	}, findings)
	close(findings)

	require.Error(t, err, "invalid ref should return error without panicking")
}
