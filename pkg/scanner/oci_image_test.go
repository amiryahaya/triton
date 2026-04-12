package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// fakeFetcher returns a pre-baked rootfs path without network access.
// Used by unit tests to exercise the full module path without pulling
// real images.
type fakeFetcher struct {
	rootFS  string
	ref     string
	digest  string
	layers  int
	sizeB   int64
	err     error
	cleaned bool
}

func (f *fakeFetcher) Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &fetchedImage{
		RootFS:    f.rootFS,
		Ref:       f.ref,
		Digest:    f.digest,
		LayerN:    f.layers,
		SizeBytes: f.sizeB,
		Cleanup: func() error {
			f.cleaned = true
			return nil
		},
	}, nil
}

func TestOCIImage_ModuleInterface(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "standard"}
	m := NewOCIImageModule(cfg)
	assert.Equal(t, "oci_image", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetOCIImage, m.ScanTargetType())
}

func TestOCIImage_FakeFetcherReturnsFixture(t *testing.T) {
	rootFS, err := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
	require.NoError(t, err)

	ff := &fakeFetcher{
		rootFS: rootFS,
		ref:    "nginx:1.25",
		digest: "sha256:abc123",
		layers: 3,
		sizeB:  50_000,
	}
	img, err := ff.Fetch(context.Background(), "nginx:1.25", ScanCredentials{})
	require.NoError(t, err)
	require.NotNil(t, img)
	assert.Equal(t, rootFS, img.RootFS)
	assert.Equal(t, "sha256:abc123", img.Digest)

	require.NoError(t, img.Cleanup())
	assert.True(t, ff.cleaned)
}

func TestOCIImage_HappyPathAnnotatesFindings(t *testing.T) {
	rootFS, err := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
	require.NoError(t, err)

	cfg := &scannerconfig.Config{
		Profile:         "standard",
		Modules:         []string{"certificates"},
		MaxFileSize:     100 * 1024 * 1024,
		IncludePatterns: []string{"*.pem", "*.crt", "*.cer", "*.key", "*.p12", "*.pfx", "*.jks"},
		ExcludePatterns: []string{},
		MaxDepth:        -1,
	}
	m := &OCIImageModule{
		config: cfg,
		fetcher: &fakeFetcher{
			rootFS: rootFS,
			ref:    "nginx:1.25",
			digest: "sha256:deadbeef",
			layers: 1,
			sizeB:  50_000,
		},
	}

	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings {
			collected = append(collected, f)
		}
	}()

	scanErr := m.Scan(context.Background(), model.ScanTarget{
		Type:  model.TargetOCIImage,
		Value: "nginx:1.25",
	}, findings)
	close(findings)
	<-done

	require.NoError(t, scanErr)
	require.NotEmpty(t, collected, "expected at least one finding from fixture cert")

	var annotated int
	for _, f := range collected {
		if f.CryptoAsset == nil {
			continue
		}
		if f.CryptoAsset.ImageRef == "nginx:1.25" &&
			f.CryptoAsset.ImageDigest == "sha256:deadbeef" {
			annotated++
		}
	}
	assert.Greater(t, annotated, 0, "expected annotated cert finding")
}

func TestOCIImage_FetcherErrorReturnsError(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OCIImageModule{
		config:  cfg,
		fetcher: &fakeFetcher{err: fmt.Errorf("network unreachable")},
	}
	findings := make(chan *model.Finding, 4)
	err := m.Scan(context.Background(), model.ScanTarget{
		Type:  model.TargetOCIImage,
		Value: "nginx:1.25",
	}, findings)
	close(findings)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch")
}

func TestOCIImage_SizeCapExceeded(t *testing.T) {
	rootFS, _ := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OCIImageModule{
		config: cfg,
		fetcher: &fakeFetcher{
			rootFS: rootFS,
			sizeB:  5 * 1024 * 1024 * 1024, // 5 GB > 4 GB cap
		},
	}
	findings := make(chan *model.Finding, 4)
	err := m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetOCIImage, Value: "huge:1.0",
	}, findings)
	close(findings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size cap")
}

func TestOCIImage_LayerCapExceeded(t *testing.T) {
	rootFS, _ := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
	cfg := &scannerconfig.Config{Profile: "standard"}
	m := &OCIImageModule{
		config: cfg,
		fetcher: &fakeFetcher{
			rootFS: rootFS,
			layers: 200, // > 128 cap
		},
	}
	findings := make(chan *model.Finding, 4)
	err := m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetOCIImage, Value: "deeplayers:1.0",
	}, findings)
	close(findings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "layer cap")
}

func TestOCIImage_RedactionNoPasswordInFindings(t *testing.T) {
	rootFS, _ := filepath.Abs("../../test/fixtures/oci/minimal-rootfs")
	cfg := &scannerconfig.Config{
		Profile: "standard",
		Modules: []string{"certificates"},
		Credentials: ScanCredentials{
			RegistryUsername: "alice",
			RegistryPassword: "super-secret-xyz",
		},
		IncludePatterns: []string{"*.pem"},
		MaxDepth:        -1,
		MaxFileSize:     100 * 1024 * 1024,
	}
	m := &OCIImageModule{
		config: cfg,
		fetcher: &fakeFetcher{
			rootFS: rootFS,
			ref:    "nginx:1.25",
			digest: "sha256:abc",
		},
	}
	findings := make(chan *model.Finding, 64)
	var collected []*model.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findings {
			collected = append(collected, f)
		}
	}()

	_ = m.Scan(context.Background(), model.ScanTarget{
		Type: model.TargetOCIImage, Value: "nginx:1.25",
	}, findings)
	close(findings)
	<-done

	for _, f := range collected {
		b, _ := json.Marshal(f)
		assert.NotContains(t, string(b), "super-secret-xyz",
			"password must never appear in findings")
	}
}
