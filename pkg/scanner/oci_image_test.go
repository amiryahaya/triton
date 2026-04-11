package scanner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
