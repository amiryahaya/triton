package scanner

import (
	"context"
)

// imageFetcher abstracts image pull + layer extraction so unit tests
// can substitute a fake that returns a pre-baked rootfs. The real
// implementation lives in oci_image_remote.go (Task 13) and uses
// github.com/google/go-containerregistry.
type imageFetcher interface {
	Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error)
}

// fetchedImage is the result of pulling and extracting an OCI image.
// RootFS is a local filesystem path the caller may walk like any other
// filesystem target. Cleanup must be called when the caller is done
// (typically via defer) to remove the sandbox.
type fetchedImage struct {
	RootFS    string // extracted rootfs path
	Ref       string // canonical image ref
	Digest    string // sha256:... manifest digest
	LayerN    int    // layer count after flatten
	SizeBytes int64  // total uncompressed size
	Cleanup   func() error
}
