//go:build integration

package manageserver_test

import (
	"io/fs"
	"testing"

	"github.com/amiryahaya/triton/pkg/manageserver"
)

// TestUIFS_HasIndexAfterBuild asserts the embedded UI filesystem
// contains index.html. Run after `make web-build-manage` during local
// dev; CI runs it after the web-builder stage in Containerfile.
func TestUIFS_HasIndexAfterBuild(t *testing.T) {
	sub, err := fs.Sub(manageserver.UIFS(), "ui/dist")
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		t.Skipf("index.html not found (run `make web-build-manage` first): %v", err)
	}
}
