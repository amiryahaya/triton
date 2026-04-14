package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

type stubFile struct {
	name string
	data []byte
}

func (s stubFile) Name() string               { return s.name }
func (s stubFile) Size() int64                { return int64(len(s.data)) }
func (s stubFile) Mode() fs.FileMode          { return 0644 }
func (s stubFile) ModTime() time.Time         { return time.Now() }
func (s stubFile) IsDir() bool                { return false }
func (s stubFile) Sys() any                   { return nil }
func (s stubFile) Type() fs.FileMode          { return 0 }
func (s stubFile) Info() (fs.FileInfo, error) { return s, nil }

type inMemReader struct {
	root  string
	files map[string][]byte
}

func (r *inMemReader) ReadFile(ctx context.Context, p string) ([]byte, error) {
	if b, ok := r.files[p]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}
func (r *inMemReader) Stat(ctx context.Context, p string) (fs.FileInfo, error) {
	if b, ok := r.files[p]; ok {
		return stubFile{name: filepath.Base(p), data: b}, nil
	}
	return nil, os.ErrNotExist
}
func (r *inMemReader) ReadDir(ctx context.Context, p string) ([]fs.DirEntry, error) {
	return nil, nil
}
func (r *inMemReader) Walk(ctx context.Context, root string, fn fsadapter.WalkFunc) error {
	for p, b := range r.files {
		if err := fn(p, stubFile{name: filepath.Base(p), data: b}, nil); err != nil {
			return err
		}
	}
	return nil
}

func TestCertificateModuleUsesInjectedReader(t *testing.T) {
	pem, err := os.ReadFile("testdata/certs/rsa2048.pem")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}

	reader := &inMemReader{
		root:  "/remote/etc/ssl",
		files: map[string][]byte{"/remote/etc/ssl/cert.pem": pem},
	}

	m := NewCertificateModule(&scannerconfig.Config{})
	m.SetFileReader(reader)

	findings := make(chan *model.Finding, 10)
	go func() {
		_ = m.Scan(context.Background(), model.ScanTarget{
			Type:  model.TargetFilesystem,
			Value: "/remote/etc/ssl",
		}, findings)
		close(findings)
	}()

	got := 0
	for range findings {
		got++
	}
	if got == 0 {
		t.Fatal("expected at least one finding from injected reader")
	}
}
