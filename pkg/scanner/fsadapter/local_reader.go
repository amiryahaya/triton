package fsadapter

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
)

// LocalReader reads from the local filesystem via the stdlib os/filepath
// packages. Zero overhead vs direct os.ReadFile calls.
type LocalReader struct{}

// NewLocalReader returns a ready-to-use LocalReader.
func NewLocalReader() *LocalReader {
	return &LocalReader{}
}

func (l *LocalReader) ReadFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (l *LocalReader) Stat(_ context.Context, path string) (fs.FileInfo, error) {
	return os.Stat(path)
}

func (l *LocalReader) ReadDir(_ context.Context, path string) ([]fs.DirEntry, error) {
	return os.ReadDir(path)
}

func (l *LocalReader) Walk(ctx context.Context, root string, fn WalkFunc) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// Honor cancellation between entries.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fn(path, d, err)
	})
}
