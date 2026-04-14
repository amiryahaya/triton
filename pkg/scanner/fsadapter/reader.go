// Package fsadapter decouples scanner modules from the source of file
// I/O. LocalReader wraps os/filepath. SshReader (Task 6) executes
// commands over SSH. Modules use FileReader without caring which they got.
package fsadapter

import (
	"context"
	"io/fs"
)

// WalkFunc is called for every entry discovered during Walk.
// Implementations should skip entries where err != nil (best-effort scan).
type WalkFunc func(path string, entry fs.DirEntry, err error) error

// FileReader abstracts file I/O for scanner modules.
type FileReader interface {
	// ReadFile returns the contents of the file at path.
	ReadFile(ctx context.Context, path string) ([]byte, error)

	// Stat returns file metadata without reading contents.
	Stat(ctx context.Context, path string) (fs.FileInfo, error)

	// ReadDir returns the direct children of path.
	ReadDir(ctx context.Context, path string) ([]fs.DirEntry, error)

	// Walk recursively walks entries under root, calling fn for each.
	// Implementations may optimize: LocalReader uses filepath.WalkDir;
	// SshReader issues a single 'find' command.
	Walk(ctx context.Context, root string, fn WalkFunc) error
}
