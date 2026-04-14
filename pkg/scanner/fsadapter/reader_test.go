package fsadapter

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalReader_ReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	require.NoError(t, os.WriteFile(path, []byte("world"), 0o644))

	r := NewLocalReader()
	data, err := r.ReadFile(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, "world", string(data))
}

func TestLocalReader_Walk(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("b"), 0o644))

	r := NewLocalReader()
	seen := make(map[string]bool)
	err := r.Walk(context.Background(), dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		seen[path] = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, seen[filepath.Join(dir, "a.txt")])
	assert.True(t, seen[filepath.Join(dir, "sub", "b.txt")])
}

func TestLocalReader_WalkCancelled(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "f"+string(rune('0'+i))), []byte{0}, 0o644))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := NewLocalReader()
	err := r.Walk(ctx, dir, func(_ string, _ fs.DirEntry, _ error) error {
		return nil
	})
	assert.ErrorIs(t, err, context.Canceled)
}
