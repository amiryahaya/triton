package license

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheMeta_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".triton", "license.meta")

	meta := &CacheMeta{
		ServerURL:     "http://localhost:8081",
		LicenseID:     "lic-123",
		Tier:          "pro",
		Seats:         5,
		SeatsUsed:     2,
		ExpiresAt:     "2027-01-01T00:00:00Z",
		LastValidated: time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, meta.Save(path))

	loaded, err := LoadCacheMeta(path)
	require.NoError(t, err)
	assert.Equal(t, meta.ServerURL, loaded.ServerURL)
	assert.Equal(t, meta.LicenseID, loaded.LicenseID)
	assert.Equal(t, meta.Tier, loaded.Tier)
	assert.Equal(t, meta.Seats, loaded.Seats)
}

func TestCacheMeta_LoadNotFound(t *testing.T) {
	_, err := LoadCacheMeta("/nonexistent/path")
	require.Error(t, err)
}

func TestCacheMeta_IsFresh(t *testing.T) {
	fresh := &CacheMeta{LastValidated: time.Now().Add(-24 * time.Hour)}
	assert.True(t, fresh.IsFresh(), "1 day old should be fresh")

	stale := &CacheMeta{LastValidated: time.Now().Add(-8 * 24 * time.Hour)}
	assert.False(t, stale.IsFresh(), "8 days old should be stale")
}

func TestRemoveCacheMeta(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "license.meta")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0600))

	RemoveCacheMeta(path)
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestCacheMeta_SaveCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deep", "nested", "license.meta")

	meta := &CacheMeta{ServerURL: "http://localhost:8081"}
	require.NoError(t, meta.Save(path))

	_, err := os.Stat(path)
	require.NoError(t, err)
}
