package license

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/licensestore"
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

func TestCacheMeta_V2Roundtrip(t *testing.T) {
	orig := &CacheMeta{
		ServerURL:     "https://license.example",
		LicenseID:     "L1",
		Tier:          "enterprise",
		Seats:         50,
		SeatsUsed:     12,
		ExpiresAt:     "2027-01-01T00:00:00Z",
		LastValidated: time.Now(),
		Features: licensestore.Features{
			Report: true, Manage: true, DiffTrend: true,
		},
		Limits: licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 50},
		},
		SoftBufferPct: 10,
		ProductScope:  "bundle",
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "license.meta")
	if err := orig.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCacheMeta(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Features.Report || !loaded.Features.Manage {
		t.Errorf("features not round-tripped: %+v", loaded.Features)
	}
	if loaded.ProductScope != "bundle" {
		t.Errorf("product_scope: %q", loaded.ProductScope)
	}
	if e := loaded.Limits.Find("seats", "total"); e == nil || e.Cap != 50 {
		t.Errorf("limits: %+v", loaded.Limits)
	}
}

func TestCacheMeta_V1LegacyRoundtrip(t *testing.T) {
	// Legacy cache without v2 fields should still Load cleanly.
	dir := t.TempDir()
	path := filepath.Join(dir, "license.meta")
	legacy := `{"serverURL":"x","licenseID":"L1","tier":"pro","seats":10,"seatsUsed":2,"expiresAt":"2027-01-01","lastValidated":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCacheMeta(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Tier != "pro" {
		t.Errorf("legacy tier")
	}
	if loaded.Features.Report {
		t.Errorf("legacy cache should have empty features, got %+v", loaded.Features)
	}
	if loaded.ProductScope != "" {
		t.Errorf("legacy scope should be empty, got %q", loaded.ProductScope)
	}
}
