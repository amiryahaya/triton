package license

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CacheMeta stores license server metadata locally for offline fallback.
type CacheMeta struct {
	ServerURL     string    `json:"serverURL"`
	LicenseID     string    `json:"licenseID"`
	Tier          string    `json:"tier"`
	Seats         int       `json:"seats"`
	SeatsUsed     int       `json:"seatsUsed"`
	ExpiresAt     string    `json:"expiresAt"`
	LastValidated time.Time `json:"lastValidated"`
}

// GracePeriodDays is the number of days a cached token remains valid
// when the license server is unreachable.
const GracePeriodDays = 5

// DefaultCacheMetaPath returns ~/.triton/license.meta.
func DefaultCacheMetaPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".triton", "license.meta")
}

// LoadCacheMeta reads the cache metadata file.
func LoadCacheMeta(path string) (*CacheMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading cache meta: %w", err)
	}
	var meta CacheMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parsing cache meta: %w", err)
	}
	return &meta, nil
}

// Save writes the cache metadata to disk atomically (write temp + rename).
func (m *CacheMeta) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling cache meta: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing temp cache meta: %w", err)
	}
	return os.Rename(tmp, path)
}

// IsFresh returns true if the cache was validated within the grace period.
func (m *CacheMeta) IsFresh() bool {
	return time.Since(m.LastValidated) < time.Duration(GracePeriodDays)*24*time.Hour
}

// RemoveCacheMeta deletes the cache metadata file.
func RemoveCacheMeta(path string) {
	_ = os.Remove(path)
}
