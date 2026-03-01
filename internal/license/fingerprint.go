package license

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
)

// MachineFingerprint returns a deterministic SHA-256 hex digest derived from
// the hostname, OS, and architecture. This is used to bind licence tokens to
// a specific machine without requiring elevated privileges.
func MachineFingerprint() string {
	hostname, _ := os.Hostname()
	data := hostname + "|" + runtime.GOOS + "|" + runtime.GOARCH
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
