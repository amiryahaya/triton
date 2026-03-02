package license

import (
	"encoding/hex"
	"os"
	"runtime"

	"golang.org/x/crypto/sha3"
)

// MachineFingerprint returns a deterministic SHA-3-256 hex digest derived from
// the hostname, OS, and architecture. This is used to bind licence tokens to
// a specific machine without requiring elevated privileges.
func MachineFingerprint() string {
	hostname, _ := os.Hostname()
	data := hostname + "|" + runtime.GOOS + "|" + runtime.GOARCH
	hash := sha3.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
