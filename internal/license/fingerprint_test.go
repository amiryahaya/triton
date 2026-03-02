package license

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineFingerprint_Deterministic(t *testing.T) {
	fp1 := MachineFingerprint()
	fp2 := MachineFingerprint()
	assert.Equal(t, fp1, fp2, "two calls should return the same fingerprint")
}

func TestMachineFingerprint_NonEmpty(t *testing.T) {
	fp := MachineFingerprint()
	assert.Len(t, fp, 64, "SHA-3-256 hex digest should be 64 characters")
}

func TestMachineFingerprint_IsHex(t *testing.T) {
	fp := MachineFingerprint()
	_, err := hex.DecodeString(fp)
	require.NoError(t, err, "fingerprint should be valid hex")
}

func TestMachineFingerprint_NotSHA256(t *testing.T) {
	// Verify the fingerprint uses SHA-3-256, not SHA-256.
	hostname, _ := os.Hostname()
	data := hostname + "|" + runtime.GOOS + "|" + runtime.GOARCH
	sha256Hash := sha256.Sum256([]byte(data))
	sha256Hex := hex.EncodeToString(sha256Hash[:])

	fp := MachineFingerprint()
	assert.NotEqual(t, sha256Hex, fp, "fingerprint should use SHA-3-256, not SHA-256")
}
