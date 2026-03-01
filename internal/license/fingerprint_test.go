package license

import (
	"encoding/hex"
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
	assert.Len(t, fp, 64, "SHA-256 hex digest should be 64 characters")
}

func TestMachineFingerprint_IsHex(t *testing.T) {
	fp := MachineFingerprint()
	_, err := hex.DecodeString(fp)
	require.NoError(t, err, "fingerprint should be valid hex")
}
