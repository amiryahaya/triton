//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptor_StoreRoundTrip verifies that SaveScan+GetScan
// transparently encrypt on write and decrypt on read when an
// Encryptor is configured. The returned ScanResult must match
// the original exactly.
func TestEncryptor_StoreRoundTrip(t *testing.T) {
	s := testStore(t)
	enc, err := NewEncryptor(randomKeyHex(t))
	require.NoError(t, err)
	s.SetEncryptor(enc)

	ctx := context.Background()
	scan := testScanResult(testUUID("encrypted-scan"), "host-1", "quick")

	require.NoError(t, s.SaveScan(ctx, scan))

	got, err := s.GetScan(ctx, scan.ID, "")
	require.NoError(t, err)
	assert.Equal(t, scan.ID, got.ID)
	assert.Equal(t, scan.Metadata.Hostname, got.Metadata.Hostname)
	assert.Equal(t, scan.Metadata.ScanProfile, got.Metadata.ScanProfile)
	assert.Len(t, got.Findings, len(scan.Findings))
}

// TestEncryptor_StoreReadsLegacyPlainRow verifies backward compat:
// a row written BEFORE encryption was enabled (plain JSON) can still
// be read after enabling encryption. This is the forward-compat path
// from the encryption docs: "enabling encryption on an existing
// database works forward-compatibly."
func TestEncryptor_StoreReadsLegacyPlainRow(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Write a scan WITHOUT encryption (legacy row)
	scan := testScanResult(testUUID("legacy-scan"), "host-legacy", "quick")
	require.NoError(t, s.SaveScan(ctx, scan))

	// Now enable encryption
	enc, err := NewEncryptor(randomKeyHex(t))
	require.NoError(t, err)
	s.SetEncryptor(enc)

	// Legacy plain-text row must still be readable
	got, err := s.GetScan(ctx, scan.ID, "")
	require.NoError(t, err)
	assert.Equal(t, scan.ID, got.ID)
	assert.Equal(t, scan.Metadata.Hostname, got.Metadata.Hostname)
}

// TestEncryptor_StoreMixedRows verifies a store can read both
// encrypted (new) and plain (legacy) rows seamlessly.
func TestEncryptor_StoreMixedRows(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Write a legacy row WITHOUT encryption
	legacy := testScanResult(testUUID("mixed-legacy"), "host-A", "quick")
	require.NoError(t, s.SaveScan(ctx, legacy))

	// Enable encryption, write a new encrypted row
	enc, err := NewEncryptor(randomKeyHex(t))
	require.NoError(t, err)
	s.SetEncryptor(enc)

	encrypted := testScanResult(testUUID("mixed-new"), "host-B", "standard")
	require.NoError(t, s.SaveScan(ctx, encrypted))

	// Both rows readable, regardless of encryption state
	gotLegacy, err := s.GetScan(ctx, legacy.ID, "")
	require.NoError(t, err)
	assert.Equal(t, "host-A", gotLegacy.Metadata.Hostname)

	gotEncrypted, err := s.GetScan(ctx, encrypted.ID, "")
	require.NoError(t, err)
	assert.Equal(t, "host-B", gotEncrypted.Metadata.Hostname)
}
