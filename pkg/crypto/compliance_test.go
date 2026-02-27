package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCompliance_CNSA2Approved(t *testing.T) {
	approved := []string{"AES-256-GCM", "ML-KEM-1024", "ML-DSA-87", "SHA-384", "SHA-512", "LMS", "XMSS"}

	for _, algo := range approved {
		t.Run(algo, func(t *testing.T) {
			ci := GetCompliance(algo)
			assert.True(t, ci.CNSA2Approved, "%s should be CNSA 2.0 approved", algo)
			assert.Equal(t, "Approved", ci.CNSA2Status)
		})
	}
}

func TestGetCompliance_CNSA2NotApproved(t *testing.T) {
	notApproved := []string{"RSA-2048", "ECDSA-P256", "AES-128-GCM", "DES", "RC4"}

	for _, algo := range notApproved {
		t.Run(algo, func(t *testing.T) {
			ci := GetCompliance(algo)
			assert.False(t, ci.CNSA2Approved, "%s should not be CNSA 2.0 approved", algo)
			assert.Equal(t, "Not Approved", ci.CNSA2Status)
		})
	}
}

func TestGetCompliance_NISTTimeline_RSA(t *testing.T) {
	ci := GetCompliance("RSA-2048")
	assert.Equal(t, 2030, ci.NISTDeprecatedYear)
	assert.Equal(t, 2035, ci.NISTDisallowedYear)
	assert.Contains(t, ci.Warning, "2030")
	assert.Contains(t, ci.Warning, "2035")
}

func TestGetCompliance_NISTTimeline_ECDSA(t *testing.T) {
	ci := GetCompliance("ECDSA-P256")
	assert.Equal(t, 2030, ci.NISTDeprecatedYear)
	assert.Equal(t, 2035, ci.NISTDisallowedYear)
}

func TestGetCompliance_NISTTimeline_DSA(t *testing.T) {
	ci := GetCompliance("DSA")
	assert.Equal(t, 2025, ci.NISTDeprecatedYear)
	assert.Equal(t, 2030, ci.NISTDisallowedYear)
}

func TestGetCompliance_NoNISTTimeline_Symmetric(t *testing.T) {
	ci := GetCompliance("AES-256-GCM")
	assert.Equal(t, 0, ci.NISTDeprecatedYear)
	assert.Equal(t, 0, ci.NISTDisallowedYear)
}

func TestGetCompliance_WarningUnsafe(t *testing.T) {
	ci := GetCompliance("DES")
	assert.Contains(t, ci.Warning, "CRITICAL")
	assert.Contains(t, ci.Warning, "Immediate replacement")
}

func TestGetCompliance_WarningDeprecated(t *testing.T) {
	ci := GetCompliance("MD5")
	assert.Contains(t, ci.Warning, "deprecated")
}

func TestGetCompliance_WarningTransitional(t *testing.T) {
	ci := GetCompliance("RSA-2048")
	assert.Contains(t, ci.Warning, "migration")
}

func TestGetCompliance_PQCSafeNoWarning(t *testing.T) {
	ci := GetCompliance("ML-KEM-1024")
	assert.True(t, ci.CNSA2Approved)
	assert.Empty(t, ci.Warning)
}

func TestGetCompliance_PQCNotInCNSA2(t *testing.T) {
	ci := GetCompliance("ML-KEM-512")
	assert.False(t, ci.CNSA2Approved)
	assert.Contains(t, ci.Warning, "not in CNSA 2.0")
}

func TestItoa(t *testing.T) {
	assert.Equal(t, "2030", itoa(2030))
	assert.Equal(t, "0", itoa(0))
	assert.Equal(t, "1", itoa(1))
}
