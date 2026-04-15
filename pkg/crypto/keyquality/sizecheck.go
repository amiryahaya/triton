package keyquality

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

// sizeMismatchCheck compares the caller-reported keySize against the actual
// bit length of the parsed public key. Applies only to RSA for now; other
// key types return ok=false.
//
// Tolerance: ±1 bit (real RSA keys sometimes come back 2047-bit).
// HIGH when |claimed - actual| ≥ 16 AND not in critical range.
// CRITICAL when claimed ≥ 2048 but actual < 1024.
func sizeMismatchCheck(pub crypto.PublicKey, claimed int) (Warning, bool) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok || rsaPub == nil || rsaPub.N == nil {
		return Warning{}, false
	}
	actual := rsaPub.N.BitLen()
	if claimed <= 0 || actual <= 0 {
		return Warning{}, false
	}
	delta := claimed - actual
	if delta < 0 {
		delta = -delta
	}
	if delta < 16 {
		return Warning{}, false
	}
	// Critical: claimed >= 2048 but actual modulus too small to resist modern attacks.
	if claimed >= 2048 && actual < 1024 {
		return Warning{
			Code:     CodeSizeMismatch,
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("claimed %d bits, actual modulus %d bits (catastrophically undersized)", claimed, actual),
		}, true
	}
	return Warning{
		Code:     CodeSizeMismatch,
		Severity: SeverityHigh,
		Message:  fmt.Sprintf("claimed %d bits, actual modulus %d bits", claimed, actual),
	}, true
}
