package keyquality

import (
	"crypto"
	"crypto/sha1" //nolint:gosec
	"crypto/x509"
)

func publicKeyFingerprintForTest(pub crypto.PublicKey) [20]byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [20]byte{}
	}
	return sha1.Sum(der) //nolint:gosec
}

func injectBlocklistFingerprintForTest(set fingerprintSet, fp [20]byte) {
	set[fp] = struct{}{}
}

func removeBlocklistFingerprintForTest(set fingerprintSet, fp [20]byte) {
	delete(set, fp)
}
