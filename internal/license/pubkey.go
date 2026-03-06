package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"log"
)

// publicKeyHex is the Ed25519 public key used to verify licence tokens.
// Override at build time with:
//
//	go build -ldflags "-X github.com/amiryahaya/triton/internal/license.publicKeyHex=<hex>"
var publicKeyHex = "0000000000000000000000000000000000000000000000000000000000000000"

// loadPublicKey decodes the hex-encoded public key. Falls back to a zeroed key
// on error (which will fail all signature checks, resulting in free tier).
func loadPublicKey() ed25519.PublicKey {
	key, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		log.Printf("warning: invalid embedded public key, licence verification will fail")
		return make(ed25519.PublicKey, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key)
}

// LoadPublicKeyBytes returns the embedded Ed25519 public key for external use
// (e.g. server-side token verification). Returns nil if the key is invalid.
func LoadPublicKeyBytes() ed25519.PublicKey {
	key, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil
	}
	// Check if it's the zeroed placeholder key.
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil
	}
	return ed25519.PublicKey(key)
}
