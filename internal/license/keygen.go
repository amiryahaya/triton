package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"github.com/google/uuid"
)

// GenerateKeypair creates a new Ed25519 keypair for licence signing.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// IssueToken creates a signed licence token.
func IssueToken(privKey ed25519.PrivateKey, tier Tier, org string, seats, days int) (string, error) {
	lic := &License{
		ID:        uuid.New().String(),
		Tier:      tier,
		Org:       org,
		Seats:     seats,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix(),
	}
	return Encode(lic, privKey)
}
