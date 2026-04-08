package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// MinPasswordLength is the minimum character count required for any
// user-facing password on the Triton report server and license server.
// This single constant replaces per-handler duplicates that made it
// easy to drift the policy across endpoints during Phases 1–3.
//
// The value is 12, chosen to match OWASP 2021 guidance (minimum 8 but
// >= 12 recommended) without crossing into the >14 territory where
// users start using predictable patterns. Raising this later requires
// touching both server Go constants AND the two UI `minlength`
// attributes — grep for MinPasswordLength when changing.
const MinPasswordLength = 12

// GenerateTempPassword returns a cryptographically random base64url
// password of the given character length. 24 chars ≈ 144 bits of
// entropy, well above the 12-char minimum. Used by the license
// server's provisioning flow and by the report server's
// resend-invite endpoint.
//
// length must be > 0; values <= 0 are clamped to 24.
func GenerateTempPassword(length int) (string, error) {
	if length <= 0 {
		length = 24
	}
	// base64url expands 3 bytes to 4 chars, so we need ceil(length*3/4)
	// raw bytes to produce at least `length` encoded chars.
	rawBytes := (length*3 + 3) / 4
	raw := make([]byte, rawBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating temp password: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) > length {
		encoded = encoded[:length]
	}
	return encoded, nil
}
