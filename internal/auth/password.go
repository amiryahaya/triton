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
// password of approximately the given character length. Used by the
// license server's provisioning flow and by the report server's
// resend-invite endpoint.
//
// Implementation note: base64url encodes 3 input bytes to exactly 4
// output characters (no padding in RawURLEncoding). We compute the
// number of raw bytes as ceil(length*3/4); the encoder will then
// produce exactly `length` rounded up to the nearest multiple of 4
// characters. For common lengths like 24, the result is exact. For
// other lengths the caller may observe up to 3 extra characters —
// that's fine, more entropy is not a bug.
//
// length must be > 0; values <= 0 are clamped to 24.
func GenerateTempPassword(length int) (string, error) {
	if length <= 0 {
		length = 24
	}
	rawBytes := (length*3 + 3) / 4
	raw := make([]byte, rawBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating temp password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
