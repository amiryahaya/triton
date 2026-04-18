package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// gracePeriod allows a short window after licence expiry before enforcement.
const gracePeriod = 5 * time.Minute

// License represents a signed licence token's claims.
type License struct {
	ID    string `json:"lid"`
	Tier  Tier   `json:"tier"`
	OrgID string `json:"oid,omitempty"` // Organization UUID (tenant identifier)
	Org   string `json:"org"`
	// Seats represents the number of machine-bound tokens the org is entitled to.
	// Enforcement is at keygen time; runtime binding is via MachineID.
	Seats     int    `json:"seats"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	MachineID string `json:"mid,omitempty"` // SHA-3-256 machine fingerprint

	// v2 claims (optional — legacy tokens omit these).
	Features      licensestore.Features `json:"features,omitempty"`
	Limits        licensestore.Limits   `json:"limits,omitempty"`
	SoftBufferPct int                   `json:"sbp,omitempty"`
	ProductScope  string                `json:"ps,omitempty"`
}

// IsExpired reports whether the licence has passed its expiry plus grace period.
func (l *License) IsExpired() bool {
	expiry := time.Unix(l.ExpiresAt, 0).Add(gracePeriod)
	return time.Now().After(expiry)
}

// Encode signs a licence with the given Ed25519 private key and returns
// a token in the format: base64url(claims).base64url(signature).
func Encode(l *License, privKey ed25519.PrivateKey) (string, error) {
	claimsJSON, err := json.Marshal(l)
	if err != nil {
		return "", fmt.Errorf("encoding claims: %w", err)
	}

	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := ed25519.Sign(privKey, claimsJSON)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return claimsB64 + "." + sigB64, nil
}

// Parse verifies and decodes a licence token using the given Ed25519 public key.
func Parse(token string, pubKey ed25519.PublicKey) (*License, error) {
	if token == "" {
		return nil, fmt.Errorf("empty licence token")
	}

	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed token: expected claims.signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	if !ed25519.Verify(pubKey, claimsJSON, sig) {
		return nil, fmt.Errorf("invalid signature")
	}

	var lic License
	if err := json.Unmarshal(claimsJSON, &lic); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	if lic.ID == "" {
		return nil, fmt.Errorf("missing required field: lid")
	}
	if lic.Tier == "" {
		return nil, fmt.Errorf("missing required field: tier")
	}

	if lic.IsExpired() {
		return nil, fmt.Errorf("licence expired at %s", time.Unix(lic.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}

	if lic.MachineID != "" && lic.MachineID != MachineFingerprint() {
		return nil, fmt.Errorf("licence bound to different machine")
	}

	return &lic, nil
}
