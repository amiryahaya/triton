package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// UserClaims represents JWT claims for human users.
type UserClaims struct {
	Sub  string `json:"sub"`           // user UUID
	Org  string `json:"org,omitempty"` // org UUID (empty for platform admin)
	Role string `json:"role"`          // platform_admin, org_admin, org_user
	Name string `json:"name"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

// jwtHeader is the fixed EdDSA/JWT header emitted by SignJWT.
// Pre-computed at package init so we don't re-serialize on every call.
var jwtHeaderB64 = func() string {
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	return base64.RawURLEncoding.EncodeToString(h)
}()

// SignJWT creates an Ed25519-signed JWT from user claims. The emitted token
// has the standard three-part JWT structure: header.payload.signature, where
// the header declares alg=EdDSA and typ=JWT.
//
// SignJWT does not mutate the passed-in claims struct — it copies the struct
// before setting Iat and Exp, so callers can log or reuse their claims value
// without surprise.
func SignJWT(claims *UserClaims, privKey ed25519.PrivateKey, ttl time.Duration) (string, error) {
	// Defensive copy: never mutate the caller's struct.
	c := *claims
	now := time.Now()
	c.Iat = now.Unix()
	c.Exp = now.Add(ttl).Unix()

	payload, err := json.Marshal(&c)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	b64Payload := base64.RawURLEncoding.EncodeToString(payload)

	// Standard JWT: sign over "header.payload" (the signing input), not just
	// payload. This is what RFC 7519 compliant verifiers expect.
	signingInput := jwtHeaderB64 + "." + b64Payload
	sig := ed25519.Sign(privKey, []byte(signingInput))
	b64Sig := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + b64Sig, nil
}

// VerifyJWT parses and verifies a standard three-part JWT signed with Ed25519.
// It enforces alg=EdDSA in the header and checks that the token has not expired.
func VerifyJWT(token string, pubKey ed25519.PublicKey) (*UserClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unmarshalling header: %w", err)
	}
	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("unexpected alg %q, want EdDSA", header.Alg)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}

	// Signature is over "header.payload" (the signing input), matching the
	// format produced by SignJWT.
	signingInput := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(pubKey, signingInput, sig) {
		return nil, errors.New("invalid signature")
	}

	var claims UserClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshalling claims: %w", err)
	}
	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}
