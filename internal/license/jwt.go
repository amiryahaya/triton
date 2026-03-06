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

// SignJWT creates an Ed25519-signed JWT from user claims.
func SignJWT(claims *UserClaims, privKey ed25519.PrivateKey, ttl time.Duration) (string, error) {
	now := time.Now()
	claims.Iat = now.Unix()
	claims.Exp = now.Add(ttl).Unix()
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	b64Payload := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(privKey, payload)
	b64Sig := base64.RawURLEncoding.EncodeToString(sig)
	return b64Payload + "." + b64Sig, nil
}

// VerifyJWT parses and verifies an Ed25519-signed JWT.
func VerifyJWT(token string, pubKey ed25519.PublicKey) (*UserClaims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	if !ed25519.Verify(pubKey, payload, sig) {
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
