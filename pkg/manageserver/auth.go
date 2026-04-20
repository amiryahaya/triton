package manageserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/pkg/managestore"
)

// JWTClaims are the payload fields for Manage Server HS256 JWTs.
//
// The Mcp ("must change password") field is a one-bit hint the frontend route
// guard reads without a /me round-trip. It mirrors ManageUser.MustChangePW at
// the moment the token was minted; after a successful /auth/change-password
// flow the next JWT carries Mcp=false.
type JWTClaims struct {
	Sub  string `json:"sub"`  // user UUID
	Role string `json:"role"` // "admin" | "network_engineer"
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
	Jti  int64  `json:"jti,omitempty"` // nanosecond nonce — guarantees uniqueness across same-second issues
	Mcp  bool   `json:"mcp,omitempty"` // must_change_password — frontend guard pushes user to /auth/change-password
}

// jwtHeader is the fixed header for HS256 JWTs, pre-encoded.
var jwtHeaderB64 = func() string {
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	return base64.RawURLEncoding.EncodeToString(h)
}()

// signJWT creates an HS256-signed JWT from claims.
func signJWT(claims JWTClaims, key []byte) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	msg := jwtHeaderB64 + "." + payloadB64
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msg))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return msg + "." + sig, nil
}

// parseJWT verifies the HS256 signature and decodes the payload.
// Returns an error if the signature is invalid or the token is expired.
func parseJWT(token string, key []byte) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token: expected 3 parts")
	}
	msg := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msg))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, errors.New("invalid token signature")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims JWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

// hashToken returns the SHA-256 hex digest of the raw token string.
// Used as the session key in the DB so raw tokens are never stored.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// HashPassword bcrypt-hashes a plaintext password.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(h), nil
}

// VerifyPassword checks a plaintext password against a bcrypt hash.
func VerifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// contextWithUser stores a ManageUser in context under userCtxKey.
func contextWithUser(ctx context.Context, u *managestore.ManageUser) context.Context {
	return context.WithValue(ctx, userCtxKey, u)
}
