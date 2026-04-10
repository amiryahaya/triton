package licenseserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// installTokenClaims is the payload embedded in an install token.
type installTokenClaims struct {
	LicenseID string `json:"lid"`
	ExpiresAt int64  `json:"exp"`
}

// deriveInstallHMACKey derives a dedicated HMAC key from the Ed25519
// signing key seed using HKDF with a domain-separated label. This
// ensures the HMAC key material is cryptographically independent from
// the Ed25519 signing key, avoiding key confusion between schemes
// (NIST SP 800-133, RFC 8032 guidance).
func deriveInstallHMACKey(seed []byte) []byte {
	r := hkdf.New(sha256.New, seed, nil, []byte("triton-install-token-v1"))
	key := make([]byte, 32)
	_, _ = io.ReadFull(r, key)
	return key
}

// GenerateInstallToken creates an HMAC-signed install token.
// hmacSecret should be the Ed25519 signing key's 32-byte seed;
// a dedicated HMAC key is derived via HKDF before signing.
// Returns error if licenseID is empty.
func GenerateInstallToken(hmacSecret []byte, licenseID string, ttl time.Duration) (string, error) {
	if licenseID == "" {
		return "", errors.New("licenseID must not be empty")
	}

	claims := installTokenClaims{
		LicenseID: licenseID,
		ExpiresAt: time.Now().Add(ttl).Unix(),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	derivedKey := deriveInstallHMACKey(hmacSecret)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	sig := hmacSign(derivedKey, []byte(encodedPayload))
	encodedSig := base64.RawURLEncoding.EncodeToString(sig)

	return encodedPayload + "." + encodedSig, nil
}

// ValidateInstallToken verifies HMAC signature and checks expiry.
// Returns decoded claims on success, error on invalid/expired/tampered.
func ValidateInstallToken(hmacSecret []byte, token string) (*installTokenClaims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}

	encodedPayload := parts[0]
	encodedSig := parts[1]

	derivedKey := deriveInstallHMACKey(hmacSecret)
	expectedSig := hmacSign(derivedKey, []byte(encodedPayload))
	expectedEncodedSig := base64.RawURLEncoding.EncodeToString(expectedSig)

	if !hmac.Equal([]byte(encodedSig), []byte(expectedEncodedSig)) {
		return nil, errors.New("invalid token signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, errors.New("invalid token encoding")
	}

	var claims installTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("invalid token payload")
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

// hmacSign is a private helper that HMAC-SHA256 signs a message.
func hmacSign(secret, message []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return mac.Sum(nil)
}
