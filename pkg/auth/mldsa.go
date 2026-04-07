package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/amiryahaya/platform/go/pqcjwt"
)

// HybridVerifier verifies both ML-DSA-65 and standard (ES256/RS256) JWT tokens.
// ML-DSA-65 verification is delegated to the pqcjwt SDK; standard algorithms
// are handled by the existing OIDCVerifier.
type HybridVerifier struct {
	oidcVerifier *OIDCVerifier
	pqcVerifier  *pqcjwt.Verifier
}

// NewHybridVerifier creates a verifier that handles both ML-DSA-65 and standard tokens.
func NewHybridVerifier(ctx context.Context, cfg OIDCConfig) (*HybridVerifier, error) {
	oidcVerifier, err := NewVerifier(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC verifier: %w", err)
	}

	normalizedIssuer := strings.TrimSuffix(cfg.IssuerURL, "/")
	jwksURL := normalizedIssuer + "/mldsa-certs"

	pqcVerifier := pqcjwt.NewVerifier(pqcjwt.Config{
		JWKSURL:  jwksURL,
		Issuer:   normalizedIssuer,
		Audience: cfg.ClientID,
	})

	return &HybridVerifier{
		oidcVerifier: oidcVerifier,
		pqcVerifier:  pqcVerifier,
	}, nil
}

// Verify validates a JWT token, supporting both ML-DSA-65 and standard algorithms.
func (hv *HybridVerifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	if pqcjwt.IsMLDSA(rawToken) {
		return hv.verifyMLDSA(ctx, rawToken)
	}
	return hv.oidcVerifier.Verify(ctx, rawToken)
}

func (hv *HybridVerifier) verifyMLDSA(ctx context.Context, rawToken string) (*Claims, error) {
	pqcClaims, err := hv.pqcVerifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	// Map SDK claims to Triton's Claims type.
	var claims Claims
	claims.Sub = pqcClaims.Sub
	claims.Email = pqcClaims.Email
	claims.Name = pqcClaims.Name
	claims.PreferredUser = pqcClaims.PreferredUser

	// Parse Keycloak-specific claims from raw JSON.
	if pqcClaims.RealmAccess != nil {
		var ra RoleAccess
		if err := jsonUnmarshal(pqcClaims.RealmAccess, &ra); err == nil {
			claims.RealmAccess = ra
		}
	}
	if pqcClaims.ResourceAccess != nil {
		var ra map[string]RoleAccess
		if err := jsonUnmarshal(pqcClaims.ResourceAccess, &ra); err == nil {
			claims.ResourceAccess = ra
		}
	}
	if pqcClaims.Organization != nil {
		var org map[string]OrgInfo
		if err := jsonUnmarshal(pqcClaims.Organization, &org); err == nil {
			claims.Organization = org
		}
	}

	return &claims, nil
}

func jsonUnmarshal(data json.RawMessage, v interface{}) error {
	return json.Unmarshal([]byte(data), v)
}
