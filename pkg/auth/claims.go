package auth

import (
	"context"
	"fmt"
)

type contextKey string

const claimsKey contextKey = "keycloak_claims"

// Claims represents Keycloak JWT claims.
type Claims struct {
	Sub            string                `json:"sub"`
	Email          string                `json:"email"`
	Name           string                `json:"name"`
	PreferredUser  string                `json:"preferred_username"`
	RealmAccess    RoleAccess            `json:"realm_access"`
	ResourceAccess map[string]RoleAccess `json:"resource_access"`
	Organization   map[string]OrgInfo    `json:"organization,omitempty"`
}

// RoleAccess holds role lists for realm or client access.
type RoleAccess struct {
	Roles []string `json:"roles"`
}

// OrgInfo holds organization metadata from Keycloak Organizations.
type OrgInfo struct {
	Name string `json:"name"`
}

// NewContext stores claims in context.
func NewContext(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ClaimsFromContext retrieves claims from context.
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey).(*Claims)
	return c
}

// OrgIDFromClaims returns the organization ID from the claims.
// Returns an error if the user belongs to more than one organization.
func OrgIDFromClaims(claims *Claims) (string, error) {
	if claims == nil {
		return "", nil
	}
	if len(claims.Organization) > 1 {
		return "", fmt.Errorf("token contains %d organizations; expected at most 1", len(claims.Organization))
	}
	for id := range claims.Organization {
		return id, nil
	}
	return "", nil
}

// HasClientRole checks if claims contain a specific client role.
func HasClientRole(claims *Claims, clientID, role string) bool {
	if claims == nil {
		return false
	}
	access, ok := claims.ResourceAccess[clientID]
	if !ok {
		return false
	}
	for _, r := range access.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasRealmRole checks if claims contain a specific realm role.
func HasRealmRole(claims *Claims, role string) bool {
	if claims == nil {
		return false
	}
	for _, r := range claims.RealmAccess.Roles {
		if r == role {
			return true
		}
	}
	return false
}
