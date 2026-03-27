package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// TokenVerifier verifies OIDC tokens. Interface for testability.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (*Claims, error)
}

// OIDCConfig holds OIDC configuration.
type OIDCConfig struct {
	IssuerURL string
	ClientID  string
}

// OIDCVerifier validates Keycloak-issued JWTs using JWKS.
type OIDCVerifier struct {
	verifier *oidc.IDTokenVerifier
}

// NewVerifier creates an OIDCVerifier that fetches JWKS from the issuer.
func NewVerifier(ctx context.Context, cfg OIDCConfig) (*OIDCVerifier, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc provider discovery: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})
	return &OIDCVerifier{verifier: verifier}, nil
}

// Verify validates a raw JWT token and returns the parsed claims.
func (v *OIDCVerifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}
	claims.Sub = idToken.Subject
	return &claims, nil
}

// OIDCAuth is an HTTP middleware that validates Bearer tokens.
func OIDCAuth(v TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"error":"invalid authorization header"}`, http.StatusUnauthorized)
				return
			}
			claims, err := v.Verify(r.Context(), parts[1])
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"invalid token: %s"}`, err.Error()), http.StatusUnauthorized)
				return
			}
			ctx := NewContext(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole is a middleware that checks for specific client roles.
func RequireRole(clientID string, roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"no claims in context"}`, http.StatusForbidden)
				return
			}
			// Platform admins bypass role checks.
			if HasRealmRole(claims, "platform-admin") {
				next.ServeHTTP(w, r)
				return
			}
			for _, role := range roles {
				if HasClientRole(claims, clientID, role) {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
		})
	}
}

// OptionalOIDCAuth tries to validate a Bearer token if present, but does not reject if missing.
// Used for dual-auth endpoints where license token fallback is supported.
func OptionalOIDCAuth(v TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				next.ServeHTTP(w, r)
				return
			}
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				next.ServeHTTP(w, r)
				return
			}
			claims, err := v.Verify(r.Context(), parts[1])
			if err != nil {
				// Bearer token present but invalid — reject.
				http.Error(w, fmt.Sprintf(`{"error":"invalid token: %s"}`, err.Error()), http.StatusUnauthorized)
				return
			}
			ctx := NewContext(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
