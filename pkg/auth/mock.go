package auth

import (
	"context"
)

// MockVerifier is a test double for TokenVerifier.
type MockVerifier struct {
	Claims         *Claims
	Err            error
	ReceivedTokens []string
}

// Verify returns the pre-configured claims or error.
func (m *MockVerifier) Verify(_ context.Context, rawToken string) (*Claims, error) {
	m.ReceivedTokens = append(m.ReceivedTokens, rawToken)
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Claims, nil
}

// NewMockVerifier creates a MockVerifier with the given claims.
func NewMockVerifier(claims *Claims) *MockVerifier {
	return &MockVerifier{Claims: claims}
}

// PlatformAdminClaims returns claims for a platform admin user.
func PlatformAdminClaims() *Claims {
	return &Claims{
		Sub:   "admin-user-id",
		Email: "admin@platform.test",
		Name:  "Platform Admin",
		RealmAccess: RoleAccess{
			Roles: []string{"platform-admin"},
		},
		ResourceAccess: map[string]RoleAccess{
			"triton": {Roles: []string{"license-admin"}},
		},
	}
}

// OrgAdminClaims returns claims for an org admin.
func OrgAdminClaims(orgID, orgName string) *Claims {
	return &Claims{
		Sub:   "org-admin-user-id",
		Email: "orgadmin@test.com",
		Name:  "Org Admin",
		RealmAccess: RoleAccess{
			Roles: []string{"org-admin"},
		},
		ResourceAccess: map[string]RoleAccess{
			"triton": {Roles: []string{"report-viewer"}},
		},
		Organization: map[string]OrgInfo{
			orgID: {Name: orgName},
		},
	}
}

// ScanAgentClaims returns claims for a scan agent service account.
func ScanAgentClaims(orgID, orgName string) *Claims {
	return &Claims{
		Sub:   "scan-agent-sa-id",
		Email: "scanner@test.com",
		Name:  "Scan Agent",
		ResourceAccess: map[string]RoleAccess{
			"triton": {Roles: []string{"scan-agent"}},
		},
		Organization: map[string]OrgInfo{
			orgID: {Name: orgName},
		},
	}
}
