package server

import (
	"fmt"
	"net/http"
)

// roleRank orders roles by privilege, highest number = highest privilege.
// A route gated at RoleEngineer admits RoleOwner + RoleEngineer but not
// RoleOfficer. Unknown roles map to 0 and are always rejected.
var roleRank = map[string]int{
	RoleOfficer:  1,
	RoleEngineer: 2,
	RoleOwner:    3,
}

// RequireRole returns middleware that enforces the caller has at least
// the given role. It relies on JWTAuth having populated *auth.UserClaims
// in the request context via ClaimsFromContext.
//
// Returns 401 if no claims are present (misconfiguration — JWTAuth not
// chained) and 403 if the caller's role ranks below the minimum.
func RequireRole(minRole string) func(http.Handler) http.Handler {
	minRank, ok := roleRank[minRole]
	if !ok {
		panic(fmt.Sprintf("RequireRole: unknown minRole %q", minRole))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if roleRank[claims.Role] < minRank {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
