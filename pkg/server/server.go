package server

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/store"
)

// Config holds server configuration.
type Config struct {
	ListenAddr   string
	DBUrl        string
	TLSCert      string
	TLSKey       string
	Guard        *license.Guard // nil = no enforcement (backward compat for testserver)
	TenantPubKey []byte         // optional: Ed25519 public key for tenant token verification (overrides embedded key)
	// ServiceKey is the shared secret used by the license server to authenticate
	// to the report server's /api/v1/admin/* endpoints (e.g., org provisioning).
	// If empty, the admin route group is not registered at all.
	ServiceKey string
	// JWTSigningKey is the report server's own Ed25519 private key for signing
	// user JWTs (org_admin and org_user logins). Independent from the license
	// server's signing key. If empty, the /api/v1/auth/* route group is not
	// registered at all.
	JWTSigningKey ed25519.PrivateKey
	// JWTPublicKey is the corresponding public key used to verify report
	// server JWTs. Derived from JWTSigningKey if not supplied.
	JWTPublicKey ed25519.PublicKey
	// DataEncryptionKeyHex enables at-rest AES-256-GCM encryption of
	// scan_data. 64 hex characters = 32-byte key. Empty disables
	// encryption (existing rows continue to read as plaintext).
	DataEncryptionKeyHex string
}

// Server is the Triton REST API server.
type Server struct {
	config *Config
	store  store.Store
	router chi.Router
	http   *http.Server
	guard  *license.Guard
}

// securityHeaders adds security-related HTTP headers to all responses.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// New creates a new Server with the given config and store. It returns
// an error for any configuration that would silently downgrade security:
// today that is a malformed DataEncryptionKeyHex, which used to fall
// through to plaintext storage after a "FATAL" log line. Callers MUST
// check the returned error and refuse to start the process on failure.
func New(cfg *Config, s store.Store) (*Server, error) {
	// Validate the at-rest encryption key first — independently of the
	// store's concrete type. A malformed key is a fatal misconfiguration
	// regardless of whether encryption would actually be wired up for
	// this store, because an operator who set the env var clearly
	// intended encryption. Silently continuing unencrypted would mask
	// a config bug and violate the operator's expectation.
	if cfg.DataEncryptionKeyHex != "" {
		enc, err := store.NewEncryptor(cfg.DataEncryptionKeyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid DataEncryptionKeyHex: %w", err)
		}
		// Only *PostgresStore currently supports at-rest encryption.
		// For other store types (e.g., future in-memory/testing stores)
		// the validated key is simply ignored — we still validated it
		// to preserve the fail-fast contract above.
		if ps, ok := s.(*store.PostgresStore); ok {
			ps.SetEncryptor(enc)
			log.Printf("at-rest scan data encryption enabled (AES-256-GCM)")
		}
	}

	srv := &Server{
		config: cfg,
		store:  s,
		guard:  cfg.Guard,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(securityHeaders)
	r.Use(middleware.Throttle(100))

	// Resolve tenant Ed25519 pubkey for license token verification. If
	// TenantPubKey is nil, fall back to the embedded default. UnifiedAuth
	// below passes this to the license-token resolution path.
	var licensePubKey ed25519.PublicKey
	if len(cfg.TenantPubKey) > 0 {
		licensePubKey = ed25519.PublicKey(cfg.TenantPubKey)
	} else {
		licensePubKey = license.LoadPublicKeyBytes()
	}

	// Derive JWT public key now (also done below for /auth routes, but
	// UnifiedAuth needs it up-front).
	var jwtPubKey ed25519.PublicKey
	if cfg.JWTSigningKey != nil {
		if cfg.JWTPublicKey == nil {
			cfg.JWTPublicKey = cfg.JWTSigningKey.Public().(ed25519.PublicKey)
		}
		jwtPubKey = cfg.JWTPublicKey
	}

	// API routes — UnifiedAuth (JWT OR license token) is the primary
	// tenant resolver. Agents authenticate via license token; org users
	// authenticate via JWT obtained from /api/v1/auth/login. The legacy
	// APIKeyAuth was removed in Phase 4 — clients that previously used
	// X-Triton-API-Key must migrate to one of the supported auth modes.
	r.Route("/api/v1", func(r chi.Router) {
		if cfg.Guard != nil {
			r.Use(LicenceGate(cfg.Guard))
		}
		// Always install UnifiedAuth. It gracefully handles:
		//   - Guard == nil (skips the single-tenant fallback)
		//   - JWT not configured (skips the JWT path)
		//   - License pubkey always present via embedded default
		// When no credentials are supplied and no guard exists, it
		// passes through without setting tenant context — existing
		// handlers that read TenantFromContext will see an empty
		// org_id (backward compat with public-ish routes).
		r.Use(UnifiedAuth(jwtPubKey, s, licensePubKey, cfg.Guard))
		srv.registerAPIRoutes(r)
	})

	// Admin API for service-to-service calls (license server → report server).
	// Only registered if a ServiceKey is configured. Uses its own auth
	// middleware (X-Triton-Service-Key) separate from the agent API key.
	if cfg.ServiceKey != "" {
		r.Route("/api/v1/admin", func(r chi.Router) {
			r.Use(ServiceKeyAuth(cfg.ServiceKey))
			r.Post("/orgs", srv.handleProvisionOrg)
		})
	}

	// User auth API (login, logout, refresh, change-password).
	// Only registered if JWT signing is configured.
	if cfg.JWTSigningKey != nil {
		r.Route("/api/v1/auth", func(r chi.Router) {
			r.Post("/login", srv.handleLogin)
			r.Post("/logout", srv.handleLogout)
			r.Post("/refresh", srv.handleRefresh)
			r.Post("/change-password", srv.handleChangePassword)
		})

		// Org-scoped user management — requires JWT auth + org_admin role
		// + cleared password change requirement. Tenant isolation is
		// enforced inside the handlers (queries scoped to the requesting
		// admin's org_id).
		//
		// BlockUntilPasswordChanged ensures invited users (must_change_password
		// =true on their initial JWT) cannot use the user-management API
		// until they've called /auth/change-password to clear the flag.
		r.Route("/api/v1/users", func(r chi.Router) {
			r.Use(JWTAuth(cfg.JWTPublicKey, s))
			r.Use(BlockUntilPasswordChanged)
			r.Use(RequireOrgAdmin)
			r.Post("/", srv.handleCreateUser)
			r.Get("/", srv.handleListUsers)
			r.Get("/{id}", srv.handleGetUser)
			r.Put("/{id}", srv.handleUpdateUser)
			r.Delete("/{id}", srv.handleDeleteUser)
		})
	}

	// Health check — intentionally outside the auth group so it remains public.
	// It returns no sensitive data (only {"status":"ok"}).
	r.Get("/api/v1/health", srv.handleHealth)

	// Serve embedded web UI.
	r.Handle("/ui/*", http.StripPrefix("/ui/", uiHandler()))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/index.html", http.StatusFound)
	})

	srv.router = r
	srv.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return srv, nil
}

func (s *Server) registerAPIRoutes(r chi.Router) {
	// POST /scans is intentionally registered WITHOUT RequireTenant so
	// single-tenant deployments (no Guard, no JWT) can still accept
	// agent submissions. The handler sets result.OrgID from
	// TenantFromContext only if non-empty, so authenticated submissions
	// stamp the tenant's org and unauthenticated submissions retain
	// whatever the body says. See handleSubmitScan for the body-injection
	// guard that prevents cross-org writes when authenticated.
	r.Post("/scans", s.handleSubmitScan)

	// All read/write routes require an authenticated tenant context.
	// This closes the D1 finding from the Phase 2 review: without this
	// gate, an unauthenticated GET /api/v1/scans returned rows from
	// ALL orgs because TenantFromContext returned an empty string and
	// the store accepted empty org_id as "no filter".
	r.Group(func(r chi.Router) {
		r.Use(RequireTenant)
		r.Get("/scans", s.handleListScans)
		r.Get("/scans/{id}", s.handleGetScan)
		r.Get("/scans/{id}/findings", s.handleGetFindings)
		r.Get("/diff", s.handleDiff)
		r.Get("/trend", s.handleTrend)
		r.Get("/machines", s.handleListMachines)
		r.Get("/machines/{hostname}", s.handleMachineHistory)
		r.Post("/policy/evaluate", s.handlePolicyEvaluate)
		r.Get("/reports/{id}/{format}", s.handleGenerateReport)
		r.Get("/aggregate", s.handleAggregate)

		// Destructive operations require org_admin (Arch #7 from
		// Phase 2 review). org_user can read but cannot delete scans.
		r.Group(func(r chi.Router) {
			r.Use(RequireScanAdmin)
			r.Delete("/scans/{id}", s.handleDeleteScan)
		})
	})
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	log.Printf("Triton server listening on %s", s.config.ListenAddr)
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		return s.http.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	return s.http.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// Router returns the chi router (for testing).
func (s *Server) Router() chi.Router {
	return s.router
}
