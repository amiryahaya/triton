package manageserver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/zones"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// Server is the Manage Server HTTP shell. Run() blocks until ctx is cancelled.
type Server struct {
	cfg    *Config
	store  managestore.Store
	router chi.Router
	http   *http.Server

	mu           sync.RWMutex
	setupMode    bool              // true until admin created AND license activated
	loginLimiter *loginRateLimiter // in-memory brute-force guard for /auth/login

	// Licence wiring (Task 5.1). Populated by startLicence; nil until
	// /setup/license activates or a valid persisted token is found at boot.
	licenceGuard  *license.Guard
	licencePusher *license.UsagePusher
	licenceCancel context.CancelFunc // cancels the pusher goroutine

	// Admin-API handler packages (Batch C). Constructed in New() against
	// the shared pool and mounted under /api/v1/admin/*.
	zonesAdmin *zones.AdminHandlers
	hostsAdmin *hosts.AdminHandlers
}

// New constructs the Server, probes setup state from the DB, and wires the
// Chi router. It does NOT start the listener — callers use Run(ctx).
//
// pool is the same pgxpool the caller constructed `store` against. Admin
// handler packages (zones, hosts, …) open their own lightweight stores over
// the shared pool rather than dial a second time. The caller owns the pool's
// lifecycle; the server does not Close() it.
func New(cfg *Config, store managestore.Store, pool *pgxpool.Pool) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if len(cfg.JWTSigningKey) < 32 {
		return nil, fmt.Errorf("JWTSigningKey must be ≥32 bytes")
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 24 * time.Hour
	}
	if store == nil {
		return nil, fmt.Errorf("nil store")
	}
	if pool == nil {
		return nil, fmt.Errorf("nil pool")
	}

	srv := &Server{
		cfg:          cfg,
		store:        store,
		loginLimiter: newLoginRateLimiter(),
		zonesAdmin:   zones.NewAdminHandlers(zones.NewPostgresStore(pool)),
		hostsAdmin:   hosts.NewAdminHandlers(hosts.NewPostgresStore(pool)),
	}
	if err := srv.initSetupState(context.Background()); err != nil {
		return nil, fmt.Errorf("init setup state: %w", err)
	}
	srv.router = srv.buildRouter()

	// If a persisted licence already exists, bring the guard + usage pusher
	// online now. A bad token is non-fatal: we log and continue so admins can
	// re-activate via /setup/license without needing to restart the process.
	if err := srv.startLicence(context.Background()); err != nil {
		log.Printf("manageserver: startLicence at boot: %v (server will run; re-activate via API)", err)
	}
	return srv, nil
}

// initSetupState reads the singleton manage_setup row and configures
// s.setupMode. Called once from New(). Re-activating the licence is
// deferred to a future task (license.go) — here we only set the flag.
func (s *Server) initSetupState(ctx context.Context) error {
	state, err := s.store.GetSetup(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setupMode = !state.AdminCreated || !state.LicenseActivated
	return nil
}

// RefreshSetupMode re-reads setup state from the DB; called by setup handlers
// (Task 4.x) after they mutate state.
func (s *Server) RefreshSetupMode(ctx context.Context) {
	state, err := s.store.GetSetup(ctx)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setupMode = !state.AdminCreated || !state.LicenseActivated
}

// isSetupMode is mu-read-locked.
func (s *Server) isSetupMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.setupMode
}

// Router exposes the chi router (for tests — mirrors the licenseserver pattern).
func (s *Server) Router() chi.Router { return s.router }

// buildRouter wires all routes. Separate method so tests can inspect it.
func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(manageSecurityHeaders)
	r.Use(middleware.Throttle(100))

	// Always available.
	r.Get("/api/v1/health", s.handleHealth)

	// Setup endpoints — status is always readable; POST endpoints gated to
	// setup mode only (SetupOnly middleware returns 409 when setup is done).
	r.Route("/api/v1/setup", func(r chi.Router) {
		r.Get("/status", s.handleSetupStatus)
		r.Group(func(r chi.Router) {
			r.Use(s.SetupOnly)
			r.Post("/admin", s.handleSetupAdmin)
			r.Post("/license", s.handleSetupLicense)
		})
	})

	// Auth endpoints — available only when not in setup mode.
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Use(s.requireOperational)
		r.Post("/login", s.handleLogin)
		r.Post("/logout", s.handleLogout)
		r.Post("/refresh", s.handleRefresh)
	})

	// Authenticated endpoints — require valid JWT.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.requireOperational)
		r.Use(s.jwtAuth)
		r.Get("/me", s.handleMe)
	})

	// Admin CRUD subtree — operational, auth'd, and tenancy-scoped to the
	// Manage instance_id via injectInstanceOrg. Role enforcement on DELETE
	// is intentionally deferred until the handler packages grow role-
	// awareness; see Batch C notes in the plan. Mount as a separate top-
	// level Route (not nested under /api/v1) so chi doesn't double-compose
	// the /me group's jwtAuth onto this subtree.
	r.Route("/api/v1/admin", func(r chi.Router) {
		r.Use(s.requireOperational)
		r.Use(s.jwtAuth)
		r.Use(s.injectInstanceOrg)
		r.Route("/zones", func(r chi.Router) { zones.MountAdminRoutes(r, s.zonesAdmin) })
		r.Route("/hosts", func(r chi.Router) { hosts.MountAdminRoutes(r, s.hostsAdmin) })
		// scan-jobs, agents, push-status, enrol mounted in later batches.
	})

	return r
}

// Run starts the HTTP listener and blocks until ctx is cancelled.
// On shutdown, blocks up to 10s for in-flight requests to complete.
func (s *Server) Run(ctx context.Context) error {
	s.http = &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := s.http.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		// Stop the usage pusher BEFORE waiting on HTTP shutdown so it
		// doesn't keep trying to reach the Licence Server while shutdown
		// is in progress (and so its goroutine exits cleanly).
		s.stopLicence()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	case err := <-errCh:
		s.stopLicence()
		return err
	}
}

// manageSecurityHeaders adds baseline security headers to every response.
func manageSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}
