package server

import (
	"context"
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
	ListenAddr string
	DBUrl      string
	APIKeys    []string
	TLSCert    string
	TLSKey     string
	Guard      *license.Guard // nil = no enforcement (backward compat for testserver)
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// New creates a new Server with the given config and store.
func New(cfg *Config, s store.Store) *Server {
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

	// API routes with optional auth.
	r.Route("/api/v1", func(r chi.Router) {
		if len(cfg.APIKeys) > 0 {
			r.Use(APIKeyAuth(cfg.APIKeys))
		}
		if cfg.Guard != nil {
			r.Use(LicenceGate(cfg.Guard))
		}
		srv.registerAPIRoutes(r)
	})

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

	return srv
}

func (s *Server) registerAPIRoutes(r chi.Router) {
	r.Post("/scans", s.handleSubmitScan)
	r.Get("/scans", s.handleListScans)
	r.Get("/scans/{id}", s.handleGetScan)
	r.Delete("/scans/{id}", s.handleDeleteScan)
	r.Get("/scans/{id}/findings", s.handleGetFindings)
	r.Get("/diff", s.handleDiff)
	r.Get("/trend", s.handleTrend)
	r.Get("/machines", s.handleListMachines)
	r.Get("/machines/{hostname}", s.handleMachineHistory)
	r.Post("/policy/evaluate", s.handlePolicyEvaluate)
	r.Get("/reports/{id}/{format}", s.handleGenerateReport)
	r.Get("/aggregate", s.handleAggregate)
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
