package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/amiryahaya/triton/pkg/store"
)

// Config holds server configuration.
type Config struct {
	ListenAddr string
	DBPath     string
	APIKeys    []string
	TLSCert    string
	TLSKey     string
}

// Server is the Triton REST API server.
type Server struct {
	config *Config
	store  store.Store
	router chi.Router
	http   *http.Server
}

// New creates a new Server with the given config and store.
func New(cfg *Config, s store.Store) *Server {
	srv := &Server{
		config: cfg,
		store:  s,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// API routes with optional auth.
	r.Route("/api/v1", func(r chi.Router) {
		if len(cfg.APIKeys) > 0 {
			r.Use(APIKeyAuth(cfg.APIKeys))
		}
		srv.registerAPIRoutes(r)
	})

	// Health check (no auth).
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
	fmt.Printf("Triton server listening on %s\n", s.config.ListenAddr)
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
