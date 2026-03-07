package licenseserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// Server is the License Server REST API.
type Server struct {
	config *Config
	store  licensestore.Store
	router chi.Router
	http   *http.Server
}

// securityHeaders adds security-related HTTP headers.
func licenseSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"font-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; object-src 'none'; base-uri 'self'; "+
				"form-action 'self'; frame-ancestors 'none'")
		// HSTS: only set when request arrived via TLS.
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		// Propagate chi RequestID to response for client correlation.
		if reqID := middleware.GetReqID(r.Context()); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		next.ServeHTTP(w, r)
	})
}

// New creates a new license Server.
func New(cfg *Config, s licensestore.Store) *Server {
	srv := &Server{
		config: cfg,
		store:  s,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(licenseSecurityHeaders)
	r.Use(middleware.Throttle(100))

	// Health check (no auth).
	r.Get("/api/v1/health", srv.handleHealth)

	// Client API (no API key — secured by license UUID knowledge + machine fingerprint).
	r.Route("/api/v1/license", func(r chi.Router) {
		r.Post("/activate", srv.handleActivate)
		r.Post("/deactivate", srv.handleDeactivate)
		r.Post("/validate", srv.handleValidate)
		r.Get("/download/latest-version", srv.handleLatestVersion)
		r.With(middleware.Timeout(300*time.Second)).Get("/download/{version}/{os}/{arch}", srv.handleDownloadBinary)
	})

	// Auth API (public, no admin key required).
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/login", srv.handleLogin)
		r.Post("/logout", srv.handleLogout)
		r.Post("/refresh", srv.handleRefresh)
	})

	// Admin API (requires admin key — always applies auth middleware).
	r.Route("/api/v1/admin", func(r chi.Router) {
		r.Use(AdminKeyAuth(cfg.AdminKeys))

		// Organizations
		r.Post("/orgs", srv.handleCreateOrg)
		r.Get("/orgs", srv.handleListOrgs)
		r.Get("/orgs/{id}", srv.handleGetOrg)
		r.Put("/orgs/{id}", srv.handleUpdateOrg)
		r.Delete("/orgs/{id}", srv.handleDeleteOrg)

		// Licenses
		r.Post("/licenses", srv.handleCreateLicense)
		r.Get("/licenses", srv.handleListLicenses)
		r.Get("/licenses/{id}", srv.handleGetLicense)
		r.Post("/licenses/{id}/revoke", srv.handleRevokeLicense)

		// Activations
		r.Get("/activations", srv.handleListActivations)
		r.Post("/activations/{id}/deactivate", srv.handleAdminDeactivate)

		// Audit
		r.Get("/audit", srv.handleListAudit)

		// Stats
		r.Get("/stats", srv.handleDashboardStats)

		// Binaries
		r.Post("/binaries", srv.handleUploadBinary)
		r.Get("/binaries", srv.handleListBinaries)
		r.Delete("/binaries/{version}/{os}/{arch}", srv.handleDeleteBinary)
	})

	// Serve embedded admin UI.
	r.Handle("/ui/*", http.StripPrefix("/ui/", adminUIHandler()))

	// Serve embedded download page (public, no admin key).
	r.Handle("/download/*", http.StripPrefix("/download/", downloadPageHandler()))
	r.Get("/download", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/download/index.html", http.StatusFound)
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/index.html", http.StatusFound)
	})

	srv.router = r
	srv.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return srv
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	fmt.Printf("License server listening on %s\n", s.config.ListenAddr)
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

// maxRequestBody is the maximum allowed request body size (1 MB).
const maxRequestBody = 1 << 20

// Input length limits.
const (
	maxNameLen     = 255
	maxContactLen  = 255
	maxNotesLen    = 1000
	maxHostnameLen = 255
	maxVersionLen  = 50
	maxReasonLen   = 500
)

// tooLong checks if a string exceeds the specified maximum length.
func tooLong(s string, limit int) bool { return len(s) > limit }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
