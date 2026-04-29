package licenseserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/time/rate"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

// Server is the License Server REST API.
type Server struct {
	config          *Config
	store           licensestore.Store
	router          chi.Router
	http            *http.Server
	reportAPIClient *ReportAPIClient // nil when no report server configured
	loginLimiter    *auth.LoginRateLimiter
	clientLimiter   *ipRateLimiter // per-IP rate limiter for client API
	// ctx is canceled in Shutdown so background workers (rate-limit
	// janitor) stop promptly. Wired in Phase 5 Sprint 2 (N1).
	ctx    context.Context
	cancel context.CancelFunc
}

// ipRateLimiter provides per-IP token-bucket rate limiting.
type ipRateLimiter struct {
	clients sync.Map // map[string]*rate.Limiter
	r       rate.Limit
	b       int
}

func newIPRateLimiter(r rate.Limit, b int) *ipRateLimiter {
	return &ipRateLimiter{r: r, b: b}
}

func (l *ipRateLimiter) allow(ip string) bool {
	v, loaded := l.clients.Load(ip)
	if !loaded {
		lim := rate.NewLimiter(l.r, l.b)
		v, _ = l.clients.LoadOrStore(ip, lim)
	}
	return v.(*rate.Limiter).Allow()
}

func (l *ipRateLimiter) middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			if !l.allow(ip) {
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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
			"default-src 'self'; script-src 'self'; style-src 'self'; "+
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

// corsMiddleware returns an explicit CORS policy. When allowedOrigins is empty,
// no cross-origin access is allowed (default same-origin browser behavior).
// Configurable via Config.AllowedOrigins for deployments where the UI is served
// from a different origin than the API.
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o != "" {
			allowed[o] = struct{}{}
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if _, ok := allowed[origin]; ok {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
					w.Header().Set("Access-Control-Max-Age", "300")
				}
				w.Header().Add("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// New creates a new license Server.
func New(cfg *Config, s licensestore.Store) *Server {
	rateLimitCfg := auth.DefaultLoginRateLimiterConfig
	if cfg.LoginRateLimiterConfig != nil {
		rateLimitCfg = *cfg.LoginRateLimiterConfig
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		config:          cfg,
		store:           s,
		reportAPIClient: NewReportAPIClient(cfg.ReportServerURL, cfg.ReportServerServiceKey),
		loginLimiter:    auth.NewLoginRateLimiter(rateLimitCfg),
		// 20 req/s burst per IP, refilling at 5 req/s — generous for legitimate
		// clients (agents heartbeat every few minutes) but blocks abuse quickly.
		clientLimiter: newIPRateLimiter(rate.Every(200*time.Millisecond), 20),
		ctx:           ctx,
		cancel:        cancel,
	}
	// Phase 5.1 D1 fix — see pkg/server/server.go for rationale. Same
	// janitor strategy on the license server's limiter. Sprint 2 (N1)
	// threaded srv.ctx so Shutdown cancels the janitor deterministically.
	_ = srv.loginLimiter.StartJanitor(ctx, rateLimitCfg.LockoutDuration)
	go srv.runExpiryNotifications(ctx)

	// Wire stale-seat reaping threshold into the store. Type-assert to
	// the concrete PostgresStore since SetStaleThreshold is not part of
	// the Store interface (it's a deployment knob, not a storage contract).
	if ps, ok := s.(*licensestore.PostgresStore); ok && cfg.StaleActivationThreshold > 0 {
		ps.SetStaleThreshold(cfg.StaleActivationThreshold)
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(licenseSecurityHeaders)
	r.Use(corsMiddleware(cfg.AllowedOrigins))
	r.Use(middleware.Throttle(100))

	// Health check (no auth).
	r.Get("/api/v1/health", srv.handleHealth)

	// Client API (no API key — secured by license UUID knowledge + machine fingerprint).
	// Per-IP rate limiting protects against brute-force and seat exhaustion attacks.
	r.Route("/api/v1/license", func(r chi.Router) {
		r.Use(srv.clientLimiter.middleware())
		r.Post("/activate", srv.handleActivate)
		r.Post("/deactivate", srv.handleDeactivate)
		r.Post("/validate", srv.handleValidate)
		r.Post("/usage", srv.handleUsage) // near-real-time usage push
		r.Get("/download/latest-version", srv.handleLatestVersion)
		r.With(middleware.Timeout(300*time.Second)).Get("/download/{version}/{os}/{arch}", srv.handleDownloadBinary)
	})

	// Auth API (public, no admin key required).
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/login", srv.handleLogin)
		r.Post("/logout", srv.handleLogout)
		r.Post("/refresh", srv.handleRefresh)
		r.With(srv.JWTAuth()).Post("/change-password", srv.handleChangePassword)
	})

	// Setup API (public, guarded by empty-DB check inside the handler).
	r.Get("/api/v1/setup/status", srv.handleSetupStatus)
	r.Post("/api/v1/setup/first-admin", srv.handleFirstAdminSetup)

	// Install API (token-authed via HMAC token in URL path — no admin key).
	r.Route("/api/v1/install/{token}", func(r chi.Router) {
		r.Get("/", srv.handleInstallScript)
		r.Get("/binary/{os}/{arch}", srv.handleInstallBinary)
		r.Get("/agent-yaml", srv.handleInstallAgentYAML)
	})

	// Admin API (requires platform_admin JWT — always applies auth middleware).
	r.Route("/api/v1/admin", func(r chi.Router) {
		r.Use(srv.JWTAuth())
		r.Use(srv.BlockUntilPasswordChanged())

		// Organizations
		r.Post("/orgs", srv.handleCreateOrg)
		r.Get("/orgs", srv.handleListOrgs)
		r.Get("/orgs/{id}", srv.handleGetOrg)
		r.Put("/orgs/{id}", srv.handleUpdateOrg)
		r.Delete("/orgs/{id}", srv.handleDeleteOrg)
		r.Post("/orgs/{id}/suspend", srv.handleSuspendOrg)

		// Licenses
		r.Post("/licenses", srv.handleCreateLicense)
		r.Get("/licenses", srv.handleListLicenses)
		r.Get("/licenses/{id}", srv.handleGetLicense)
		r.Patch("/licenses/{id}", srv.handleUpdateLicense)
		r.Post("/licenses/{id}/revoke", srv.handleRevokeLicense)
		// agent.yaml download (closes the fool-proof loop —
		// superadmin clicks one button and gets a ready-to-ship
		// file with the license's Ed25519 token baked in).
		r.Post("/licenses/{id}/agent-yaml", srv.handleDownloadAgentYAML)
		// Install token: generates a short-lived HMAC token that
		// the admin copies as a curl one-liner to the target host.
		r.Post("/licenses/{id}/install-token", srv.handleGenerateInstallToken)
		// Bundle download: binary + agent.yaml + install script in one archive.
		r.Post("/licenses/{id}/bundle", srv.handleDownloadBundle)

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

		// Superadmins (platform admins for the license server itself)
		r.Route("/superadmins", func(r chi.Router) {
			r.Post("/", srv.handleCreateSuperadmin)
			r.Get("/", srv.handleListSuperadmins)
			r.Get("/{id}", srv.handleGetSuperadmin)
			r.Put("/{id}", srv.handleUpdateSuperadmin)
			r.Delete("/{id}", srv.handleDeleteSuperadmin)
			r.Post("/{id}/resend-invite", srv.handleResendInvite)
		})
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

// Shutdown gracefully shuts down the server. Cancels the internal
// Server context first so background workers (rate-limit janitor)
// stop promptly, then drains in-flight HTTP requests up to the
// caller-supplied deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	return s.http.Shutdown(ctx)
}

// Router returns the chi router (for testing).
func (s *Server) Router() chi.Router {
	return s.router
}

// expiryThresholds defines the three notification windows.
var expiryThresholds = []struct {
	within   time.Duration
	interval string
	days     int
}{
	{30 * 24 * time.Hour, "30d", 30},
	{7 * 24 * time.Hour, "7d", 7},
	{24 * time.Hour, "1d", 1},
}

// runExpiryNotifications ticks hourly and calls sendExpiryNotifications.
// Exits immediately if no mailer is configured (to keep logs clean on
// deployments that don't set TRITON_LICENSE_SERVER_RESEND_API_KEY).
// Exits when ctx is cancelled (i.e., on Shutdown).
func (s *Server) runExpiryNotifications(ctx context.Context) {
	if s.config.Mailer == nil {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendExpiryNotifications(ctx)
		}
	}
}

// TriggerExpiryCheck runs one expiry notification cycle. Exported for testing.
func (s *Server) TriggerExpiryCheck(ctx context.Context) {
	s.sendExpiryNotifications(ctx)
}

// sendExpiryNotifications checks all three expiry windows and sends warning
// emails to platform_admin users and the org contact for qualifying licenses.
func (s *Server) sendExpiryNotifications(ctx context.Context) {
	if s.config.Mailer == nil {
		return
	}

	admins, err := s.store.ListUsers(ctx, licensestore.UserFilter{Role: "platform_admin"})
	if err != nil {
		log.Printf("expiry notifications: list admins: %v", err)
		return
	}

	for _, threshold := range expiryThresholds {
		licenses, err := s.store.ListExpiringLicenses(ctx, threshold.within)
		if err != nil {
			log.Printf("expiry notifications [%s]: list licenses: %v", threshold.interval, err)
			continue
		}

		for i := range licenses {
			lic := &licenses[i]
			if !s.needsNotification(*lic, threshold.interval) {
				continue
			}

			data := ExpiryWarningEmailData{
				OrgName:       lic.OrgName,
				LicenseID:     lic.LicenseID,
				ExpiresAt:     lic.ExpiresAt,
				DaysRemaining: threshold.days,
			}

			for j := range admins {
				admin := &admins[j]
				d := data
				d.RecipientName = admin.Name
				if sendErr := s.config.Mailer.SendExpiryWarningEmail(ctx, admin.Email, d); sendErr != nil {
					log.Printf("expiry notifications [%s]: send to admin %s: %v", threshold.interval, admin.Email, sendErr)
				}
			}

			if lic.ContactEmail != "" {
				d := data
				d.RecipientName = lic.ContactName
				if sendErr := s.config.Mailer.SendExpiryWarningEmail(ctx, lic.ContactEmail, d); sendErr != nil {
					log.Printf("expiry notifications [%s]: send to contact %s: %v", threshold.interval, lic.ContactEmail, sendErr)
				}
			}

			// Mark regardless of individual send errors: at-most-once semantics.
			// A transient Resend outage suppresses this interval's notification
			// rather than causing a retry storm on the next hourly tick.
			if markErr := s.store.MarkLicenseNotified(ctx, lic.LicenseID, threshold.interval); markErr != nil {
				log.Printf("expiry notifications [%s]: mark license %s: %v", threshold.interval, lic.LicenseID, markErr)
			}
		}
	}
}

// needsNotification returns true when the license has not yet been notified
// for the given interval.
func (s *Server) needsNotification(lic licensestore.LicenseWithOrg, interval string) bool {
	switch interval {
	case "30d":
		return lic.Notified30dAt == nil
	case "7d":
		return lic.Notified7dAt == nil
	case "1d":
		return lic.Notified1dAt == nil
	}
	return false
}

// NewForTest constructs a minimal Server for unit testing expiry notification
// logic without starting an HTTP server.
func NewForTest(store licensestore.Store, m Mailer) *Server {
	return &Server{
		config: &Config{Mailer: m},
		store:  store,
	}
}

// maxRequestBody is the maximum allowed request body size (1 MB).
const maxRequestBody = 1 << 20

// Input length limits.
const (
	maxNameLen         = 255
	maxContactNameLen  = 100
	maxContactPhoneLen = 50
	maxContactEmailLen = 325
	maxNotesLen        = 1000
	maxHostnameLen     = 255
	maxVersionLen      = 50
	maxReasonLen       = 500
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
