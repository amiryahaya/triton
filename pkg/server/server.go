package server

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/auth/sessioncache"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/internal/mailer"
	"github.com/amiryahaya/triton/pkg/server/manage_enrol"
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

	// LoginRateLimiterConfig tunes the per-email login rate limit.
	// When nil, auth.DefaultLoginRateLimiterConfig applies (5
	// attempts per 15-minute window, 15-minute lockout). Matches
	// the license server's same-named Config field so both servers
	// can be tuned symmetrically — see Sprint 1 review finding M1.
	LoginRateLimiterConfig *auth.LoginRateLimiterConfig

	// RequestRateLimiterConfig tunes the per-tenant data-endpoint
	// rate limit. When nil, auth.DefaultRequestRateLimiterConfig
	// applies (600 requests / minute). Phase 5 Sprint 3 B3 — covers
	// non-login endpoints that were previously only throttled by
	// the global middleware.Throttle(100) concurrency cap.
	RequestRateLimiterConfig *auth.RequestRateLimiterConfig

	// Mailer, if non-nil, is used by the resend-invite flow to push
	// the rotated temp password directly to the invitee via email,
	// so the temp password does NOT appear in the API response body.
	// If nil, resend-invite falls back to returning the temp
	// password in the JSON body (with Cache-Control: no-store) for
	// out-of-band admin delivery. See Sprint 1 review finding S3.
	Mailer mailer.Mailer

	// InviteLoginURL is the URL embedded in resent-invite emails.
	// Typically the report server's own login page (e.g.,
	// "https://reports.example.com/ui/#/login"). Ignored when
	// Mailer is nil.
	InviteLoginURL string

	// SessionCacheSize bounds the in-process JWT session cache
	// (Arch #4). Zero disables the cache, leaving JWTAuth on its
	// two-round-trip DB fast path (acceptable for dev/testing,
	// but NOT for production multi-tenant deployments — the
	// uncached p99 ceiling is around 500 req/s).
	SessionCacheSize int

	// SessionCacheTTL is the maximum time a cached session entry
	// may be returned without re-validating against the sessions
	// table. Defaults to 60 seconds; clamped to [5s, 5m] to keep
	// revocation latency bounded. Ignored when SessionCacheSize
	// is zero.
	SessionCacheTTL time.Duration

	// LicenseServer is the base URL of the License Server for usage
	// reporting (e.g. "https://license.example.com"). When empty, the
	// usage pusher is not started even if a licence token is present.
	LicenseServer string

	// InstanceID is a stable identifier for this Report Server instance,
	// included in usage-push payloads for multi-instance deployments.
	// If empty, the server generates a UUID at startup (see New()).
	InstanceID string

	// ManageEnrolHandlers, when non-nil, is mounted under
	// /api/v1/admin/enrol/manage (behind ServiceKeyAuth) and replaces the
	// 501 stub returned when the handler is absent. Deployments that run
	// Manage supply this via cmd/server.go; plain Report-only deployments
	// leave it nil and the endpoint reports "not configured".
	ManageEnrolHandlers *manage_enrol.EnrolHandlers

	// LicencePortalURL is the base URL of the Licence Portal used to
	// activate/validate/deactivate tenant licences. When empty, tenant
	// creation returns 503.
	LicencePortalURL string
}

// Server is the Triton REST API server.
type Server struct {
	config         *Config
	store          store.Store
	router         chi.Router
	http           *http.Server
	guard          *license.Guard
	loginLimiter   *auth.LoginRateLimiter
	requestLimiter *auth.RequestRateLimiter
	// ctx is canceled in Shutdown so background workers (rate-limit
	// janitor, and any future ticker-driven helpers) stop promptly
	// instead of running until the process exits. Wired in Phase 5
	// Sprint 2 as the N1 follow-up to the Sprint 1 review.
	ctx    context.Context
	cancel context.CancelFunc
	// auditWG tracks fire-and-forget writeAudit goroutines so
	// Shutdown can drain them before the store pool is closed.
	// Sprint 3 D2 — without this, an in-flight audit write could
	// race store.Close() and silently lose the event.
	auditWG sync.WaitGroup
	// auditSem bounds the number of in-flight audit goroutines so
	// a burst of sensitive actions (batch delete, bulk user CRUD)
	// cannot spawn thousands of goroutines contending for the
	// pgx pool. Empty-struct buffered channel used as a
	// semaphore; Sprint 3 full-review N6 — stop-gap before the
	// Sprint 4 batched-writer refactor.
	auditSem chan struct{}
	// sessionCache is the Arch #4 short-TTL LRU cache placed
	// in front of the JWTAuth session+user lookups. Nil when
	// SessionCacheSize is zero; JWTAuth handles the nil receiver.
	sessionCache *sessioncache.SessionCache

	// backfillInProgress is set to true while the first-boot findings
	// backfill goroutine is running. Analytics handlers read this to
	// emit the X-Backfill-In-Progress header so the UI can show a
	// banner. Analytics Phase 1 — zero cost on the hot path via atomic.
	backfillInProgress atomic.Bool

	// backfillWG tracks the first-boot findings backfill goroutine so
	// Shutdown can drain it before the store pool is closed. Without
	// this, a long-running backfill would keep making queries against
	// the closed pool after Shutdown returns, spraying "pool closed"
	// errors into the log until the goroutine's timeout expired.
	// Analytics Phase 1 — /pensive:full-review action item B2.
	backfillWG sync.WaitGroup

	// pipeline runs the T2+T3 analytics transforms in the background.
	// Started after the findings backfill completes, stopped in Shutdown.
	// Analytics Phase 4A.
	pipeline *store.Pipeline

	// licencePusher reports usage metrics to the License Server on a
	// regular interval. Nil when no LicenseServer URL is configured or
	// when no licence token is present (free-tier / no-token mode).
	licencePusher *license.UsagePusher

	// manageEnrolHandlers serves the real /api/v1/admin/enrol/manage flow
	// when configured. Nil → handleEnrolManage returns 501. Batch G.
	manageEnrolHandlers *manage_enrol.EnrolHandlers

	// licencePortalClient communicates with the Licence Portal for tenant
	// licence activation/validation/deactivation. Nil when LicencePortalURL
	// is not configured.
	licencePortalClient *license.ServerClient

	// licenceValidatorDone is closed when the background validator exits.
	licenceValidatorDone chan struct{}
}

// BackfillInProgress exposes the atomic flag so cmd/server.go can flip
// it around the backfill goroutine. Handlers read it directly via
// s.backfillInProgress.Load(). Analytics Phase 1.
func (s *Server) BackfillInProgress() *atomic.Bool {
	return &s.backfillInProgress
}

// Context returns the server's base context. It is cancelled when
// Shutdown is called, providing a clean cancellation signal for
// background workers launched from cmd/server.go (currently: the
// Phase 1 analytics backfill goroutine). Callers should derive their
// own timeouts from this, e.g.:
//
//	bfCtx, cancel := context.WithTimeout(srv.Context(), 30*time.Minute)
//	defer cancel()
//
// Analytics Phase 1 — /pensive:full-review action item B2.
func (s *Server) Context() context.Context {
	return s.ctx
}

// BackfillWG exposes the backfill WaitGroup so cmd/server.go can
// register its goroutine and Shutdown can drain it. Callers MUST
// Add(1) before launching the goroutine and Done() inside the
// goroutine's defer block. Analytics Phase 1.
func (s *Server) BackfillWG() *sync.WaitGroup {
	return &s.backfillWG
}

// Pipeline returns the analytics pipeline for lifecycle wiring in cmd/server.go.
func (s *Server) Pipeline() *store.Pipeline {
	return s.pipeline
}

// EnqueuePipelineJob queues a T2+T3 refresh for the given org/hostname.
// No-op if the pipeline is nil (testing without pipeline).
func (s *Server) EnqueuePipelineJob(orgID, hostname, scanID string) {
	if s.pipeline == nil {
		return
	}
	s.pipeline.Enqueue(store.PipelineJob{
		OrgID:    orgID,
		Hostname: hostname,
		ScanID:   scanID,
	})
}

// auditSemDepth is the max number of concurrent writeAudit
// goroutines. 32 is chosen to stay well under pgx's default 4
// connections × 4 "waiter slack" while still absorbing short
// bursts; tune downward if the pool saturates in practice.
const auditSemDepth = 32

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

	rateLimitCfg := auth.DefaultLoginRateLimiterConfig
	if cfg.LoginRateLimiterConfig != nil {
		rateLimitCfg = *cfg.LoginRateLimiterConfig
	}
	requestLimitCfg := auth.DefaultRequestRateLimiterConfig
	if cfg.RequestRateLimiterConfig != nil {
		requestLimitCfg = *cfg.RequestRateLimiterConfig
	}
	ctx, cancel := context.WithCancel(context.Background())
	// Arch #4 JWT session cache. Clamp TTL into a sane range so
	// a misconfigured 24h TTL cannot silently cap revocation
	// latency at a full day — 5 minutes is the hard upper bound
	// because at 5 minutes the p99 improvement plateaus and the
	// eventual-consistency window becomes uncomfortable for
	// operators. Zero size means no cache (dev/testing only).
	var sessCache *sessioncache.SessionCache
	if cfg.SessionCacheSize > 0 {
		ttl := cfg.SessionCacheTTL
		if ttl <= 0 {
			ttl = 60 * time.Second
		}
		original := ttl
		if ttl < 5*time.Second {
			ttl = 5 * time.Second
		}
		if ttl > 5*time.Minute {
			ttl = 5 * time.Minute
		}
		if ttl != original {
			log.Printf("session cache TTL clamped from %s to %s (allowed range 5s–5m)", original, ttl)
		}
		sessCache = sessioncache.New(sessioncache.Config{
			MaxEntries: cfg.SessionCacheSize,
			TTL:        ttl,
		})
	}
	srv := &Server{
		config:              cfg,
		store:               s,
		guard:               cfg.Guard,
		loginLimiter:        auth.NewLoginRateLimiter(rateLimitCfg),
		requestLimiter:      auth.NewRequestRateLimiter(requestLimitCfg),
		ctx:                 ctx,
		cancel:              cancel,
		auditSem:            make(chan struct{}, auditSemDepth),
		sessionCache:        sessCache,
		manageEnrolHandlers: cfg.ManageEnrolHandlers,
	}
	srv.pipeline = store.NewPipeline(s)

	if cfg.LicencePortalURL != "" {
		srv.licencePortalClient = license.NewServerClient(cfg.LicencePortalURL)
	}
	srv.licenceValidatorDone = make(chan struct{})

	// Start licence usage pusher when a LicenseServer URL and a real
	// licence token are both present. Free-tier / no-token deployments
	// skip this entirely — they have nothing to report and no server to
	// push to. The pusher runs as a goroutine tied to srv.ctx so it stops
	// deterministically when Shutdown is called. Phase 4A.
	if cfg.LicenseServer != "" && cfg.Guard != nil && cfg.Guard.License() != nil {
		instanceID := cfg.InstanceID
		if instanceID == "" {
			instanceID = cfg.Guard.License().ID // stable per-deployment anchor
		}
		src := NewUsageSource(s)
		pusher := license.NewUsagePusher(license.UsagePusherConfig{
			LicenseServer: cfg.LicenseServer,
			LicenseID:     cfg.Guard.License().ID,
			InstanceID:    instanceID,
			Source:        src.Collect,
			Interval:      60 * time.Second,
		})
		srv.licencePusher = pusher
		go pusher.Run(ctx)
	}

	// Phase 5.1 D1 fix — periodically reclaim stale rate-limit entries
	// so a dictionary-style attack against unknown emails cannot leak
	// memory over time. Phase 5 Sprint 2 (N1) replaced the previous
	// context.Background() with srv.ctx so that Shutdown cancels the
	// janitor deterministically.
	//
	// The returned done channel is intentionally discarded here; if
	// a future caller needs to wait for background workers at
	// shutdown, thread it through Server struct state and drain it
	// inside Shutdown.
	_ = srv.loginLimiter.StartJanitor(ctx, rateLimitCfg.LockoutDuration)
	// Request rate limiter janitor — sweep interval equal to the
	// rolling window so stale entries from bursty one-off clients
	// are reclaimed promptly.
	_ = srv.requestLimiter.StartJanitor(ctx, requestLimitCfg.Window)

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
		// A10: transparently decompress gzipped request bodies.
		// Runs BEFORE auth/licence so a gzipped body with a valid
		// license token is parsed correctly. Uncompressed bodies
		// pass through unchanged — this is a pure additive
		// middleware with backward compatibility for pre-A10
		// agents.
		r.Use(GzipDecodeMiddleware)

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
		// Phase 5 Sprint 3 B3 — per-tenant request rate limit on
		// the data-plane route group. Runs AFTER UnifiedAuth so
		// the limiter keys by the resolved tenant org_id rather
		// than by IP. Unauthenticated requests fall back to
		// IP-based keying to still get DoS protection.
		r.Use(RequestRateLimit(srv.requestLimiter))
		srv.registerAPIRoutes(r)
	})

	// Admin API for service-to-service calls (license server → report server).
	// Only registered if a ServiceKey is configured. Uses its own auth
	// middleware (X-Triton-Service-Key) separate from the agent API key.
	if cfg.ServiceKey != "" {
		r.Route("/api/v1/admin", func(r chi.Router) {
			r.Use(ServiceKeyAuth(cfg.ServiceKey))
			r.Post("/orgs", srv.handleProvisionOrg)
			// Arch #4 operator break-glass — flush the JWT session
			// cache so a revoked token stops working inside the
			// current TTL window.
			r.Post("/sessions/flush", srv.handleFlushSessionCache)
			// Manage Server mTLS enrolment — stub in B1, implemented in
			// B2 (see pkg/server/handlers_enrol.go).
			r.Post("/enrol/manage", srv.handleEnrolManage)
		})
	}

	// User auth API (login, logout, refresh, change-password).
	// Only registered if JWT signing is configured.
	if cfg.JWTSigningKey != nil {
		r.Route("/api/v1/auth", func(r chi.Router) {
			// Phase 5 Sprint 3 full-review N2 fix: /auth/refresh and
			// /auth/change-password were outside the request rate
			// limiter, so an authenticated client could hammer them
			// at full speed bounded only by the global concurrency
			// throttle. RequestRateLimit keys by IP for these
			// routes (there's no tenant ctx on login/logout paths
			// and the JWT handlers set user context only AFTER
			// middleware runs), which gives DoS protection
			// without coupling the budget to the per-tenant
			// authenticated limit on /users and /audit.
			//
			// login remains gated by the dedicated per-email
			// LoginRateLimiter inside handleLogin — stricter
			// than the request limit because login is a
			// credential-attack surface, not a data-fetch surface.
			r.Use(RequestRateLimit(srv.requestLimiter))
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
			r.Use(JWTAuth(cfg.JWTPublicKey, s, srv.sessionCache))
			r.Use(BlockUntilPasswordChanged)
			r.Use(RequireOrgAdmin)
			// Per-tenant rate limit — same policy as the data-plane
			// /api/v1 group. Keys by the admin's OrgID (read from
			// the user context by RequestRateLimit when tenant is
			// empty... wait no, RequestRateLimit reads tenant
			// context which JWTAuth doesn't set. Use a dedicated
			// middleware that keys on the authenticated user.
			r.Use(RequestRateLimitByUser(srv.requestLimiter))
			r.Post("/", srv.handleCreateUser)
			r.Get("/", srv.handleListUsers)
			r.Get("/{id}", srv.handleGetUser)
			r.Put("/{id}", srv.handleUpdateUser)
			r.Delete("/{id}", srv.handleDeleteUser)
			r.Post("/{id}/resend-invite", srv.handleResendInvite)
		})

		// Audit log query — Phase 5 Sprint 3 B2. Org-scoped via the
		// JWT's org claim; admin role required to read.
		r.Route("/api/v1/audit", func(r chi.Router) {
			r.Use(JWTAuth(cfg.JWTPublicKey, s, srv.sessionCache))
			r.Use(BlockUntilPasswordChanged)
			r.Use(RequireOrgAdmin)
			r.Use(RequestRateLimitByUser(srv.requestLimiter))
			r.Get("/", srv.handleListAudit)
		})

		// Agent control channel — admin side. Requires JWT + org_admin
		// so humans can pause agents, enqueue cancel/force_run, and
		// view agent/command history. Tenant isolation is enforced by
		// the handlers reading TenantFromContext (the admin's OrgID).
		r.Route("/api/v1/admin/agents", func(r chi.Router) {
			r.Use(JWTAuth(cfg.JWTPublicKey, s, srv.sessionCache))
			r.Use(BlockUntilPasswordChanged)
			r.Use(RequireOrgAdmin)
			r.Use(RequestRateLimitByUser(srv.requestLimiter))
			r.Get("/", srv.handleAdminListAgents)
			r.Get("/{machineID}", srv.handleAdminGetAgent)
			r.Post("/{machineID}/pause", srv.handleAdminAgentPause)
			r.Delete("/{machineID}/pause", srv.handleAdminAgentPauseClear)
			r.Post("/{machineID}/commands", srv.handleAdminEnqueueCommand)
		})

		// Onboarding metrics — Phase 7 Task 9. Any authenticated user
		// can view their own org's progress (no admin requirement).
		r.Route("/api/v1/manage/onboarding-metrics", func(r chi.Router) {
			r.Use(JWTAuth(cfg.JWTPublicKey, s, srv.sessionCache))
			r.Use(BlockUntilPasswordChanged)
			r.Use(RequestRateLimitByUser(srv.requestLimiter))
			r.Get("/", srv.handleOnboardingMetrics)
		})
	}

	// Health check — intentionally outside the auth group so it remains public.
	// It returns no sensitive data (only {"status":"ok"}).
	r.Get("/api/v1/health", srv.handleHealth)

	// Pipeline status — operational endpoint for the UI's staleness bar.
	// No tenant auth required; returns no sensitive data.
	r.Get("/api/v1/pipeline/status", srv.handlePipelineStatus)

	// Metrics endpoint — Phase 5 Sprint 3 B4. Also outside the auth
	// group because Prometheus scrapers typically cannot
	// authenticate as a user. Operators restrict access via network
	// (reverse proxy IP allowlist or TLS client cert).
	r.Get("/api/v1/metrics", srv.handleMetrics)

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

		// Analytics Phase 1 — three new aggregation endpoints backed
		// by the denormalized findings table. All three are tenant-
		// scoped via the surrounding RequireTenant middleware.
		r.Get("/filters", s.handleFilterOptions)
		r.Get("/inventory", s.handleInventory)
		r.Get("/certificates/expiring", s.handleExpiringCertificates)
		r.Get("/priority", s.handlePriorityFindings)
		r.Get("/executive", s.handleExecutiveSummary)

		// Analytics Phase 4A — pre-computed host summaries, trend
		// sparklines, and pipeline staleness metadata.
		r.Get("/systems", s.handleSystems)
		r.Get("/trends", s.handleTrends)

		// Analytics Phase 5 — PDF and Excel export endpoints.
		r.Get("/export/pdf", s.handleExportPDF)
		r.Get("/export/xlsx", s.handleExportExcel)

		// Analytics Phase 4B — remediation tracking (read-only routes).
		// Mutation routes (status set / revert) require org_admin and
		// are registered in the RequireScanAdmin group below.
		r.Get("/remediation", s.handleListRemediation)
		r.Get("/remediation/summary", s.handleRemediationSummary)
		r.Get("/findings/{id}/history", s.handleFindingHistory)

		// Destructive operations require org_admin (Arch #7 from
		// Phase 2 review). org_user can read but cannot delete scans.
		r.Group(func(r chi.Router) {
			r.Use(RequireScanAdmin)
			r.Delete("/scans/{id}", s.handleDeleteScan)
			// Analytics Phase 4B — remediation status mutations.
			r.Post("/findings/{id}/status", s.handleSetFindingStatus)
			r.Post("/findings/{id}/revert", s.handleRevertFinding)
		})
	})

	// Agent control channel — agent side. Reuses the enclosing
	// RequireTenant gate (license-token auth populates the tenant via
	// UnifiedAuth on the parent /api/v1 group) and adds RequireMachineID
	// so every request is bound to a specific fingerprint. Agents
	// poll long-running GETs for commands and POST their results back.
	r.Group(func(r chi.Router) {
		r.Use(RequireTenant)
		r.Use(RequireMachineID)
		r.Get("/agent/commands/poll", s.handleAgentCommandsPoll)
		r.Post("/agent/commands/{id}/result", s.handleAgentCommandResult)
	})
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	log.Printf("Triton report server listening on %s", s.config.ListenAddr)
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		return s.http.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	return s.http.ListenAndServe()
}

// Shutdown gracefully shuts down the server. Order of operations:
//
//  1. Cancel the internal Server context so background workers
//     (rate-limit janitor, ticker-driven helpers) stop promptly.
//  2. Drain in-flight HTTP requests via http.Server.Shutdown up to
//     the caller-supplied deadline.
//  3. Wait for any outstanding writeAudit goroutines to finish.
//     These are fire-and-forget writes spawned AFTER the HTTP
//     response is returned, so http.Server.Shutdown does NOT wait
//     on them (Sprint 3 D2). Without this step, cmd/server.go's
//     defer db.Close() would tear down the store pool out from
//     under an in-flight audit write, silently losing the event.
//
// The audit drain uses the same ctx deadline the caller supplied to
// Shutdown so a stuck audit write cannot block indefinitely — an
// exhausted deadline logs and returns.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.pipeline != nil {
		s.pipeline.Stop()
	}
	if err := s.http.Shutdown(ctx); err != nil {
		return err
	}

	// Drain audit goroutines with a bounded wait.
	auditDone := make(chan struct{})
	go func() {
		s.auditWG.Wait()
		close(auditDone)
	}()
	select {
	case <-auditDone:
		// continue to backfill drain
	case <-ctx.Done():
		log.Printf("shutdown: audit drain deadline exceeded; some events may have been lost")
		return ctx.Err()
	}

	// Drain the analytics backfill goroutine (Phase 1). s.cancel()
	// above cancelled s.ctx, so any backfill goroutine derived from
	// it is already unwinding. Waiting here ensures the goroutine
	// finishes BEFORE cmd/server.go's deferred db.Close() fires —
	// without this, a long backfill would spray "pool closed"
	// errors into the log after Shutdown returns.
	// /pensive:full-review action item B2.
	backfillDone := make(chan struct{})
	go func() {
		s.backfillWG.Wait()
		close(backfillDone)
	}()
	select {
	case <-backfillDone:
		return nil
	case <-ctx.Done():
		log.Printf("shutdown: backfill drain deadline exceeded; goroutine will finish against a closing pool")
		return ctx.Err()
	}
}

// Router returns the chi router (for testing).
func (s *Server) Router() chi.Router {
	return s.router
}
