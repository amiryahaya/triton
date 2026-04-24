package manageserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/ca"
	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
	"github.com/amiryahaya/triton/pkg/manageserver/zones"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// Gateway listener lifecycle states. Read by /admin/gateway-health,
// written by gatewayRetryLoop + bootstrapGatewayListener.
const (
	gatewayStatePendingSetup int32 = 0 // CA not yet minted
	gatewayStateRetryLoop    int32 = 1 // Retry loop running, listener not yet up
	gatewayStateUp           int32 = 2 // Listener bound, cert minted, healthy
	gatewayStateFailed       int32 = 3 // Listener exited with error
)

// Server is the Manage Server HTTP shell. Run() blocks until ctx is cancelled.
type Server struct {
	cfg         *Config
	store       managestore.Store
	router      chi.Router
	gatewayR    chi.Router
	http        *http.Server
	httpGateway *http.Server

	mu           sync.RWMutex
	setupMode    bool              // true until admin created AND license activated
	loginLimiter *loginRateLimiter // in-memory brute-force guard for /auth/login

	gatewayState atomic.Int32 // see gatewayState* constants
	serverLeaf   atomic.Value // stores tls.Certificate when listener is up

	// Licence wiring (Task 5.1). Populated by startLicence; nil until
	// /setup/license activates or a valid persisted token is found at boot.
	licenceGuard  *license.Guard
	licencePusher *license.UsagePusher
	licenceCancel context.CancelFunc // cancels the pusher goroutine

	// Test-only overrides for Batch H licence-cap checks. Production
	// code leaves these nil and handlers fall back to licenceGuard.
	// mu-protected alongside the rest of the licence fields so a
	// concurrent test setter doesn't race the handler read.
	seatCapGuardOverride  SeatCapGuard
	hostCapGuardOverride  hosts.HostCapGuard
	scanCapGuardOverride  scanjobs.ScanCapGuard
	agentCapGuardOverride agents.AgentCapGuard

	// Admin-API handler packages (Batch C). Constructed in New() against
	// the shared pool and mounted under /api/v1/admin/*.
	zonesAdmin *zones.AdminHandlers
	hostsAdmin *hosts.AdminHandlers

	// Batch E admin handlers + the scanner pipeline stores. Orchestrator
	// + drain goroutines are spawned in Run() — not in New() — so
	// construction stays side-effect-free and testable.
	scanjobsAdmin   *scanjobs.AdminHandlers
	pushStatusAdmin *scanresults.AdminHandlers
	scanjobsStore   scanjobs.Store
	resultsStore    scanresults.Store
	hostsStore      *hosts.PostgresStore

	// Batch F agent enrolment + gateway wiring. caStore owns the
	// singleton CA + revocation cache; agentStore owns manage_agents
	// CRUD; agentsAdmin + agentsGateway are the admin-plane and
	// gateway-plane handler facades. The CA is bootstrapped in Run()
	// (not New) so instance_id resolution can fail cleanly before
	// minting a CA that would leak into tests.
	caStore       *ca.PostgresStore
	agentStore    agents.Store
	agentsAdmin   *agents.AdminHandlers
	agentsGateway *agents.GatewayHandlers

	// watcherRunning guards the single-watcher invariant for the
	// deactivation watcher goroutine. CompareAndSwap ensures at most
	// one goroutine is running at any time, preventing TOCTOU races
	// from concurrent handleLicenceDeactivate calls or a boot-time
	// resume racing a concurrent request.
	watcherRunning atomic.Bool

	// runCtx is the context passed to Run(). Set once at Run() entry and
	// used by goroutines spawned from HTTP handlers that must respect server
	// shutdown (e.g. the deactivation watcher). Nil until Run() is called
	// (e.g. in unit tests); callers must use a nil-safe fallback.
	runCtx context.Context
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

	// Default gateway listen + hostname so fresh configs boot a listener
	// without requiring the operator to set both. Tests override both
	// via Config; production deployments typically override GatewayListen
	// + GatewayHostname only.
	if cfg.GatewayListen == "" {
		cfg.GatewayListen = ":8443"
	}
	if cfg.GatewayHostname == "" {
		cfg.GatewayHostname = "localhost"
	}
	if cfg.GatewayRetryInterval == 0 {
		cfg.GatewayRetryInterval = 5 * time.Second
	}

	hostsStore := hosts.NewPostgresStore(pool)
	resultsStore := scanresults.NewPostgresStore(pool)
	scanjobsStore := scanjobs.NewPostgresStore(pool)
	caStore := ca.NewPostgresStore(pool)
	agentStore := agents.NewPostgresStore(pool)

	agentsGateway := agents.NewGatewayHandlers(caStore, agentStore, resultsStore)

	srv := &Server{
		cfg:             cfg,
		store:           store,
		loginLimiter:    newLoginRateLimiter(),
		zonesAdmin:      zones.NewAdminHandlers(zones.NewPostgresStore(pool)),
		pushStatusAdmin: scanresults.NewAdminHandlers(resultsStore),
		scanjobsStore:   scanjobsStore,
		resultsStore:    resultsStore,
		hostsStore:      hostsStore,
		caStore:         caStore,
		agentStore:      agentStore,
		agentsGateway:   agentsGateway,
	}
	// Guard providers close over srv so sub-handlers see the current
	// licence snapshot without a shared field write (race-free by
	// construction — see pkg/manageserver/license.go::guardSnapshot).
	// Providers consult the test overrides first so Set*CapGuardForTest
	// still wins without having to re-wire the handler.
	srv.hostsAdmin = hosts.NewAdminHandlers(hostsStore, srv.hostGuardProvider)
	srv.scanjobsAdmin = scanjobs.NewAdminHandlers(scanjobsStore, resultsStore, srv.scanGuardProvider)
	srv.agentsAdmin = agents.NewAdminHandlers(
		caStore, agentStore, gatewayURLFromCfg(cfg), 60*time.Second, srv.agentGuardProvider,
	)
	if err := srv.initSetupState(context.Background()); err != nil {
		return nil, fmt.Errorf("init setup state: %w", err)
	}
	srv.router = srv.buildRouter()
	srv.gatewayR = srv.buildGatewayRouter()

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
		r.Post("/change-password", s.handleChangePassword)
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
		r.Route("/scan-jobs", func(r chi.Router) {
			r.Use(s.rejectWhenDeactivationPending)
			scanjobs.MountAdminRoutes(r, s.scanjobsAdmin)
		})
		r.Route("/push-status", func(r chi.Router) { scanresults.MountAdminRoutes(r, s.pushStatusAdmin) })
		r.Route("/agents", func(r chi.Router) { agents.MountAdminRoutes(r, s.agentsAdmin) })
		r.Get("/gateway-health", s.handleGatewayHealth)
		r.Get("/licence", s.handleLicenceSummary)
		r.Get("/settings", s.handleSettings)

		// Admin-only subtree (user CRUD, agent enrol, licence lifecycle).
		// Role check is chained in addition to jwtAuth so a
		// network_engineer session hits 403 rather than silently
		// producing licence-seat output. Licence lifecycle routes are
		// destructive operations and require admin role.
		r.Group(func(r chi.Router) {
			r.Use(RequireRole("admin"))
			r.Route("/users", func(r chi.Router) {
				r.Get("/", s.handleListUsers)
				r.Post("/", s.handleCreateUser)
				r.Delete("/{id}", s.handleDeleteUser)
			})
			r.Route("/enrol", func(r chi.Router) { agents.MountEnrolRoutes(r, s.agentsAdmin) })
			r.Get("/security-events", s.handleListSecurityEvents)
			r.Delete("/security-events", s.handleClearSecurityEvent)
			// Licence lifecycle — destructive operations restricted to admin role.
			r.Post("/licence/refresh", s.handleLicenceRefresh)
			r.Post("/licence/replace", s.handleLicenceReplace)
			r.Post("/licence/deactivate", s.handleLicenceDeactivate)
			r.Delete("/licence/deactivation", s.handleCancelDeactivation)
		})
	})

	// Serve the embedded Vue portal at /ui/. Root and unknown paths
	// redirect to /ui/ so operators can visit https://manage.example.com
	// and land on the dashboard. The hash router inside the SPA handles
	// deep links (#/inventory/hosts etc.) so no SPA-fallback logic is
	// needed here.
	uiSub, _ := fs.Sub(uiFS, "ui/dist")
	r.Handle("/ui/*", http.StripPrefix("/ui/", http.FileServer(http.FS(uiSub))))
	r.Get("/ui", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/ui/", http.StatusMovedPermanently)
	})
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/ui/", http.StatusFound)
	})

	return r
}

// Run starts the HTTP listener and blocks until ctx is cancelled.
// On shutdown, blocks up to 10s for in-flight requests to complete
// and waits for the orchestrator + drain goroutines to exit.
//
// In addition to the admin listener, Run spawns a :8443 gateway
// listener if the CA is (or can be) bootstrapped. Gateway lifecycle
// is coupled to ctx but independent of the admin listener — a gateway
// failure is logged but never crashes the admin plane.
func (s *Server) Run(ctx context.Context) error {
	// Store the server context so handler-spawned goroutines (e.g. the
	// deactivation watcher) can respect server shutdown without holding
	// a stale request context.
	s.runCtx = ctx

	// Spawn the Batch E scanner pipeline before the HTTP listener comes
	// up so we never serve /scan-jobs while the orchestrator is offline.
	// startScannerPipeline derives a cancellable child context from ctx;
	// stopScannerPipeline waits for graceful exit. CA bootstrap rides
	// on the same instance_id resolution.
	pipelineWG := s.startScannerPipeline(ctx)

	// Resume pending deactivation watcher if server was restarted mid-deactivation.
	if setup, err := s.store.GetSetup(ctx); err == nil && setup.PendingDeactivation {
		if s.watcherRunning.CompareAndSwap(false, true) {
			go func() {
				defer s.watcherRunning.Store(false)
				s.runDeactivationWatcher(ctx)
			}()
		}
	}

	// Gateway listener runs concurrently with admin. Spawn it AFTER
	// startScannerPipeline (which bootstraps the CA) so the retry loop
	// sees a populated CA row on first-boot scenarios. When the CA is
	// not yet bootstrapped (e.g. /setup/license hasn't been called),
	// gatewayRetryLoop polls caStore.Load and brings the listener up
	// as soon as the CA lands, so the gateway self-recovers without a
	// server restart.
	gatewayWG := sync.WaitGroup{}
	gatewayWG.Add(1)
	go func() {
		defer gatewayWG.Done()
		s.gatewayRetryLoop(ctx)
	}()

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
		shutdownErr := s.http.Shutdown(shutdownCtx)
		// Wait for orchestrator + drain goroutines. The parent ctx is
		// already cancelled; they'll exit after their current poll tick.
		pipelineWG.Wait()
		gatewayWG.Wait()
		return shutdownErr
	case err := <-errCh:
		s.stopLicence()
		pipelineWG.Wait()
		gatewayWG.Wait()
		return err
	}
}

// startScannerPipeline spawns the orchestrator + drain goroutines. It
// returns a WaitGroup the caller blocks on during shutdown so a
// cancelled ctx doesn't leave workers running past Run's return.
//
// Two resolvers are intentionally best-effort at startup:
//   - InstanceID: if setup hasn't completed yet, we log and skip the
//     orchestrator. Future /setup/license activations can restart the
//     pipeline via a call-site outside this function (Batch F/G).
//   - Push creds: not present until Batch G's auto-enrol populates
//     manage_push_creds. We log and skip; drain will start idling
//     once creds land.
//
// Either branch returns a "drained" WaitGroup so Run.Wait is a no-op.
func (s *Server) startScannerPipeline(ctx context.Context) *sync.WaitGroup {
	var wg sync.WaitGroup

	state, err := s.store.GetSetup(ctx)
	if err != nil {
		log.Printf("manageserver: scanner pipeline: read setup state: %v (skipping orchestrator + drain)", err)
		return &wg
	}
	if state.InstanceID == "" {
		log.Printf("manageserver: scanner pipeline: instance_id not set (setup incomplete); skipping orchestrator + drain")
		return &wg
	}
	instanceID, err := uuid.Parse(state.InstanceID)
	if err != nil {
		log.Printf("manageserver: scanner pipeline: parse instance_id %q: %v (skipping orchestrator + drain)", state.InstanceID, err)
		return &wg
	}

	// Bootstrap the Manage CA now that instance_id is known. Idempotent —
	// re-running on every boot is a no-op once the row exists. This is
	// the only natural point to do it pre-gateway; Batch G's setup/
	// license flow also calls Bootstrap when instance_id first lands.
	s.bootstrapCA(ctx, instanceID.String())

	orch := scanjobs.NewOrchestrator(scanjobs.OrchestratorConfig{
		Store:       s.scanjobsStore,
		ResultStore: s.resultsStore,
		Parallelism: s.cfg.Parallelism,
		ScanFunc:    scanjobs.NewScanFunc(s.hostsStore),
		SourceID:    instanceID,
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		orch.Run(ctx)
	}()

	// Drain is best-effort: missing creds = log + idle. Batch G wires
	// the /setup or /enrol flow that persists creds; until then the
	// queue fills up with scan results and /admin/push-status surfaces
	// the backlog via queue_depth.
	creds, err := s.resultsStore.LoadPushCreds(ctx)
	if err != nil {
		log.Printf("manageserver: scanner pipeline: push creds not present (%v); drain idle until populated", err)
		return &wg
	}
	client, err := scanresults.BuildHTTPClient(creds)
	if err != nil {
		log.Printf("manageserver: scanner pipeline: build push http client: %v; drain disabled", err)
		return &wg
	}
	drain := scanresults.NewDrain(scanresults.DrainConfig{
		Store:     s.resultsStore,
		ReportURL: creds.ReportURL,
		Client:    client,
		Batch:     100,
		Interval:  5 * time.Second,
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		drain.Run(ctx)
	}()

	return &wg
}

// gatewayURLFromCfg returns the bundle-embedded URL the agent will
// dial. Prefers an explicit ManageGatewayURL; otherwise derives one
// from GatewayHostname + GatewayListen so operators only need to set
// either one.
func gatewayURLFromCfg(cfg *Config) string {
	if cfg.ManageGatewayURL != "" {
		return cfg.ManageGatewayURL
	}
	host := cfg.GatewayHostname
	if host == "" {
		host = "localhost"
	}
	port := cfg.GatewayListen
	if port == "" {
		port = ":8443"
	}
	return "https://" + host + port
}

// buildGatewayRouter wires the :8443 agent-facing chi router. Agents
// authenticate via client certs; MTLSCNAuth enforces CN prefix +
// revocation on every request.
func (s *Server) buildGatewayRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Route("/api/v1/gateway", func(r chi.Router) {
		r.Use(agents.MTLSCNAuth("agent:", s.caStore))
		agents.MountGatewayRoutes(r, s.agentsGateway)
	})
	return r
}

// gatewayRetryLoop polls caStore.Load every cfg.GatewayRetryInterval
// until the CA is bootstrapped, then invokes bootstrapGatewayListener.
// Meant to be spawned as a goroutine from Server.Run.
//
// Gateway failures are logged but don't kill the admin :8082 listener —
// a broken CA shouldn't knock the admin UI offline. When the CA is
// absent at Run-entry, the loop keeps polling so that a later
// /setup/license call (which triggers bootstrapCA) brings the gateway
// up without a process restart.
//
// Cancellation: ctx cancel stops the poll loop AND (via
// bootstrapGatewayListener) the listener itself.
//
// SERVER CERT LIFETIME — the TLS leaf handed to the listener is
// issued once at listener startup by caStore.IssueServerCert with a
// 90-day NotAfter (serverCertValidity in pkg/manageserver/ca/postgres.go).
// The cert is NOT auto-rotated at runtime: a server restart is
// required to mint a fresh leaf. Operators SHOULD schedule a restart
// well before the 90-day window closes (e.g. monthly, rolling) to
// avoid agent handshakes tripping expired-cert errors. Shortening or
// lengthening the lifetime requires editing serverCertValidity and
// redeploying — there's no runtime knob.
//
// The CA itself is 10-year and covers the server leaf through
// many restart cycles, so this is only a server-leaf concern.
func (s *Server) gatewayRetryLoop(ctx context.Context) {
	s.gatewayState.Store(gatewayStatePendingSetup)

	ticker := time.NewTicker(s.cfg.GatewayRetryInterval)
	defer ticker.Stop()

	for {
		if _, err := s.caStore.Load(ctx); err == nil {
			s.gatewayState.Store(gatewayStateRetryLoop)
			if err := s.bootstrapGatewayListener(ctx); err != nil {
				log.Printf("manageserver: gateway listener exited: %v", err)
				s.gatewayState.Store(gatewayStateFailed)
			}
			return
		} else if !errors.Is(err, ca.ErrNotFound) {
			// Transient DB error — log once per tick and keep polling.
			// A sticky DB failure isn't the gateway's problem to solve.
			log.Printf("manageserver: gateway retry loop: caStore.Load: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// loop
		}
	}
}

// bootstrapGatewayListener assumes the CA is bootstrapped. Mints a
// fresh server leaf via caStore.IssueServerCert, caches it on Server
// (so /admin/gateway-health can report its expiry), flips gatewayState
// to Up, and blocks until ctx.Done() or listener error.
//
// Called at most once per Server lifetime by gatewayRetryLoop.
func (s *Server) bootstrapGatewayListener(ctx context.Context) error {
	caBundle, err := s.caStore.Load(ctx)
	if err != nil {
		return fmt.Errorf("load CA for gateway: %w", err)
	}

	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caBundle.CACertPEM) {
		return errors.New("append CA cert to pool failed")
	}

	serverCert, err := s.caStore.IssueServerCert(ctx, s.cfg.GatewayHostname)
	if err != nil {
		return fmt.Errorf("issue server cert: %w", err)
	}
	// Publish the leaf so /admin/gateway-health can read NotAfter
	// without another CA round-trip.
	s.serverLeaf.Store(serverCert)

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		Certificates: []tls.Certificate{serverCert},
	}

	s.httpGateway = &http.Server{
		Addr:              s.cfg.GatewayListen,
		Handler:           s.gatewayR,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpGateway.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Flip to Up only after ListenAndServeTLS has been invoked. A
	// bind-error on the port won't have hit the handshake path yet;
	// the errCh branch below will demote to Failed in that case.
	s.gatewayState.Store(gatewayStateUp)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpGateway.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// bootstrapCA idempotently mints + persists the Manage CA using the
// caller-supplied instanceID. Called from startScannerPipeline once
// instance_id is known — before the gateway listener comes up — so
// the :8443 TLS handshake has a CA to chain against.
func (s *Server) bootstrapCA(ctx context.Context, instanceID string) {
	if _, err := s.caStore.Bootstrap(ctx, instanceID); err != nil {
		log.Printf("manageserver: bootstrap CA: %v (gateway will be disabled)", err)
	}
}

// rejectWhenDeactivationPending blocks new scan job creation (POST) when
// a deactivation is scheduled.
func (s *Server) rejectWhenDeactivationPending(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if state, err := s.store.GetSetup(r.Context()); err == nil && state.PendingDeactivation {
				writeError(w, http.StatusConflict, "deactivation pending; no new scan jobs accepted")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
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
