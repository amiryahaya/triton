package server

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// requestCtxKeyType namespaces the request stash so it can't collide
// with other context values. Unexported — only this file reads/writes.
type requestCtxKeyType struct{}

var requestCtxKey = requestCtxKeyType{}

// requestFromContext returns the *http.Request stashed by
// StashRequestMiddleware, or nil when the middleware was not applied.
func requestFromContext(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestCtxKey).(*http.Request)
	return r
}

// StashRequestMiddleware attaches the current *http.Request to the
// request context so downstream helpers that only see a context.Context
// (e.g. inventory.AuditRecorder) can reach request-scoped fields like
// RemoteAddr and the authenticated user.
func StashRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), requestCtxKey, r)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuditAdapter bridges a context-scoped audit interface (used by the
// inventory subsystem and any future bounded context) to the existing
// request-scoped Server.writeAudit pipeline. A request must have
// passed through StashRequestMiddleware for Record to write; otherwise
// it is a silent no-op — never a panic.
//
// The concrete type satisfies any interface of the shape:
//
//	Record(ctx context.Context, event, subject string, fields map[string]any)
//
// so callers (e.g. cmd/server.go) can pass *AuditAdapter directly into
// inventory.Handlers without an explicit type conversion.
type AuditAdapter struct {
	srv *Server
}

// NewAuditAdapter wires a new AuditAdapter to the given server.
func NewAuditAdapter(s *Server) *AuditAdapter {
	return &AuditAdapter{srv: s}
}

// Record emits an audit event via the server's existing writeAudit
// pipeline. Silent no-op when the stash middleware wasn't applied.
func (a *AuditAdapter) Record(ctx context.Context, event, subject string, fields map[string]any) {
	r := requestFromContext(ctx)
	if r == nil {
		return
	}
	a.srv.writeAudit(r, event, subject, fields)
}

// MountAuthenticated mounts a subrouter under the given path with the
// standard authenticated-user middleware stack pre-applied (JWT auth,
// password-change gate, per-user rate limit, request stash). The setup
// callback registers concrete routes against the inner chi.Router.
//
// This exists to let external packages (cmd/server.go wiring the
// inventory bounded context) mount routes without pkg/server having to
// import them — which would create a cycle, since those packages
// already import pkg/server for ClaimsFromContext and RequireRole.
//
// Returns an error if JWT auth is not configured on the server
// (JWTPublicKey nil) — authenticated subtrees are meaningless then.
func (s *Server) MountAuthenticated(path string, setup func(r chi.Router)) error {
	if s.config.JWTPublicKey == nil {
		return errJWTNotConfigured
	}
	s.router.Route(path, func(r chi.Router) {
		r.Use(JWTAuth(s.config.JWTPublicKey, s.store, s.sessionCache))
		r.Use(BlockUntilPasswordChanged)
		r.Use(RequestRateLimitByUser(s.requestLimiter))
		r.Use(StashRequestMiddleware)
		setup(r)
	})
	return nil
}

// errJWTNotConfigured is returned from MountAuthenticated when JWT
// signing has not been configured on the server.
var errJWTNotConfigured = &configError{msg: "JWT auth not configured; cannot mount authenticated subtree"}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }
