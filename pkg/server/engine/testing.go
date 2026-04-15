package engine

import "context"

// ContextWithEngineForTesting injects an Engine into ctx using the
// same unexported key MTLSMiddleware uses, so tests for handlers
// that expect EngineFromContext can run without a real TLS stack.
//
// Production code paths must always go through MTLSMiddleware; this
// helper is exported only for the package's own tests and for
// downstream gateway handler tests (e.g., pkg/server/discovery).
func ContextWithEngineForTesting(ctx context.Context, e *Engine) context.Context {
	return context.WithValue(ctx, mtlsCtxKey{}, e)
}
