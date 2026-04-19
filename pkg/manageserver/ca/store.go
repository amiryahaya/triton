package ca

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/google/uuid"
)

// ErrNotFound is returned when the manage_ca row is absent (i.e. the
// instance has not yet been bootstrapped). Callers use errors.Is to
// distinguish "fresh install" from real DB faults.
var ErrNotFound = errors.New("ca: not found")

// Store is the persistence boundary for the Manage CA + its revocation
// list. The shape is deliberately narrow: CRUD on the singleton CA row,
// in-memory-cached revocation lookups, and a helper to mint short-lived
// server leaves for the gateway listener.
type Store interface {
	// Bootstrap returns the persisted CA, minting + inserting a fresh
	// one if no row exists. Idempotent — multiple callers racing on
	// Bootstrap all return the same CA.
	Bootstrap(ctx context.Context, instanceID string) (*CA, error)

	// Load returns the persisted CA or ErrNotFound when the manage_ca
	// row is missing. Unlike Bootstrap, this does NOT create anything.
	Load(ctx context.Context) (*CA, error)

	// IsRevoked reports whether `serial` (as a base-16 string, matching
	// x509.Certificate.SerialNumber.Text(16)) sits in the revocation
	// list. Backed by a 30-second in-memory cache; the first call after
	// cache expiry hits the DB. Called on every mTLS gateway request so
	// the cache is load-bearing.
	IsRevoked(ctx context.Context, serial string) (bool, error)

	// Revoke inserts a revocation row tied to (serial, agentID) with the
	// given reason, then invalidates the in-memory cache so the next
	// IsRevoked hit refreshes. Returns nil even if the serial was
	// already revoked (idempotent).
	Revoke(ctx context.Context, serial string, agentID uuid.UUID, reason string) error

	// RefreshRevocationCache re-reads the revocations table into memory.
	// Exposed for tests that need to force a refresh without sleeping
	// 30 seconds.
	RefreshRevocationCache(ctx context.Context) error

	// IssueServerCert mints a short-lived (90 day) server leaf signed by
	// the CA for the gateway :8443 TLS listener. hostname is both the
	// CN and the sole SAN (DNS or IP, whichever parses cleanly). The
	// returned tls.Certificate is ready to drop into tls.Config.
	// Certificates; callers should re-issue on every process start.
	IssueServerCert(ctx context.Context, hostname string) (tls.Certificate, error)
}
