// Package engineadapter bridges the engine CA subsystem to the
// manage_enrol.CAProvider interface. It lives as a separate package so
// manage_enrol (and pkg/server, which imports manage_enrol for the
// EnrolHandlers type) can stay free of an engine import — engine itself
// imports pkg/server for the auth middleware, and a direct import from
// pkg/server → engine would close the cycle.
//
// Production wiring in cmd/server.go instantiates one Provider per
// Report-deployment.
package engineadapter

import (
	"context"
	"crypto"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server/engine"
	"github.com/amiryahaya/triton/pkg/server/manage_enrol"
)

// Provider is a manage_enrol.CAProvider backed by engine.Store +
// engine.CA.SignLeaf.
type Provider struct {
	store     engine.Store
	masterKey []byte
	orgID     uuid.UUID
}

// New wires a Provider. All three arguments are required; nil/zero values
// will panic on first use (fail-fast is correct — a misconfigured CA
// can't be salvaged at request time).
func New(store engine.Store, masterKey []byte, orgID uuid.UUID) *Provider {
	return &Provider{store: store, masterKey: masterKey, orgID: orgID}
}

// LoadCACert implements manage_enrol.CAProvider.
func (p *Provider) LoadCACert(ctx context.Context) ([]byte, error) {
	ca, err := p.store.GetCA(ctx, p.orgID)
	if err != nil {
		if errors.Is(err, engine.ErrCANotFound) {
			return nil, manage_enrol.ErrCANotBootstrapped
		}
		return nil, err
	}
	// Defensive copy so callers can't mutate the stored PEM.
	out := make([]byte, len(ca.CACertPEM))
	copy(out, ca.CACertPEM)
	return out, nil
}

// SignLeaf implements manage_enrol.CAProvider.
func (p *Provider) SignLeaf(ctx context.Context, cn string, validity time.Duration, pub crypto.PublicKey) ([]byte, error) {
	ca, err := p.store.GetCA(ctx, p.orgID)
	if err != nil {
		if errors.Is(err, engine.ErrCANotFound) {
			return nil, manage_enrol.ErrCANotBootstrapped
		}
		return nil, err
	}
	return ca.SignLeaf(p.masterKey, cn, validity, pub)
}

// Compile-time interface satisfaction assertion.
var _ manage_enrol.CAProvider = (*Provider)(nil)
