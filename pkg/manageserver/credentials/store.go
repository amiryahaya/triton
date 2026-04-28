package credentials

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

var (
	ErrCredentialNotFound = errors.New("credentials: not found")
	ErrConflict           = errors.New("credentials: name already exists for this tenant")
	ErrInUse              = errors.New("credentials: credential is referenced by one or more hosts")
)

// Store is the Postgres persistence boundary for credential metadata.
type Store interface {
	List(ctx context.Context, tenantID uuid.UUID) ([]Credential, error)
	Get(ctx context.Context, id uuid.UUID) (Credential, error)
	Create(ctx context.Context, c Credential) (Credential, error)
	// Update writes a new Vault secret version at the existing path and bumps
	// updated_at. The credential name and auth_type are immutable.
	Update(ctx context.Context, id uuid.UUID, payload SecretPayload) error
	Delete(ctx context.Context, id uuid.UUID) error
	CountHosts(ctx context.Context, credID uuid.UUID) (int64, error)
}
