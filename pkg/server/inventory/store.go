package inventory

import (
	"context"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server/hostmatch"
)

type Store interface {
	CreateGroup(ctx context.Context, g Group) (Group, error)
	GetGroup(ctx context.Context, orgID, id uuid.UUID) (Group, error)
	ListGroups(ctx context.Context, orgID uuid.UUID) ([]Group, error)
	UpdateGroup(ctx context.Context, orgID uuid.UUID, id uuid.UUID, name, description string) (Group, error)
	DeleteGroup(ctx context.Context, orgID, id uuid.UUID) error

	CreateHost(ctx context.Context, h Host) (Host, error)
	GetHost(ctx context.Context, orgID, id uuid.UUID) (Host, error)
	ListHosts(ctx context.Context, orgID uuid.UUID, filters HostFilters) ([]Host, error)
	UpdateHost(ctx context.Context, orgID uuid.UUID, id uuid.UUID, patch HostPatch) (Host, error)
	DeleteHost(ctx context.Context, orgID, id uuid.UUID) error

	SetTags(ctx context.Context, hostID uuid.UUID, tags []Tag) error
	GetTags(ctx context.Context, hostID uuid.UUID) ([]Tag, error)

	// ImportHosts bulk-inserts rows into a single group. Each row gets
	// its own SAVEPOINT so a unique/CHECK violation rolls back only
	// that row, not the whole batch. With dryRun=true the outer
	// transaction is rolled back and counts are still returned.
	ImportHosts(ctx context.Context, orgID, groupID uuid.UUID, rows []ImportRow, dryRun bool) (ImportResult, error)

	// ListHostSummaries returns the projection of every host in the org
	// joined with its tags. Credentials' matcher resolver consumes this
	// shape; the return type lives in pkg/server/hostmatch so neither
	// inventory nor credentials depends on the other.
	ListHostSummaries(ctx context.Context, orgID uuid.UUID) ([]hostmatch.HostSummary, error)

	// GetHostsByIDs returns hosts in the given org matching any of the
	// IDs. Used by the credentials gateway to enrich a claimed test job
	// with host address + port before handing it off to the engine.
	// Missing IDs are silently omitted.
	GetHostsByIDs(ctx context.Context, orgID uuid.UUID, ids []uuid.UUID) ([]Host, error)

	// GetEnginesForHosts returns the distinct engine_ids among the
	// provided host IDs. Hosts with NULL engine_id are excluded. Hosts
	// belonging to other orgs are excluded. Scan-job creation uses this
	// to enforce the one-engine-per-job invariant.
	GetEnginesForHosts(ctx context.Context, orgID uuid.UUID, hostIDs []uuid.UUID) (map[uuid.UUID]struct{}, error)
}

type HostFilters struct {
	GroupID *uuid.UUID
	OS      string
	Mode    string
}

type HostPatch struct {
	GroupID  *uuid.UUID
	Hostname *string
	OS       *string
	Mode     *string
}
