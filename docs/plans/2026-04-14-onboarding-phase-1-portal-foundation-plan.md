# Onboarding Phase 1 — Portal Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the portal container with Identity (from `feat/multi-tenant`) extended with the `Officer` role, a new Inventory bounded context (groups/hosts/tags CRUD) served under `/api/v1/manage/*`, an audit log write path, and a minimal `/manage/*` UI — all gated by RBAC.

**Architecture:** Extend the existing `pkg/server` package (which already provides auth, audit, analytics, report UI). Add a new sub-package `pkg/server/inventory/` for the Inventory context. Mount two UI surfaces: `/manage/*` (new vanilla-JS SPA) and `/reports/*` (existing dashboard, relocated from `/`). No new binary in this phase — the portal IS the existing server process with new routes. The spec's aspirational `pkg/portal/*` naming is deferred to a later rename.

**Tech Stack:** Go 1.25, `go-chi/chi/v5`, `jackc/pgx/v5`, PostgreSQL 18 (JSONB + `inet` + `cidr` types), vanilla JS for management UI (consistent with existing report UI), existing `internal/auth/sessioncache` for JWT sessions.

**Spec:** `docs/plans/2026-04-14-onboarding-design.md`

---

## Prerequisites

- [ ] `feat/multi-tenant` merged to `main`. Confirm the following exist in the codebase before starting:
  - `pkg/server/auth_middleware.go` with a JWT middleware
  - Identity types (`User`, `Org`, `Session`) — inspect exact package path and rename references accordingly
  - `pkg/store/Store` interface extended with user/org methods
  - Migration scripts in `pkg/store/migrations/` for identity schema

If multi-tenant is not merged, STOP and escalate — the Identity context is a hard dependency.

---

## File Map

**Create:**
- `pkg/server/inventory/types.go` — domain types (Group, Host, Tag)
- `pkg/server/inventory/store.go` — Store interface (inventory-scoped)
- `pkg/server/inventory/postgres.go` — PostgresStore impl
- `pkg/server/inventory/postgres_test.go` — integration tests
- `pkg/server/inventory/handlers.go` — HTTP handlers under `/api/v1/manage/`
- `pkg/server/inventory/handlers_test.go` — HTTP handler tests
- `pkg/server/inventory/routes.go` — route mounting helper
- `pkg/server/rbac.go` — role gate middleware
- `pkg/server/rbac_test.go` — middleware tests
- `pkg/server/ui/manage/index.html` — management UI shell
- `pkg/server/ui/manage/app.js` — management UI JS (groups + hosts pages)
- `pkg/server/ui/manage/style.css` — management UI styles
- `pkg/store/migrations/V0XX__inventory.sql` — groups/hosts/tags schema
- `pkg/store/migrations/V0XX__officer_role.sql` — add `officer` to roles enum

**Modify:**
- `pkg/server/server.go` — mount `/manage/*` UI + `/api/v1/manage/*` routes; ensure `/reports/*` still serves existing dashboard
- `pkg/server/handlers.go` — root `/` redirects to `/manage/` for Owner/Engineer, `/reports/` for Officer
- `pkg/server/audit.go` — extend with inventory events if the existing event taxonomy doesn't cover group/host mutations (spot-check before modifying)

**Do not touch:**
- `pkg/licenseserver/*` — unrelated to this phase
- Anything under `pkg/scanner/*` — scanner engine is out of scope here

---

### Task 1: Role extension — add `officer`

Multi-tenant currently ships two roles (per design spec). Add the third.

**Files:**
- Create: `pkg/store/migrations/V0XX__officer_role.sql`
- Modify: identity role constants in the multi-tenant package (path TBD once multi-tenant merged; likely `pkg/server/identity/roles.go` or similar)
- Modify: `pkg/server/rbac.go` (created in Task 2)

- [ ] **Step 1: Inspect current role definitions**

Run: `grep -rn "owner\|engineer\|officer\|admin" pkg/server/ --include="*.go" | grep -i role | head -20`

Confirm which roles currently exist post-multi-tenant merge. If `officer` already exists, skip this task entirely.

- [ ] **Step 2: Write migration**

Create `pkg/store/migrations/V0XX__officer_role.sql` with the correct schema path (replace `identity.user_roles` below if multi-tenant uses a different table/column name; check with `grep -rn "CREATE TABLE.*role\|role.*enum" pkg/store/migrations/`):

```sql
-- Add 'officer' to the role enum used by identity.
-- Matches Onboarding design spec §5: Owner / Engineer / Officer.
ALTER TYPE identity.user_role ADD VALUE IF NOT EXISTS 'officer';
```

If the roles are stored as `text` + CHECK constraint rather than an enum type, instead:

```sql
ALTER TABLE identity.users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE identity.users ADD CONSTRAINT users_role_check
  CHECK (role IN ('owner', 'engineer', 'officer'));
```

- [ ] **Step 3: Extend role constants**

Add `RoleOfficer = "officer"` to wherever `RoleOwner` and `RoleEngineer` live (grep to find). Add it to the "valid roles" set.

- [ ] **Step 4: Run migrations locally, verify**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" make db-up
go test -run TestMigrations ./pkg/store/
```

Expected: no migration errors.

- [ ] **Step 5: Commit**

```bash
git add pkg/store/migrations/V0XX__officer_role.sql <role constant file>
git commit -m "feat(identity): add officer role for onboarding RBAC"
```

---

### Task 2: RBAC middleware

**Files:**
- Create: `pkg/server/rbac.go`
- Create: `pkg/server/rbac_test.go`

- [ ] **Step 1: Write failing test**

`pkg/server/rbac_test.go`:

```go
package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireRole_AllowsMatchingRole(t *testing.T) {
	h := RequireRole(RoleEngineer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(withClaims(req.Context(), &SessionClaims{Role: RoleEngineer}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRequireRole_RejectsLowerRole(t *testing.T) {
	h := RequireRole(RoleEngineer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(withClaims(req.Context(), &SessionClaims{Role: RoleOfficer}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRequireRole_RejectsNoClaims(t *testing.T) {
	h := RequireRole(RoleOfficer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
```

**Note:** `withClaims` and `SessionClaims` must match whatever multi-tenant named them. If multi-tenant uses `requestClaims` or `AuthContext`, adjust the test and implementation accordingly.

- [ ] **Step 2: Run tests — verify they fail**

Run: `go test -run TestRequireRole ./pkg/server/`
Expected: FAIL (RequireRole not defined)

- [ ] **Step 3: Implement RBAC**

`pkg/server/rbac.go`:

```go
package server

import (
	"net/http"
)

// Role hierarchy (highest → lowest):
//   owner > engineer > officer
// A route gated at RoleEngineer allows owner + engineer but not officer.
var roleRank = map[string]int{
	RoleOfficer:  1,
	RoleEngineer: 2,
	RoleOwner:    3,
}

// RequireRole returns middleware that enforces the caller has at least
// the given role. It relies on an upstream middleware (JWT auth) having
// populated session claims in the request context.
func RequireRole(min string) func(http.Handler) http.Handler {
	minRank := roleRank[min]
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := claimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if roleRank[claims.Role] < minRank {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
```

Use the exact claim-context helper name from multi-tenant (replace `claimsFromContext` if multi-tenant named it differently).

- [ ] **Step 4: Verify tests pass**

Run: `go test -run TestRequireRole ./pkg/server/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/server/rbac.go pkg/server/rbac_test.go
git commit -m "feat(server): RBAC middleware with owner/engineer/officer hierarchy"
```

---

### Task 3: Inventory schema migration

**Files:**
- Create: `pkg/store/migrations/V0XX__inventory.sql`

- [ ] **Step 1: Determine next migration number**

Run: `ls pkg/store/migrations/ | sort | tail -3`
Pick the next sequential `V0XX` number for this file AND the officer role migration from Task 1 (they must not collide).

- [ ] **Step 2: Write migration**

`pkg/store/migrations/V0XX__inventory.sql`:

```sql
CREATE SCHEMA IF NOT EXISTS inventory;

CREATE TABLE inventory.groups (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES identity.orgs(id) ON DELETE CASCADE,
    name        text NOT NULL,
    description text,
    created_at  timestamptz NOT NULL DEFAULT NOW(),
    created_by  uuid REFERENCES identity.users(id),
    UNIQUE (org_id, name)
);

CREATE INDEX idx_inventory_groups_org ON inventory.groups(org_id);

CREATE TABLE inventory.hosts (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES identity.orgs(id) ON DELETE CASCADE,
    group_id     uuid NOT NULL REFERENCES inventory.groups(id) ON DELETE RESTRICT,
    hostname     text,
    address      inet,
    os           text CHECK (os IN ('linux', 'windows', 'macos', 'cisco-iosxe', 'juniper-junos', 'unknown')),
    mode         text NOT NULL DEFAULT 'agentless' CHECK (mode IN ('agentless', 'agent')),
    engine_id    uuid, -- FK added in Phase 2 when engines table exists
    last_scan_id uuid,
    last_seen    timestamptz,
    created_at   timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, hostname)
);

CREATE INDEX idx_inventory_hosts_group ON inventory.hosts(group_id);
CREATE INDEX idx_inventory_hosts_org   ON inventory.hosts(org_id);

CREATE TABLE inventory.tags (
    host_id uuid NOT NULL REFERENCES inventory.hosts(id) ON DELETE CASCADE,
    key     text NOT NULL,
    value   text NOT NULL,
    PRIMARY KEY (host_id, key)
);

CREATE INDEX idx_inventory_tags_kv ON inventory.tags(key, value);
```

Reference: the references to `identity.orgs(id)` and `identity.users(id)` assume multi-tenant uses those exact names. If not, update the FKs.

- [ ] **Step 3: Apply + verify**

```bash
make db-up
TRITON_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" go run ./cmd/triton-migrate up
```

If no `triton-migrate` binary exists, use whatever migration runner the existing codebase uses (check `Makefile`). Verify with:

```bash
psql "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" -c "\dt inventory.*"
```

Expected: three tables listed.

- [ ] **Step 4: Commit**

```bash
git add pkg/store/migrations/V0XX__inventory.sql
git commit -m "feat(store): inventory schema — groups, hosts, tags"
```

---

### Task 4: Inventory domain types

**Files:**
- Create: `pkg/server/inventory/types.go`

- [ ] **Step 1: Write types**

`pkg/server/inventory/types.go`:

```go
// Package inventory is the Onboarding Inventory bounded context:
// groups of hosts, hosts themselves, and key-value tags attached
// to hosts. All APIs are scoped by org_id enforced at the store layer.
package inventory

import (
	"net"
	"time"

	"github.com/google/uuid"
)

type Group struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   uuid.UUID `json:"created_by"`
}

type Host struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	GroupID    uuid.UUID  `json:"group_id"`
	Hostname   string     `json:"hostname,omitempty"`
	Address    net.IP     `json:"address,omitempty"`
	OS         string     `json:"os,omitempty"`
	Mode       string     `json:"mode"` // agentless|agent
	EngineID   *uuid.UUID `json:"engine_id,omitempty"`
	LastScanID *uuid.UUID `json:"last_scan_id,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	Tags       []Tag      `json:"tags,omitempty"`
}

type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
```

- [ ] **Step 2: Build**

Run: `go build ./pkg/server/inventory/`
Expected: success (package exists, no other deps yet).

- [ ] **Step 3: Commit**

```bash
git add pkg/server/inventory/types.go
git commit -m "feat(inventory): domain types — Group, Host, Tag"
```

---

### Task 5: Inventory Store interface

**Files:**
- Create: `pkg/server/inventory/store.go`

- [ ] **Step 1: Define the interface**

`pkg/server/inventory/store.go`:

```go
package inventory

import (
	"context"

	"github.com/google/uuid"
)

// Store is the persistence interface for the Inventory context.
// Every method MUST scope by orgID to prevent cross-tenant leaks.
// Implementations: PostgresStore (pkg/server/inventory/postgres.go).
type Store interface {
	// Groups
	CreateGroup(ctx context.Context, g Group) (Group, error)
	GetGroup(ctx context.Context, orgID, id uuid.UUID) (Group, error)
	ListGroups(ctx context.Context, orgID uuid.UUID) ([]Group, error)
	UpdateGroup(ctx context.Context, orgID uuid.UUID, id uuid.UUID, name, description string) (Group, error)
	DeleteGroup(ctx context.Context, orgID, id uuid.UUID) error

	// Hosts
	CreateHost(ctx context.Context, h Host) (Host, error)
	GetHost(ctx context.Context, orgID, id uuid.UUID) (Host, error)
	ListHosts(ctx context.Context, orgID uuid.UUID, filters HostFilters) ([]Host, error)
	UpdateHost(ctx context.Context, orgID uuid.UUID, id uuid.UUID, patch HostPatch) (Host, error)
	DeleteHost(ctx context.Context, orgID, id uuid.UUID) error

	// Tags (attached to a host)
	SetTags(ctx context.Context, hostID uuid.UUID, tags []Tag) error
	GetTags(ctx context.Context, hostID uuid.UUID) ([]Tag, error)
}

type HostFilters struct {
	GroupID *uuid.UUID
	OS      string
	Mode    string
	TagKey  string
	TagVal  string
}

type HostPatch struct {
	GroupID  *uuid.UUID
	Hostname *string
	OS       *string
	Mode     *string
}
```

- [ ] **Step 2: Build + commit**

```bash
go build ./pkg/server/inventory/
git add pkg/server/inventory/store.go
git commit -m "feat(inventory): Store interface with org-scoped methods"
```

---

### Task 6: PostgresStore implementation with tests

**Files:**
- Create: `pkg/server/inventory/postgres.go`
- Create: `pkg/server/inventory/postgres_test.go`

- [ ] **Step 1: Write integration tests first**

`pkg/server/inventory/postgres_test.go` (use build tag `integration` so they don't run in `make test`):

```go
//go:build integration

package inventory

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newTestStore(t *testing.T) (*PostgresStore, uuid.UUID) {
	t.Helper()
	url := os.Getenv("TRITON_TEST_DB_URL")
	if url == "" {
		t.Skip("TRITON_TEST_DB_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	orgID := uuid.Must(uuid.NewV7())
	// Seed a fake org so FKs pass. Assumes identity.orgs exists with columns (id, name).
	_, err = pool.Exec(context.Background(),
		`INSERT INTO identity.orgs (id, name) VALUES ($1, 'test-org-' || $1::text)`,
		orgID,
	)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM identity.orgs WHERE id = $1`, orgID)
	})

	return &PostgresStore{pool: pool}, orgID
}

func TestPostgresStore_CreateAndListGroups(t *testing.T) {
	store, orgID := newTestStore(t)
	ctx := context.Background()

	g, err := store.CreateGroup(ctx, Group{
		ID:    uuid.Must(uuid.NewV7()),
		OrgID: orgID,
		Name:  "prod-web",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if g.Name != "prod-web" {
		t.Fatalf("expected prod-web, got %s", g.Name)
	}

	groups, err := store.ListGroups(ctx, orgID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
}

func TestPostgresStore_HostWithTags(t *testing.T) {
	store, orgID := newTestStore(t)
	ctx := context.Background()

	g, _ := store.CreateGroup(ctx, Group{ID: uuid.Must(uuid.NewV7()), OrgID: orgID, Name: "grp"})

	h, err := store.CreateHost(ctx, Host{
		ID:       uuid.Must(uuid.NewV7()),
		OrgID:    orgID,
		GroupID:  g.ID,
		Hostname: "app-01",
		OS:       "linux",
		Mode:     "agentless",
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}

	err = store.SetTags(ctx, h.ID, []Tag{
		{Key: "env", Value: "prod"},
		{Key: "team", Value: "platform"},
	})
	if err != nil {
		t.Fatalf("set tags: %v", err)
	}

	tags, err := store.GetTags(ctx, h.ID)
	if err != nil {
		t.Fatalf("get tags: %v", err)
	}
	if len(tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(tags))
	}
}

func TestPostgresStore_OrgScopingBlocksCrossTenant(t *testing.T) {
	store1, org1 := newTestStore(t)
	_, org2 := newTestStore(t)
	ctx := context.Background()

	g, _ := store1.CreateGroup(ctx, Group{ID: uuid.Must(uuid.NewV7()), OrgID: org1, Name: "g1"})

	// Attempt to fetch org1's group using org2 — must fail.
	_, err := store1.GetGroup(ctx, org2, g.ID)
	if err == nil {
		t.Fatal("expected cross-tenant fetch to fail, got nil error")
	}
}
```

- [ ] **Step 2: Run tests, verify they fail to build (no implementation)**

Run: `go test -tags integration ./pkg/server/inventory/`
Expected: build error — `undefined: PostgresStore`.

- [ ] **Step 3: Implement PostgresStore**

`pkg/server/inventory/postgres.go`:

```go
package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// --- Groups ---

func (s *PostgresStore) CreateGroup(ctx context.Context, g Group) (Group, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO inventory.groups (id, org_id, name, description, created_by)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING created_at`,
		g.ID, g.OrgID, g.Name, g.Description, g.CreatedBy,
	)
	if err := row.Scan(&g.CreatedAt); err != nil {
		return Group{}, fmt.Errorf("create group: %w", err)
	}
	return g, nil
}

func (s *PostgresStore) GetGroup(ctx context.Context, orgID, id uuid.UUID) (Group, error) {
	var g Group
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, name, COALESCE(description, ''), created_at, created_by
		 FROM inventory.groups WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	if err := row.Scan(&g.ID, &g.OrgID, &g.Name, &g.Description, &g.CreatedAt, &g.CreatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Group{}, fmt.Errorf("group %s not found in org %s", id, orgID)
		}
		return Group{}, err
	}
	return g, nil
}

func (s *PostgresStore) ListGroups(ctx context.Context, orgID uuid.UUID) ([]Group, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, name, COALESCE(description, ''), created_at, created_by
		 FROM inventory.groups WHERE org_id = $1 ORDER BY name`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.OrgID, &g.Name, &g.Description, &g.CreatedAt, &g.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateGroup(ctx context.Context, orgID, id uuid.UUID, name, description string) (Group, error) {
	_, err := s.pool.Exec(ctx,
		`UPDATE inventory.groups SET name = $3, description = $4 WHERE org_id = $1 AND id = $2`,
		orgID, id, name, description,
	)
	if err != nil {
		return Group{}, err
	}
	return s.GetGroup(ctx, orgID, id)
}

func (s *PostgresStore) DeleteGroup(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM inventory.groups WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	return err
}

// --- Hosts ---

func (s *PostgresStore) CreateHost(ctx context.Context, h Host) (Host, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO inventory.hosts (id, org_id, group_id, hostname, address, os, mode)
		 VALUES ($1, $2, $3, NULLIF($4, ''), $5, NULLIF($6, ''), $7)
		 RETURNING created_at`,
		h.ID, h.OrgID, h.GroupID, h.Hostname, h.Address, h.OS, h.Mode,
	)
	if err := row.Scan(&h.CreatedAt); err != nil {
		return Host{}, fmt.Errorf("create host: %w", err)
	}
	return h, nil
}

func (s *PostgresStore) GetHost(ctx context.Context, orgID, id uuid.UUID) (Host, error) {
	var h Host
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, group_id, COALESCE(hostname, ''), address, COALESCE(os, ''), mode, created_at
		 FROM inventory.hosts WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	if err := row.Scan(&h.ID, &h.OrgID, &h.GroupID, &h.Hostname, &h.Address, &h.OS, &h.Mode, &h.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Host{}, fmt.Errorf("host %s not found in org %s", id, orgID)
		}
		return Host{}, err
	}
	tags, err := s.GetTags(ctx, h.ID)
	if err != nil {
		return Host{}, err
	}
	h.Tags = tags
	return h, nil
}

func (s *PostgresStore) ListHosts(ctx context.Context, orgID uuid.UUID, f HostFilters) ([]Host, error) {
	q := `SELECT id, org_id, group_id, COALESCE(hostname, ''), address, COALESCE(os, ''), mode, created_at
	      FROM inventory.hosts WHERE org_id = $1`
	args := []any{orgID}
	if f.GroupID != nil {
		q += fmt.Sprintf(" AND group_id = $%d", len(args)+1)
		args = append(args, *f.GroupID)
	}
	if f.OS != "" {
		q += fmt.Sprintf(" AND os = $%d", len(args)+1)
		args = append(args, f.OS)
	}
	if f.Mode != "" {
		q += fmt.Sprintf(" AND mode = $%d", len(args)+1)
		args = append(args, f.Mode)
	}
	q += " ORDER BY hostname"

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.ID, &h.OrgID, &h.GroupID, &h.Hostname, &h.Address, &h.OS, &h.Mode, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateHost(ctx context.Context, orgID, id uuid.UUID, p HostPatch) (Host, error) {
	// Build patch dynamically so each field is optional.
	set := []string{}
	args := []any{orgID, id}
	if p.GroupID != nil {
		set = append(set, fmt.Sprintf("group_id = $%d", len(args)+1))
		args = append(args, *p.GroupID)
	}
	if p.Hostname != nil {
		set = append(set, fmt.Sprintf("hostname = $%d", len(args)+1))
		args = append(args, *p.Hostname)
	}
	if p.OS != nil {
		set = append(set, fmt.Sprintf("os = $%d", len(args)+1))
		args = append(args, *p.OS)
	}
	if p.Mode != nil {
		set = append(set, fmt.Sprintf("mode = $%d", len(args)+1))
		args = append(args, *p.Mode)
	}
	if len(set) > 0 {
		q := "UPDATE inventory.hosts SET " + join(set, ", ") + " WHERE org_id = $1 AND id = $2"
		_, err := s.pool.Exec(ctx, q, args...)
		if err != nil {
			return Host{}, err
		}
	}
	return s.GetHost(ctx, orgID, id)
}

func (s *PostgresStore) DeleteHost(ctx context.Context, orgID, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM inventory.hosts WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	return err
}

// --- Tags ---

func (s *PostgresStore) SetTags(ctx context.Context, hostID uuid.UUID, tags []Tag) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `DELETE FROM inventory.tags WHERE host_id = $1`, hostID); err != nil {
		return err
	}
	for _, t := range tags {
		if _, err := tx.Exec(ctx,
			`INSERT INTO inventory.tags (host_id, key, value) VALUES ($1, $2, $3)`,
			hostID, t.Key, t.Value,
		); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) GetTags(ctx context.Context, hostID uuid.UUID) ([]Tag, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, value FROM inventory.tags WHERE host_id = $1 ORDER BY key`,
		hostID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Tag
	for rows.Next() {
		var t Tag
		if err := rows.Scan(&t.Key, &t.Value); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func join(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}
```

- [ ] **Step 4: Run integration tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/server/inventory/
```

Expected: PASS on all three tests.

- [ ] **Step 5: Commit**

```bash
git add pkg/server/inventory/postgres.go pkg/server/inventory/postgres_test.go
git commit -m "feat(inventory): PostgresStore with org-scoped CRUD"
```

---

### Task 7: HTTP handlers

**Files:**
- Create: `pkg/server/inventory/handlers.go`
- Create: `pkg/server/inventory/handlers_test.go`
- Create: `pkg/server/inventory/routes.go`

- [ ] **Step 1: Write handler tests**

`pkg/server/inventory/handlers_test.go` — one test per endpoint × role matrix. Skeleton:

```go
package inventory

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestCreateGroup_RequiresEngineerOrHigher(t *testing.T) {
	// Officer tries POST /api/v1/manage/groups → 403
	// Engineer tries same → 201
	// (See full test body when implementing.)
}

func TestListGroups_AllowsAnyAuthenticated(t *testing.T) {
	// Officer can GET, just can't mutate.
}

func TestCreateHost_InvalidGroup_Returns404(t *testing.T) {
	// group_id for a different org should 404 (not 403 — don't leak existence)
}

// Plus: CreateHost_WithTags, ListHosts_FiltersByGroup, UpdateHost_PatchMode,
//       DeleteHost_AsOfficer_Forbidden.
```

Full test bodies follow the pattern of `pkg/server/handlers_auth_test.go` in the existing codebase — use it as a reference for the auth-context fixture and JSON roundtripping.

- [ ] **Step 2: Implement handlers**

`pkg/server/inventory/handlers.go`:

```go
package inventory

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type Handlers struct {
	Store Store
	// Audit is injected from the outer server (pkg/server/audit.go).
	Audit AuditRecorder
}

type AuditRecorder interface {
	Record(r *http.Request, event, subject string, fields map[string]any)
}

func (h *Handlers) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	orgID := orgIDFromContext(r.Context())   // from pkg/server middleware
	userID := userIDFromContext(r.Context()) // ditto

	g := Group{
		ID:          uuid.Must(uuid.NewV7()),
		OrgID:       orgID,
		Name:        body.Name,
		Description: body.Description,
		CreatedBy:   userID,
	}
	created, err := h.Store.CreateGroup(r.Context(), g)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Audit.Record(r, "inventory.group.created", created.ID.String(), map[string]any{"name": created.Name})
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handlers) ListGroups(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	groups, err := h.Store.ListGroups(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

func (h *Handlers) GetGroup(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	g, err := h.Store.GetGroup(r.Context(), orgID, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// UpdateGroup, DeleteGroup follow the same pattern.
// CreateHost, ListHosts, GetHost, UpdateHost, DeleteHost also follow — see Step 3.

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
```

- [ ] **Step 3: Implement remaining handlers (UpdateGroup, DeleteGroup, CreateHost, ListHosts, GetHost, UpdateHost, DeleteHost)**

Each follows the same pattern: decode body → call store with `orgID` from context → record audit event → return JSON. Full code is ~150 more lines — mirror the Group pattern above for each endpoint.

- [ ] **Step 4: Implement routes**

`pkg/server/inventory/routes.go`:

```go
package inventory

import (
	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/server"
)

// MountRoutes attaches inventory endpoints under the given prefix.
// Call sites: pkg/server/server.go where chi.Router is built.
func MountRoutes(r chi.Router, h *Handlers) {
	// Reading is allowed for any authenticated user (officer+).
	r.Get("/groups", h.ListGroups)
	r.Get("/groups/{id}", h.GetGroup)
	r.Get("/hosts", h.ListHosts)
	r.Get("/hosts/{id}", h.GetHost)

	// Mutations require engineer+.
	r.Group(func(r chi.Router) {
		r.Use(server.RequireRole(server.RoleEngineer))
		r.Post("/groups", h.CreateGroup)
		r.Put("/groups/{id}", h.UpdateGroup)
		r.Delete("/groups/{id}", h.DeleteGroup)
		r.Post("/hosts", h.CreateHost)
		r.Put("/hosts/{id}", h.UpdateHost)
		r.Delete("/hosts/{id}", h.DeleteHost)
	})
}
```

- [ ] **Step 5: Run handler tests**

```bash
go test ./pkg/server/inventory/
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/server/inventory/handlers.go pkg/server/inventory/handlers_test.go pkg/server/inventory/routes.go
git commit -m "feat(inventory): HTTP handlers + /api/v1/manage/* routes with RBAC"
```

---

### Task 8: Mount inventory routes + two-surface UI routing

**Files:**
- Modify: `pkg/server/server.go`
- Modify: `pkg/server/handlers.go` (root redirect)

- [ ] **Step 1: Inspect the current router setup**

Open `pkg/server/server.go`. Find where `chi.NewRouter()` is built and where existing API routes mount. Note the auth middleware call site — inventory routes must sit behind it.

- [ ] **Step 2: Wire the inventory handlers**

Add to `pkg/server/server.go` where routes are registered:

```go
// Inventory context — Onboarding Phase 1.
invStore := inventory.NewPostgresStore(srv.pool)
invHandlers := &inventory.Handlers{Store: invStore, Audit: srv.audit}
r.Route("/api/v1/manage", func(r chi.Router) {
    r.Use(srv.authMiddleware) // reuse existing JWT middleware from multi-tenant
    inventory.MountRoutes(r, invHandlers)
})
```

Import `"github.com/amiryahaya/triton/pkg/server/inventory"`.

- [ ] **Step 3: Surface routing for UIs**

Add:

```go
// Two-surface UI routing per Onboarding spec §3.
r.Handle("/manage/*", http.StripPrefix("/manage/", http.FileServer(http.FS(manageUIFS))))
r.Handle("/reports/*", http.StripPrefix("/reports/", http.FileServer(http.FS(reportsUIFS))))
r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    // Role-based root redirect.
    claims := claimsFromContext(r.Context())
    if claims != nil && claims.Role == RoleOfficer {
        http.Redirect(w, r, "/reports/", http.StatusSeeOther)
        return
    }
    http.Redirect(w, r, "/manage/", http.StatusSeeOther)
})
```

`manageUIFS` and `reportsUIFS` are `//go:embed`'d. See Task 9.

- [ ] **Step 4: Build**

```bash
go build ./pkg/server/...
```

Expected: success. If `reportsUIFS` doesn't exist yet (existing code uses a single `uiFS`), rename the existing one to `reportsUIFS` and update references — `/reports/*` is now the canonical mount for today's dashboard.

- [ ] **Step 5: Commit**

```bash
git add pkg/server/server.go pkg/server/handlers.go
git commit -m "feat(server): mount /api/v1/manage/* and split UI surfaces"
```

---

### Task 9: Management UI skeleton

**Files:**
- Create: `pkg/server/ui/manage/index.html`
- Create: `pkg/server/ui/manage/app.js`
- Create: `pkg/server/ui/manage/style.css`
- Modify: `pkg/server/server.go` — add `//go:embed ui/manage` for `manageUIFS`

- [ ] **Step 1: HTML shell**

`pkg/server/ui/manage/index.html`:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Triton — Management</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <nav class="sidebar">
    <div class="brand">Triton</div>
    <a href="#/dashboard" class="nav-link">Dashboard</a>
    <a href="#/groups" class="nav-link">Groups</a>
    <a href="#/hosts" class="nav-link">Hosts</a>
    <a href="/reports/" class="nav-link">Reports ↗</a>
  </nav>
  <main id="app"></main>
  <script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 2: JS router + views**

`pkg/server/ui/manage/app.js`:

```javascript
// Minimal hash router. Matches the pattern used in pkg/server/ui/dist/app.js.

const routes = {
  '/dashboard': renderDashboard,
  '/groups': renderGroups,
  '/hosts': renderHosts,
};

window.addEventListener('hashchange', route);
window.addEventListener('DOMContentLoaded', route);

function route() {
  const path = window.location.hash.replace('#', '') || '/dashboard';
  const h = routes[path] || routes['/dashboard'];
  h(document.getElementById('app'));
}

async function renderDashboard(el) {
  el.innerHTML = '<h1>Dashboard</h1><p>Welcome. Add hosts to get started.</p>';
}

async function renderGroups(el) {
  el.innerHTML = '<h1>Groups</h1><div id="list">loading…</div><form id="newgrp"><input name="name" placeholder="Group name"><button>Create</button></form>';
  const list = el.querySelector('#list');
  const resp = await fetch('/api/v1/manage/groups');
  const groups = await resp.json();
  list.innerHTML = groups.map(g => `<div>${g.name}</div>`).join('') || '<em>none yet</em>';
  el.querySelector('#newgrp').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = e.target.name.value;
    await fetch('/api/v1/manage/groups', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name}),
    });
    route();
  });
}

async function renderHosts(el) {
  el.innerHTML = '<h1>Hosts</h1><div id="list">loading…</div>';
  const list = el.querySelector('#list');
  const resp = await fetch('/api/v1/manage/hosts');
  const hosts = await resp.json();
  list.innerHTML = hosts.map(h => `<div>${h.hostname || h.id} — ${h.mode}</div>`).join('') || '<em>none yet</em>';
}
```

- [ ] **Step 3: Minimal CSS**

`pkg/server/ui/manage/style.css`:

```css
body { margin: 0; font-family: system-ui, sans-serif; display: flex; }
.sidebar { width: 220px; min-height: 100vh; background: #1a1a2e; color: #fff; padding: 1rem; }
.brand { font-weight: 700; margin-bottom: 2rem; }
.nav-link { display: block; color: #ccc; text-decoration: none; padding: 0.5rem 0; }
.nav-link:hover { color: #fff; }
main { flex: 1; padding: 2rem; background: #f5f5f7; min-height: 100vh; }
form { margin-top: 1rem; }
input, button { padding: 0.5rem; margin-right: 0.5rem; }
```

- [ ] **Step 4: Embed into binary**

Edit `pkg/server/server.go`:

```go
//go:embed ui/manage
var manageUIFS embed.FS
```

(The existing `ui/dist` embed stays, renamed to `reportsUIFS` per Task 8.)

- [ ] **Step 5: Run server locally, smoke-test UI**

```bash
make run
# Log in via /api/v1/auth/login as an Owner
# Navigate to http://localhost:8080/manage/
# Create a group, verify it appears
```

Expected: UI renders, POST succeeds, GET lists the new group.

- [ ] **Step 6: Commit**

```bash
git add pkg/server/ui/manage/ pkg/server/server.go
git commit -m "feat(server): management UI surface under /manage/"
```

---

### Task 10: Audit log extension for inventory events

**Files:**
- Modify: `pkg/server/audit.go` (if existing taxonomy doesn't cover inventory)

- [ ] **Step 1: Check existing audit events**

```bash
grep -rn "Record\|AuditEvent" pkg/server/audit.go pkg/server/handlers_*.go | head -30
```

If the existing audit system already accepts arbitrary event strings (like `"inventory.group.created"`), no code change is needed — the handlers in Task 7 already emit correct events.

If it uses a closed enum, extend with:

```go
const (
    // ... existing constants ...
    EventInventoryGroupCreated = "inventory.group.created"
    EventInventoryGroupUpdated = "inventory.group.updated"
    EventInventoryGroupDeleted = "inventory.group.deleted"
    EventInventoryHostCreated  = "inventory.host.created"
    EventInventoryHostUpdated  = "inventory.host.updated"
    EventInventoryHostDeleted  = "inventory.host.deleted"
)
```

- [ ] **Step 2: Smoke-test audit writes**

```sql
-- After creating a group via the UI:
SELECT event, subject, created_at FROM audit.events ORDER BY created_at DESC LIMIT 5;
```

Expected: row with `event = 'inventory.group.created'`.

- [ ] **Step 3: Commit if any audit changes**

```bash
git add pkg/server/audit.go
git commit -m "feat(audit): inventory event taxonomy for groups and hosts"
```

(Skip if existing audit system already supported free-form event strings.)

---

### Task 11: End-to-end verification

- [ ] **Step 1: Lint + unit tests**

```bash
make fmt
make lint
make test
```

Expected: all green.

- [ ] **Step 2: Integration tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  make test-integration
```

Expected: PASS including new inventory integration tests.

- [ ] **Step 3: Manual end-to-end smoke**

```
1. Start postgres:    make db-up
2. Start server:      make run
3. In browser:        http://localhost:8080/manage/
4. Sign up + log in as an Owner
5. Create a group "prod-web"
6. Create a host "app-01" in "prod-web" with os=linux, mode=agentless
7. Verify host appears in /manage/#/hosts
8. Sign in as an Officer (create a second user via /api/v1/auth/invite first)
9. Attempt POST /api/v1/manage/groups — expect 403
10. Verify GET still returns 200
```

Each step must succeed for Phase 1 to be considered complete.

- [ ] **Step 4: Commit any documentation updates**

Update `docs/DEPLOYMENT_GUIDE.md` with a new section on the management UI surface and the RBAC role set.

```bash
git add docs/DEPLOYMENT_GUIDE.md
git commit -m "docs: onboarding phase 1 — management UI + RBAC roles"
```

---

### Task 12: Code review

- [ ] **Step 1: Push branch, open PR, dispatch code-reviewer**

```bash
git push -u origin feat/onboarding-phase-1-portal-foundation
gh pr create --title "feat: onboarding phase 1 — portal foundation" \
  --body "Implements Phase 1 of docs/plans/2026-04-14-onboarding-phase-index.md. Adds inventory context (groups/hosts/tags), RBAC with officer role, /manage UI surface, and /api/v1/manage/* API."
```

Then use `superpowers:requesting-code-review` per the skill's standard flow.

- [ ] **Step 2: Address review feedback**

Critical + Important issues must be fixed before merge. Push additional commits.

- [ ] **Step 3: Merge**

After CI passes, merge PR to main. Phase 1 complete.

---

## Self-Review Checklist

**Spec coverage:**
- §3 architecture (two-surface portal): covered by Task 8 (route mounting) + Task 9 (management UI).
- §4 Inventory context: covered by Tasks 3-7 (schema, types, store, handlers).
- §5 RBAC (3 roles): covered by Task 1 (role extension) + Task 2 (middleware) + Task 7 (per-endpoint gates).
- §6 journey step 3 (groups/hosts CRUD): covered. CSV import + discovery deferred to Phase 3.
- §8 data model — groups/hosts/tags: covered by Task 3. Credentials/engines/jobs/fleet tables deferred to later phases (correct per phasing).

**Placeholder scan:** one intentional `V0XX` migration-number placeholder — must be resolved at execution time per Task 3 Step 1. All other steps have exact content.

**Type consistency:** `Group`, `Host`, `Tag`, `HostFilters`, `HostPatch` names used identically across types.go, store.go, postgres.go, handlers.go. `RoleOfficer`, `RoleEngineer`, `RoleOwner` consistent across Task 1 migration, Task 2 middleware, Task 7 routes.

**Known dependencies unresolved at write time:**
- Exact name of the multi-tenant claims-context helper (`claimsFromContext` assumed).
- Exact name of existing JWT middleware on the chi router (`srv.authMiddleware` assumed).
- Existing migration-file numbering convention (`V0XX` placeholder).

These are flagged in the relevant task steps and must be confirmed as Step 1 of their task before writing the code.
