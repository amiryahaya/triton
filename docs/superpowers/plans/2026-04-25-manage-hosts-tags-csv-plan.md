# Manage Portal — Hosts Tags & CSV Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-zone host grouping with a flexible multi-tag system and add CSV bulk import to the Manage Portal.

**Architecture:** A new `pkg/manageserver/tags/` package owns tag CRUD; a `manage_host_tags` junction table replaces `zone_id` on hosts. The migration (v9) auto-converts existing zone records to tags, drops `zone_id` from `manage_hosts` and `manage_scan_jobs`, and removes `manage_zones` and `manage_zone_memberships`. The frontend gains a Tags page, tag chips on host rows, a tag multi-select on the host form, and a CSV tab in the bulk import modal.

**Tech Stack:** Go 1.25, pgx/v5, Chi router, Vue 3 + Composition API, Pinia, TypeScript, Vite, testify

---

## File Map

**Created:**
- `pkg/manageserver/tags/types.go` — Tag struct + errors
- `pkg/manageserver/tags/store.go` — Store interface
- `pkg/manageserver/tags/postgres.go` — PostgresStore
- `pkg/manageserver/tags/handlers_admin.go` — HTTP handlers
- `pkg/manageserver/tags/routes.go` — MountAdminRoutes
- `pkg/manageserver/tags/postgres_test.go` — integration tests
- `pkg/manageserver/tags/handlers_admin_test.go` — handler unit tests
- `web/apps/manage-portal/src/views/Tags.vue` — Tags management page
- `web/apps/manage-portal/src/stores/tags.ts` — Pinia tags store

**Modified:**
- `pkg/managestore/migrations.go` — add migration v9
- `pkg/manageserver/hosts/types.go` — add Tags field, remove ZoneID
- `pkg/manageserver/hosts/store.go` — add SetTags/ResolveTagNames/ListByTag/CountByTag, remove ListByZone/CountByZone
- `pkg/manageserver/hosts/postgres.go` — update all SQL, add new store methods
- `pkg/manageserver/hosts/handlers_admin.go` — remove zone_id, add tag_ids/tags, add PUT /{id}/tags
- `pkg/manageserver/hosts/routes.go` — add PUT /{id}/tags route
- `pkg/manageserver/hosts/postgres_test.go` — update for tags
- `pkg/manageserver/hosts/handlers_admin_test.go` — update for tags
- `pkg/manageserver/scanjobs/types.go` — ZoneID→removed, ZoneIDs→TagIDs in EnqueueReq
- `pkg/manageserver/scanjobs/postgres.go` — update Enqueue SQL, jobSelectCols
- `pkg/manageserver/server.go` — add tags store/handlers, remove zones
- `web/packages/api-client/src/manageServer.types.ts` — add Tag, update Host/Zone removal
- `web/packages/api-client/src/manageServer.ts` — add tag methods, remove zone methods, update hosts/scanjobs
- `web/apps/manage-portal/src/stores/hosts.ts` — update filter (zoneID→tagID), update types
- `web/apps/manage-portal/src/stores/zones.ts` — delete file
- `web/apps/manage-portal/src/views/Hosts.vue` — tag chips, tag filter, CSV tab in bulk modal
- `web/apps/manage-portal/src/views/Zones.vue` — delete file
- `web/apps/manage-portal/src/views/modals/HostForm.vue` — zone→tag multi-select
- `web/apps/manage-portal/src/views/modals/HostBulkForm.vue` — add CSV tab
- `web/apps/manage-portal/src/views/ScanJobs.vue` — zone→tag column, tags store
- `web/apps/manage-portal/src/nav.ts` — Zones→Tags entry
- `web/apps/manage-portal/src/router/index.ts` — /inventory/zones→/inventory/tags

---

## Task 1: DB Migration v9

**Files:**
- Modify: `pkg/managestore/migrations.go`

- [ ] **Step 1: Add migration v9 to the migrations slice**

Open `pkg/managestore/migrations.go`. The `migrations` slice currently has 8 entries (v1–v8). Append a ninth entry:

```go
// Version 9: Replace zones with tags.
//
// Creates manage_tags (id, name, color) and manage_host_tags junction
// table. Existing zone names are migrated to tags with default color
// #6366F1 and host memberships are carried over via manage_host_tags.
// zone_id is then dropped from manage_hosts; manage_zone_memberships
// and manage_zones are dropped. manage_scan_jobs.zone_id FK is dropped
// before manage_zones is removed, and the column itself is also dropped
// since the job no longer records which targeting group caused it.
`CREATE TABLE manage_tags (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL UNIQUE,
    color      TEXT        NOT NULL DEFAULT '#6366F1',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE manage_host_tags (
    host_id UUID NOT NULL REFERENCES manage_hosts(id) ON DELETE CASCADE,
    tag_id  UUID NOT NULL REFERENCES manage_tags(id)  ON DELETE CASCADE,
    PRIMARY KEY (host_id, tag_id)
);

INSERT INTO manage_tags (name, color)
SELECT name, '#6366F1' FROM manage_zones
ON CONFLICT (name) DO NOTHING;

INSERT INTO manage_host_tags (host_id, tag_id)
SELECT h.id, t.id
FROM manage_hosts h
JOIN manage_zones z ON z.id = h.zone_id
JOIN manage_tags  t ON t.name = z.name
WHERE h.zone_id IS NOT NULL
ON CONFLICT DO NOTHING;

ALTER TABLE manage_scan_jobs DROP CONSTRAINT IF EXISTS manage_scan_jobs_zone_id_fkey;
ALTER TABLE manage_scan_jobs DROP COLUMN IF EXISTS zone_id;

DROP INDEX IF EXISTS idx_manage_hosts_zone;
ALTER TABLE manage_hosts DROP COLUMN zone_id;

DROP TABLE IF EXISTS manage_zone_memberships;
DROP TABLE manage_zones;`,
```

- [ ] **Step 2: Verify migration compiles**

```bash
go build ./pkg/managestore/...
```

Expected: no errors.

- [ ] **Step 3: Run migration against the dev DB to verify it applies cleanly**

```bash
TRITON_MANAGE_DB_URL="postgres://triton:triton@localhost:5432/triton_manage_dev?sslmode=disable" \
  go run ./cmd/manageserver/main.go &
sleep 3 && kill %1
```

Expected: server starts (applies migration) then is killed — no migration errors in output.

- [ ] **Step 4: Commit**

```bash
git add pkg/managestore/migrations.go
git commit -m "feat(managestore): migration v9 — replace zones with tags"
```

---

## Task 2: Tags Package — Types, Store Interface, Errors

**Files:**
- Create: `pkg/manageserver/tags/types.go`
- Create: `pkg/manageserver/tags/store.go`

- [ ] **Step 1: Write the failing test for Tag CRUD (store interface)**

Create `pkg/manageserver/tags/postgres_test.go`:

```go
//go:build integration

package tags_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
	"github.com/amiryahaya/triton/pkg/managestore"
)

var testSchemaSeq atomic.Int64

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_tags_%d", testSchemaSeq.Add(1))
	ctx := context.Background()
	setup, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	_, _ = setup.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	_, err = setup.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	setup.Close()

	cfg, err := pgxpool.ParseConfig(dbURL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, managestore.Migrate(ctx, pool))

	t.Cleanup(func() {
		pool.Close()
		c, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	return pool
}

func TestTags_CreateListGetUpdateDelete(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	ctx := context.Background()

	// Create
	tag, err := s.Create(ctx, tags.Tag{Name: "production", Color: "#EF4444"})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, tag.ID)
	assert.Equal(t, "production", tag.Name)
	assert.Equal(t, "#EF4444", tag.Color)

	// List — includes HostCount
	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, tag.ID, list[0].ID)
	assert.Equal(t, 0, list[0].HostCount)

	// Get
	got, err := s.Get(ctx, tag.ID)
	require.NoError(t, err)
	assert.Equal(t, tag.ID, got.ID)

	// Update
	updated, err := s.Update(ctx, tags.Tag{ID: tag.ID, Name: "prod", Color: "#22C55E"})
	require.NoError(t, err)
	assert.Equal(t, "prod", updated.Name)
	assert.Equal(t, "#22C55E", updated.Color)

	// Delete
	require.NoError(t, s.Delete(ctx, tag.ID))
	_, err = s.Get(ctx, tag.ID)
	assert.ErrorIs(t, err, tags.ErrNotFound)
}

func TestTags_DuplicateName_Conflict(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	ctx := context.Background()

	_, err := s.Create(ctx, tags.Tag{Name: "alpha", Color: "#3B82F6"})
	require.NoError(t, err)

	_, err = s.Create(ctx, tags.Tag{Name: "alpha", Color: "#EF4444"})
	assert.ErrorIs(t, err, tags.ErrConflict)
}

func TestTags_GetNonExistent_NotFound(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	_, err := s.Get(context.Background(), uuid.New())
	assert.ErrorIs(t, err, tags.ErrNotFound)
}

func TestTags_Delete_NonExistent_NotFound(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	err := s.Delete(context.Background(), uuid.New())
	assert.ErrorIs(t, err, tags.ErrNotFound)
}

func TestTags_List_HostCount(t *testing.T) {
	pool := newTestPool(t)
	s := tags.NewPostgresStore(pool)
	ctx := context.Background()

	tag, err := s.Create(ctx, tags.Tag{Name: "linux", Color: "#6366F1"})
	require.NoError(t, err)

	// Insert a host and assign the tag directly via SQL
	var hostID uuid.UUID
	err = pool.QueryRow(ctx,
		`INSERT INTO manage_hosts (hostname, os) VALUES ('h1', 'linux') RETURNING id`,
	).Scan(&hostID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO manage_host_tags (host_id, tag_id) VALUES ($1, $2)`,
		hostID, tag.ID,
	)
	require.NoError(t, err)

	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, 1, list[0].HostCount)
}
```

- [ ] **Step 2: Run test — expect compile failure**

```bash
go test -tags integration -run TestTags_ ./pkg/manageserver/tags/ 2>&1 | head -20
```

Expected: `cannot find package "github.com/amiryahaya/triton/pkg/manageserver/tags"`

- [ ] **Step 3: Create `pkg/manageserver/tags/types.go`**

```go
package tags

import "time"
import "github.com/google/uuid"

// Tag is a coloured label that can be assigned to one or more hosts.
type Tag struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Color     string    `json:"color"`
	HostCount int       `json:"host_count,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
```

- [ ] **Step 4: Create `pkg/manageserver/tags/store.go`**

```go
package tags

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

var ErrNotFound = errors.New("tags: not found")
var ErrConflict = errors.New("tags: conflict")

type Store interface {
	Create(ctx context.Context, t Tag) (Tag, error)
	Get(ctx context.Context, id uuid.UUID) (Tag, error)
	List(ctx context.Context) ([]Tag, error)
	Update(ctx context.Context, t Tag) (Tag, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
```

- [ ] **Step 5: Run tests — expect fail (no postgres.go yet)**

```bash
go test -tags integration -run TestTags_ ./pkg/manageserver/tags/ 2>&1 | head -10
```

Expected: compile error — `NewPostgresStore` undefined.

- [ ] **Step 6: Commit stubs**

```bash
git add pkg/manageserver/tags/
git commit -m "feat(tags): types + store interface"
```

---

## Task 3: Tags PostgresStore Implementation

**Files:**
- Create: `pkg/manageserver/tags/postgres.go`

- [ ] **Step 1: Create `pkg/manageserver/tags/postgres.go`**

```go
package tags

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

func isUniqueViolation(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "23505"
}

func (s *PostgresStore) Create(ctx context.Context, t Tag) (Tag, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO manage_tags (name, color) VALUES ($1, $2)
		 RETURNING id, created_at`,
		t.Name, t.Color,
	)
	if err := row.Scan(&t.ID, &t.CreatedAt); err != nil {
		if isUniqueViolation(err) {
			return Tag{}, fmt.Errorf("%w: %q", ErrConflict, t.Name)
		}
		return Tag{}, fmt.Errorf("create tag: %w", err)
	}
	return t, nil
}

func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Tag, error) {
	var t Tag
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, color, created_at FROM manage_tags WHERE id = $1`, id,
	).Scan(&t.ID, &t.Name, &t.Color, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tag{}, ErrNotFound
	}
	if err != nil {
		return Tag{}, fmt.Errorf("get tag: %w", err)
	}
	return t, nil
}

func (s *PostgresStore) List(ctx context.Context) ([]Tag, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT t.id, t.name, t.color, t.created_at,
		        COUNT(ht.host_id)::int AS host_count
		 FROM manage_tags t
		 LEFT JOIN manage_host_tags ht ON ht.tag_id = t.id
		 GROUP BY t.id
		 ORDER BY t.name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}
	defer rows.Close()
	out := []Tag{}
	for rows.Next() {
		var t Tag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.CreatedAt, &t.HostCount); err != nil {
			return nil, fmt.Errorf("scan tag: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Update(ctx context.Context, t Tag) (Tag, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE manage_tags SET name = $1, color = $2 WHERE id = $3
		 RETURNING id, name, color, created_at`,
		t.Name, t.Color, t.ID,
	)
	var out Tag
	if err := row.Scan(&out.ID, &out.Name, &out.Color, &out.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Tag{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return Tag{}, fmt.Errorf("%w: %q", ErrConflict, t.Name)
		}
		return Tag{}, fmt.Errorf("update tag: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM manage_tags WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete tag: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
```

- [ ] **Step 2: Run integration tests**

```bash
go test -tags integration -v -run TestTags_ ./pkg/manageserver/tags/
```

Expected: all 5 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add pkg/manageserver/tags/postgres.go pkg/manageserver/tags/postgres_test.go
git commit -m "feat(tags): PostgresStore implementation + integration tests"
```

---

## Task 4: Tags HTTP Handlers + Routes

**Files:**
- Create: `pkg/manageserver/tags/handlers_admin.go`
- Create: `pkg/manageserver/tags/routes.go`
- Create: `pkg/manageserver/tags/handlers_admin_test.go`

- [ ] **Step 1: Write handler tests**

Create `pkg/manageserver/tags/handlers_admin_test.go`:

```go
package tags_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
)

type fakeStore struct {
	mu      sync.Mutex
	items   map[uuid.UUID]tags.Tag
	listErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{items: map[uuid.UUID]tags.Tag{}}
}

func (f *fakeStore) Create(_ context.Context, t tags.Tag) (tags.Tag, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	for _, existing := range f.items {
		if existing.Name == t.Name {
			return tags.Tag{}, tags.ErrConflict
		}
	}
	t.ID = uuid.Must(uuid.NewV7())
	f.items[t.ID] = t
	return t, nil
}
func (f *fakeStore) Get(_ context.Context, id uuid.UUID) (tags.Tag, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	t, ok := f.items[id]
	if !ok { return tags.Tag{}, tags.ErrNotFound }
	return t, nil
}
func (f *fakeStore) List(_ context.Context) ([]tags.Tag, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	if f.listErr != nil { return nil, f.listErr }
	out := make([]tags.Tag, 0, len(f.items))
	for _, t := range f.items { out = append(out, t) }
	return out, nil
}
func (f *fakeStore) Update(_ context.Context, t tags.Tag) (tags.Tag, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	if _, ok := f.items[t.ID]; !ok { return tags.Tag{}, tags.ErrNotFound }
	f.items[t.ID] = t
	return t, nil
}
func (f *fakeStore) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock(); defer f.mu.Unlock()
	if _, ok := f.items[id]; !ok { return tags.ErrNotFound }
	delete(f.items, id)
	return nil
}

func mountTest(s tags.Store) *chi.Mux {
	r := chi.NewRouter()
	tags.MountAdminRoutes(r, tags.NewAdminHandlers(s))
	return r
}

func TestHandlers_List(t *testing.T) {
	store := newFakeStore()
	_, _ = store.Create(context.Background(), tags.Tag{Name: "alpha", Color: "#EF4444"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	var out []tags.Tag
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.Len(t, out, 1)
}

func TestHandlers_Create(t *testing.T) {
	store := newFakeStore()
	body := `{"name":"production","color":"#EF4444"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestHandlers_Create_InvalidColor(t *testing.T) {
	store := newFakeStore()
	body := `{"name":"x","color":"not-a-color"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Create_MissingName(t *testing.T) {
	store := newFakeStore()
	body := `{"color":"#EF4444"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlers_Create_Conflict(t *testing.T) {
	store := newFakeStore()
	_, _ = store.Create(context.Background(), tags.Tag{Name: "dup", Color: "#EF4444"})
	body := `{"name":"dup","color":"#22C55E"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestHandlers_Update(t *testing.T) {
	store := newFakeStore()
	tag, _ := store.Create(context.Background(), tags.Tag{Name: "old", Color: "#EF4444"})
	body := `{"name":"new","color":"#22C55E"}`
	r := httptest.NewRequest(http.MethodPatch, "/"+tag.ID.String(), bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandlers_Delete(t *testing.T) {
	store := newFakeStore()
	tag, _ := store.Create(context.Background(), tags.Tag{Name: "gone", Color: "#EF4444"})
	r := httptest.NewRequest(http.MethodDelete, "/"+tag.ID.String(), nil)
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestHandlers_Delete_NotFound(t *testing.T) {
	store := newFakeStore()
	r := httptest.NewRequest(http.MethodDelete, "/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandlers_List_StoreError(t *testing.T) {
	store := newFakeStore()
	store.listErr = errors.New("db down")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test -run TestHandlers_ ./pkg/manageserver/tags/ 2>&1 | head -10
```

Expected: compile error — `NewAdminHandlers`, `MountAdminRoutes` undefined.

- [ ] **Step 3: Create `pkg/manageserver/tags/handlers_admin.go`**

```go
package tags

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
)

var hexColorRE = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

type AdminHandlers struct {
	Store Store
}

func NewAdminHandlers(s Store) *AdminHandlers {
	return &AdminHandlers{Store: s}
}

type tagRequestBody struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

func (b tagRequestBody) validate() error {
	if strings.TrimSpace(b.Name) == "" {
		return errors.New("name is required")
	}
	if !hexColorRE.MatchString(b.Color) {
		return errors.New("color must be a 6-digit hex color (e.g. #3B82F6)")
	}
	return nil
}

func (h *AdminHandlers) List(w http.ResponseWriter, r *http.Request) {
	list, err := h.Store.List(r.Context())
	if err != nil {
		internalErr(w, r, err, "list tags")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *AdminHandlers) Create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)
	var body tagRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := body.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	tag, err := h.Store.Create(r.Context(), Tag{
		Name:  strings.TrimSpace(body.Name),
		Color: body.Color,
	})
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "tag name already exists")
		return
	}
	if err != nil {
		internalErr(w, r, err, "create tag")
		return
	}
	writeJSON(w, http.StatusCreated, tag)
}

func (h *AdminHandlers) Update(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tag id")
		return
	}
	var body tagRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := body.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	tag, err := h.Store.Update(r.Context(), Tag{
		ID:    id,
		Name:  strings.TrimSpace(body.Name),
		Color: body.Color,
	})
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "tag not found")
		return
	}
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, "tag name already exists")
		return
	}
	if err != nil {
		internalErr(w, r, err, "update tag")
		return
	}
	writeJSON(w, http.StatusOK, tag)
}

func (h *AdminHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tag id")
		return
	}
	if err := h.Store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "tag not found")
			return
		}
		internalErr(w, r, err, "delete tag")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
	log.Printf("manageserver/tags: %s: %s %s: %v", op, r.Method, r.URL.Path, err)
	writeErr(w, http.StatusInternalServerError, "internal server error")
}
```

- [ ] **Step 4: Create `pkg/manageserver/tags/routes.go`**

```go
package tags

import "github.com/go-chi/chi/v5"

func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Patch("/{id}", h.Update)
	r.Delete("/{id}", h.Delete)
}
```

- [ ] **Step 5: Run handler tests**

```bash
go test -v -run TestHandlers_ ./pkg/manageserver/tags/
```

Expected: all 8 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/manageserver/tags/
git commit -m "feat(tags): HTTP handlers + routes"
```

---

## Task 5: Wire Tags into Server + Remove Zones

**Files:**
- Modify: `pkg/manageserver/server.go`

- [ ] **Step 1: Add tags import and fields to Server struct**

In `pkg/manageserver/server.go`, add the `tags` import alongside the existing package imports:

```go
"github.com/amiryahaya/triton/pkg/manageserver/tags"
```

In the `Server` struct (near line 74 where `zonesAdmin` is declared), replace:
```go
zonesAdmin *zones.AdminHandlers
```
with:
```go
tagsAdmin *tags.AdminHandlers
```

- [ ] **Step 2: Remove zones store construction, add tags**

Find the `NewServer` body (around line 152–178). Replace the zones store construction:
```go
zonesAdmin: zones.NewAdminHandlers(zones.NewPostgresStore(pool)),
```
with:
```go
tagsAdmin: tags.NewAdminHandlers(tags.NewPostgresStore(pool)),
```

Remove the `zones` import from the import block.

- [ ] **Step 3: Update route registration**

In `buildRouter` (around line 284), replace:
```go
r.Route("/zones", func(r chi.Router) { zones.MountAdminRoutes(r, s.zonesAdmin) })
```
with:
```go
r.Route("/tags", func(r chi.Router) { tags.MountAdminRoutes(r, s.tagsAdmin) })
```

- [ ] **Step 4: Verify build**

```bash
go build ./pkg/manageserver/...
```

Expected: no errors. (The zones package still exists but is no longer imported. scanjobs still references zone_id — it will fail until Task 7.)

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/server.go
git commit -m "feat(manageserver): wire tags routes, remove zones from server"
```

---

## Task 6: Update Hosts Package — Types + Store Interface

**Files:**
- Modify: `pkg/manageserver/hosts/types.go`
- Modify: `pkg/manageserver/hosts/store.go`

- [ ] **Step 1: Update `pkg/manageserver/hosts/types.go`**

Replace the entire file content:

```go
package hosts

import (
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
)

// Host is a single scan target. IP is nullable INET in Postgres;
// modelled as string where empty = NULL. Tags is populated on reads
// (List/Get); it is not stored directly on the host row.
type Host struct {
	ID         uuid.UUID  `json:"id"`
	Hostname   string     `json:"hostname"`
	IP         string     `json:"ip,omitempty"`
	Tags       []tags.Tag `json:"tags"`
	OS         string     `json:"os"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
```

- [ ] **Step 2: Update `pkg/manageserver/hosts/store.go`**

Replace the Store interface with:

```go
package hosts

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

var ErrNotFound = errors.New("hosts: not found")
var ErrConflict = errors.New("hosts: conflict")
var ErrInvalidInput = errors.New("hosts: invalid input")

type Store interface {
	Create(ctx context.Context, h Host) (Host, error)
	Get(ctx context.Context, id uuid.UUID) (Host, error)
	List(ctx context.Context) ([]Host, error)
	Update(ctx context.Context, h Host) (Host, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Count(ctx context.Context) (int64, error)

	// SetTags replaces the full tag set for a host (idempotent).
	SetTags(ctx context.Context, hostID uuid.UUID, tagIDs []uuid.UUID) error

	// ResolveTagNames returns tag IDs for the given names, creating
	// tags with defaultColor for names that do not yet exist.
	ResolveTagNames(ctx context.Context, names []string, defaultColor string) ([]uuid.UUID, error)

	// ListByTag returns all hosts that have the given tag.
	ListByTag(ctx context.Context, tagID uuid.UUID) ([]Host, error)

	// CountByTag returns the number of hosts with the given tag.
	CountByTag(ctx context.Context, tagID uuid.UUID) (int64, error)

	// ListByHostnames returns hosts whose hostname is in names.
	ListByHostnames(ctx context.Context, names []string) ([]Host, error)

	// BulkCreate inserts a batch of hosts in a single transaction.
	BulkCreate(ctx context.Context, hosts []Host) ([]Host, error)
}
```

- [ ] **Step 3: Verify the types compile**

```bash
go build ./pkg/manageserver/hosts/...
```

Expected: compile errors from postgres.go (zone_id references) and handlers — that's expected; those are fixed in the next two tasks.

- [ ] **Step 4: Commit**

```bash
git add pkg/manageserver/hosts/types.go pkg/manageserver/hosts/store.go
git commit -m "feat(hosts): update types (add Tags, remove ZoneID) + store interface (add SetTags/ResolveTagNames/ListByTag)"
```

---

## Task 7: Update Hosts PostgresStore

**Files:**
- Modify: `pkg/manageserver/hosts/postgres.go`
- Modify: `pkg/manageserver/hosts/postgres_test.go`

- [ ] **Step 1: Write updated integration tests**

Replace the content of `pkg/manageserver/hosts/postgres_test.go` with:

```go
//go:build integration

package hosts_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/managestore"
)

var testSchemaSeq atomic.Int64

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}
	schema := fmt.Sprintf("test_hosts_%d", testSchemaSeq.Add(1))
	ctx := context.Background()
	setup, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	_, _ = setup.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	_, err = setup.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	setup.Close()

	cfg, err := pgxpool.ParseConfig(dbURL)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, managestore.Migrate(ctx, pool))

	t.Cleanup(func() {
		pool.Close()
		c, err := pgxpool.New(context.Background(), dbURL)
		if err != nil { return }
		defer c.Close()
		_, _ = c.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	return pool
}

func insertTag(t *testing.T, pool *pgxpool.Pool, name, color string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO manage_tags (name, color) VALUES ($1, $2) RETURNING id`, name, color,
	).Scan(&id)
	require.NoError(t, err)
	return id
}

func TestHosts_CreateListGetDelete(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()

	h, err := s.Create(ctx, hosts.Host{Hostname: "web-01", OS: "linux"})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, h.ID)
	assert.Empty(t, h.Tags)

	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "web-01", list[0].Hostname)

	got, err := s.Get(ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, h.ID, got.ID)

	require.NoError(t, s.Delete(ctx, h.ID))
	_, err = s.Get(ctx, h.ID)
	assert.ErrorIs(t, err, hosts.ErrNotFound)
}

func TestHosts_SetTags_AndListByTag(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()

	tagID := insertTag(t, pool, "production", "#EF4444")
	h, err := s.Create(ctx, hosts.Host{Hostname: "db-01", OS: "linux"})
	require.NoError(t, err)

	require.NoError(t, s.SetTags(ctx, h.ID, []uuid.UUID{tagID}))

	// List shows tag on host
	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list[0].Tags, 1)
	assert.Equal(t, "production", list[0].Tags[0].Name)

	// ListByTag
	tagged, err := s.ListByTag(ctx, tagID)
	require.NoError(t, err)
	require.Len(t, tagged, 1)
	assert.Equal(t, h.ID, tagged[0].ID)

	// CountByTag
	n, err := s.CountByTag(ctx, tagID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	// Replace tags (SetTags idempotent)
	require.NoError(t, s.SetTags(ctx, h.ID, []uuid.UUID{}))
	list, err = s.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list[0].Tags)
}

func TestHosts_ResolveTagNames_CreatesIfMissing(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()

	// "linux" doesn't exist yet
	ids, err := s.ResolveTagNames(ctx, []string{"linux", "prod"}, "#6366F1")
	require.NoError(t, err)
	assert.Len(t, ids, 2)

	// Calling again returns same IDs (idempotent)
	ids2, err := s.ResolveTagNames(ctx, []string{"linux"}, "#6366F1")
	require.NoError(t, err)
	assert.Equal(t, ids[0], ids2[0])
}

func TestHosts_UniqueHostname(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()
	_, _ = s.Create(ctx, hosts.Host{Hostname: "web-01", OS: "linux"})
	_, err := s.Create(ctx, hosts.Host{Hostname: "web-01", OS: "linux"})
	assert.ErrorIs(t, err, hosts.ErrConflict)
}

func TestHosts_BulkCreate(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()

	batch := []hosts.Host{
		{Hostname: "a", OS: "linux"},
		{Hostname: "b", IP: "10.0.0.2", OS: "linux"},
	}
	out, err := s.BulkCreate(ctx, batch)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.NotEqual(t, uuid.Nil, out[0].ID)
}

func TestHosts_BulkCreate_Conflict_RollsBack(t *testing.T) {
	pool := newTestPool(t)
	s := hosts.NewPostgresStore(pool)
	ctx := context.Background()
	_, _ = s.Create(ctx, hosts.Host{Hostname: "dup", OS: "linux"})
	_, err := s.BulkCreate(ctx, []hosts.Host{
		{Hostname: "ok", OS: "linux"},
		{Hostname: "dup", OS: "linux"},
	})
	assert.ErrorIs(t, err, hosts.ErrConflict)
	// "ok" should not have been created
	list, _ := s.List(ctx)
	for _, h := range list {
		assert.NotEqual(t, "ok", h.Hostname)
	}
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
go test -tags integration -run TestHosts_ ./pkg/manageserver/hosts/ 2>&1 | head -5
```

Expected: compile errors from postgres.go (zone_id still referenced, new methods missing).

- [ ] **Step 3: Rewrite `pkg/manageserver/hosts/postgres.go`**

Replace the entire file:

```go
package hosts

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

// hostSelectCols selects host columns only (no tags). Tags are loaded
// separately via loadTags and attached by the caller.
const hostSelectCols = `id, hostname, host(ip)::text, os, last_seen_at, created_at, updated_at`

func scanHost(row pgx.Row) (Host, error) {
	var h Host
	var ip *string
	if err := row.Scan(&h.ID, &h.Hostname, &ip, &h.OS, &h.LastSeenAt, &h.CreatedAt, &h.UpdatedAt); err != nil {
		return Host{}, err
	}
	if ip != nil {
		h.IP = *ip
	}
	h.Tags = []tags.Tag{}
	return h, nil
}

func ipArg(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}

func isUniqueViolation(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "23505"
}

func isInvalidTextRepresentation(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "22P02"
}

// loadTagsForHosts fetches all tags for the given host IDs in one query
// and returns a map from host ID → tag slice.
func (s *PostgresStore) loadTagsForHosts(ctx context.Context, hostIDs []uuid.UUID) (map[uuid.UUID][]tags.Tag, error) {
	if len(hostIDs) == 0 {
		return map[uuid.UUID][]tags.Tag{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT ht.host_id, t.id, t.name, t.color, t.created_at
		 FROM manage_host_tags ht
		 JOIN manage_tags t ON t.id = ht.tag_id
		 WHERE ht.host_id = ANY($1)
		 ORDER BY t.name`,
		hostIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("load tags for hosts: %w", err)
	}
	defer rows.Close()

	result := map[uuid.UUID][]tags.Tag{}
	for rows.Next() {
		var hostID uuid.UUID
		var tag tags.Tag
		if err := rows.Scan(&hostID, &tag.ID, &tag.Name, &tag.Color, &tag.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan host tag: %w", err)
		}
		result[hostID] = append(result[hostID], tag)
	}
	return result, rows.Err()
}

func (s *PostgresStore) Create(ctx context.Context, h Host) (Host, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO manage_hosts (hostname, ip, os, last_seen_at)
		 VALUES ($1, $2::inet, $3, $4)
		 RETURNING id, created_at, updated_at`,
		h.Hostname, ipArg(h.IP), h.OS, h.LastSeenAt,
	)
	if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return Host{}, fmt.Errorf("%w: hostname %q", ErrConflict, h.Hostname)
		}
		if isInvalidTextRepresentation(err) {
			return Host{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
		return Host{}, fmt.Errorf("create host: %w", err)
	}
	h.Tags = []tags.Tag{}
	return h, nil
}

func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Host, error) {
	h, err := scanHost(s.pool.QueryRow(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts WHERE id = $1`, id,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, fmt.Errorf("get host: %w", err)
	}
	tagMap, err := s.loadTagsForHosts(ctx, []uuid.UUID{h.ID})
	if err != nil {
		return Host{}, err
	}
	if t, ok := tagMap[h.ID]; ok {
		h.Tags = t
	}
	return h, nil
}

func (s *PostgresStore) List(ctx context.Context) ([]Host, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts ORDER BY hostname`,
	)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	var out []Host
	var ids []uuid.UUID
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
		ids = append(ids, h.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	tagMap, err := s.loadTagsForHosts(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if t, ok := tagMap[out[i].ID]; ok {
			out[i].Tags = t
		}
	}
	if out == nil {
		out = []Host{}
	}
	return out, nil
}

func (s *PostgresStore) Update(ctx context.Context, h Host) (Host, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE manage_hosts
		 SET hostname = $1, ip = $2::inet, os = $3, last_seen_at = $4, updated_at = NOW()
		 WHERE id = $5
		 RETURNING id, created_at, updated_at`,
		h.Hostname, ipArg(h.IP), h.OS, h.LastSeenAt, h.ID,
	)
	if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Host{}, ErrNotFound
		}
		if isUniqueViolation(err) {
			return Host{}, fmt.Errorf("%w: hostname %q", ErrConflict, h.Hostname)
		}
		if isInvalidTextRepresentation(err) {
			return Host{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
		return Host{}, fmt.Errorf("update host: %w", err)
	}
	tagMap, err := s.loadTagsForHosts(ctx, []uuid.UUID{h.ID})
	if err != nil {
		return Host{}, err
	}
	if t, ok := tagMap[h.ID]; ok {
		h.Tags = t
	} else {
		h.Tags = []tags.Tag{}
	}
	return h, nil
}

func (s *PostgresStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM manage_hosts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM manage_hosts`).Scan(&n)
	return n, err
}

func (s *PostgresStore) SetTags(ctx context.Context, hostID uuid.UUID, tagIDs []uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin set-tags tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM manage_host_tags WHERE host_id = $1`, hostID); err != nil {
		return fmt.Errorf("clear host tags: %w", err)
	}
	for _, tid := range tagIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO manage_host_tags (host_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			hostID, tid,
		); err != nil {
			return fmt.Errorf("insert host tag: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ResolveTagNames(ctx context.Context, names []string, defaultColor string) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(names))
	for _, name := range names {
		var id uuid.UUID
		err := s.pool.QueryRow(ctx,
			`INSERT INTO manage_tags (name, color) VALUES ($1, $2)
			 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
			 RETURNING id`,
			name, defaultColor,
		).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("resolve tag %q: %w", name, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *PostgresStore) ListByTag(ctx context.Context, tagID uuid.UUID) ([]Host, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts h
		 JOIN manage_host_tags ht ON ht.host_id = h.id
		 WHERE ht.tag_id = $1
		 ORDER BY h.hostname`,
		tagID,
	)
	if err != nil {
		return nil, fmt.Errorf("list hosts by tag: %w", err)
	}
	defer rows.Close()

	var out []Host
	var ids []uuid.UUID
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
		ids = append(ids, h.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	tagMap, err := s.loadTagsForHosts(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if t, ok := tagMap[out[i].ID]; ok {
			out[i].Tags = t
		}
	}
	if out == nil {
		out = []Host{}
	}
	return out, nil
}

func (s *PostgresStore) CountByTag(ctx context.Context, tagID uuid.UUID) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_host_tags WHERE tag_id = $1`, tagID,
	).Scan(&n)
	return n, err
}

func (s *PostgresStore) ListByHostnames(ctx context.Context, names []string) ([]Host, error) {
	if len(names) == 0 {
		return []Host{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+hostSelectCols+` FROM manage_hosts WHERE hostname = ANY($1) ORDER BY hostname`,
		names,
	)
	if err != nil {
		return nil, fmt.Errorf("list hosts by names: %w", err)
	}
	defer rows.Close()

	var out []Host
	var ids []uuid.UUID
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		out = append(out, h)
		ids = append(ids, h.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	tagMap, err := s.loadTagsForHosts(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if t, ok := tagMap[out[i].ID]; ok {
			out[i].Tags = t
		}
	}
	if out == nil {
		out = []Host{}
	}
	return out, nil
}

func (s *PostgresStore) BulkCreate(ctx context.Context, hosts []Host) ([]Host, error) {
	if len(hosts) == 0 {
		return []Host{}, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin bulk-create tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	out := make([]Host, len(hosts))
	for i := range hosts {
		src := &hosts[i]
		row := tx.QueryRow(ctx,
			`INSERT INTO manage_hosts (hostname, ip, os, last_seen_at)
			 VALUES ($1, $2::inet, $3, $4)
			 RETURNING id, created_at, updated_at`,
			src.Hostname, ipArg(src.IP), src.OS, src.LastSeenAt,
		)
		dst := *src
		if err := row.Scan(&dst.ID, &dst.CreatedAt, &dst.UpdatedAt); err != nil {
			if isUniqueViolation(err) {
				return nil, fmt.Errorf("%w: hostname %q (index %d)", ErrConflict, src.Hostname, i)
			}
			if isInvalidTextRepresentation(err) {
				return nil, fmt.Errorf("%w: index %d: %v", ErrInvalidInput, i, err)
			}
			return nil, fmt.Errorf("bulk create host %q (index %d): %w", src.Hostname, i, err)
		}
		dst.Tags = []tags.Tag{}
		out[i] = dst
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit bulk-create tx: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run integration tests**

```bash
go test -tags integration -v -run TestHosts_ ./pkg/manageserver/hosts/
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/hosts/postgres.go pkg/manageserver/hosts/postgres_test.go
git commit -m "feat(hosts): update postgres store — tags join, SetTags, ResolveTagNames, ListByTag"
```

---

## Task 8: Update Hosts Handlers + Routes

**Files:**
- Modify: `pkg/manageserver/hosts/handlers_admin.go`
- Modify: `pkg/manageserver/hosts/routes.go`
- Modify: `pkg/manageserver/hosts/handlers_admin_test.go`

- [ ] **Step 1: Update `pkg/manageserver/hosts/handlers_admin.go`**

Replace the `hostRequestBody` struct and `toHost()` method, and update `List`, `Create`, `BulkCreate`. Also add a `SetTags` handler.

Find and replace the `hostRequestBody` struct (around line 50):

```go
type hostRequestBody struct {
	Hostname   string     `json:"hostname"`
	IP         string     `json:"ip"`
	OS         string     `json:"os"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	// TagIDs is the UUID-based form (from the host form modal).
	TagIDs []uuid.UUID `json:"tag_ids"`
	// Tags is the name-based form (from CSV import via BulkCreate).
	Tags []string `json:"tags"`
}

func (b hostRequestBody) toHost() Host {
	return Host{
		Hostname:   strings.TrimSpace(b.Hostname),
		IP:         strings.TrimSpace(b.IP),
		OS:         b.OS,
		LastSeenAt: b.LastSeenAt,
	}
}
```

Remove the `ZoneID *uuid.UUID` field from `hostRequestBody` and remove `ZoneID: b.ZoneID` from `toHost()`.

Replace the `List` handler's zone filter logic:

```go
func (h *AdminHandlers) List(w http.ResponseWriter, r *http.Request) {
	if tagStr := r.URL.Query().Get("tag_id"); tagStr != "" {
		tagID, err := uuid.Parse(tagStr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid tag_id")
			return
		}
		list, err := h.Store.ListByTag(r.Context(), tagID)
		if err != nil {
			internalErr(w, r, err, "list hosts by tag")
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}
	list, err := h.Store.List(r.Context())
	if err != nil {
		internalErr(w, r, err, "list hosts")
		return
	}
	writeJSON(w, http.StatusOK, list)
}
```

Add `SetTags` handler at the end of the file (before the helpers):

```go
// SetTags replaces the full tag set for a host.
// Body: {"tag_ids": ["uuid1", "uuid2"]}
func (h *AdminHandlers) SetTags(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid host id")
		return
	}
	var body struct {
		TagIDs []uuid.UUID `json:"tag_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.TagIDs == nil {
		body.TagIDs = []uuid.UUID{}
	}
	if err := h.Store.SetTags(r.Context(), id, body.TagIDs); err != nil {
		internalErr(w, r, err, "set host tags")
		return
	}
	// Return the updated host
	host, err := h.Store.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "get host after set-tags")
		return
	}
	writeJSON(w, http.StatusOK, host)
}
```

In `Create`, after the licence cap check and before `s.Store.Create`, resolve tag names if `body.TagIDs` is empty but `body.Tags` is provided:

```go
// In Create, after `host := body.toHost()`:
var tagIDs []uuid.UUID
if len(body.TagIDs) > 0 {
    tagIDs = body.TagIDs
} else if len(body.Tags) > 0 {
    resolved, err := h.Store.ResolveTagNames(r.Context(), body.Tags, "#6366F1")
    if err != nil {
        internalErr(w, r, err, "resolve tag names")
        return
    }
    tagIDs = resolved
}

created, err := h.Store.Create(r.Context(), host)
// ... (existing error handling) ...
// After successful Create, call SetTags if tagIDs non-empty:
if len(tagIDs) > 0 {
    if err := h.Store.SetTags(r.Context(), created.ID, tagIDs); err != nil {
        log.Printf("manageserver/hosts: set tags after create: %v", err)
    } else {
        created.Tags = nil // will be reloaded
        created, _ = h.Store.Get(r.Context(), created.ID)
    }
}
writeJSON(w, http.StatusCreated, created)
```

In `BulkCreate`, after `BulkCreate` succeeds, set tags per host from `body.Hosts[i].Tags`:

```go
// After out, err := h.Store.BulkCreate(r.Context(), batch)
// and error checks, add:
for i, row := range body.Hosts {
    var tagIDs []uuid.UUID
    if len(row.TagIDs) > 0 {
        tagIDs = row.TagIDs
    } else if len(row.Tags) > 0 {
        resolved, err := h.Store.ResolveTagNames(r.Context(), row.Tags, "#6366F1")
        if err != nil {
            log.Printf("manageserver/hosts: resolve tag names for bulk host %d: %v", i, err)
            continue
        }
        tagIDs = resolved
    }
    if len(tagIDs) > 0 {
        if err := h.Store.SetTags(r.Context(), out[i].ID, tagIDs); err != nil {
            log.Printf("manageserver/hosts: set tags for bulk host %d: %v", i, err)
        }
    }
}
```

Remove the `uuid` import from `hostRequestBody` if it was only used for `ZoneID` — keep it since `TagIDs []uuid.UUID` still needs it.

- [ ] **Step 2: Add `PUT /{id}/tags` to `pkg/manageserver/hosts/routes.go`**

```go
package hosts

import "github.com/go-chi/chi/v5"

func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Post("/bulk", h.BulkCreate)
	r.Get("/{id}", h.Get)
	r.Patch("/{id}", h.Update)
	r.Delete("/{id}", h.Delete)
	r.Put("/{id}/tags", h.SetTags)
}
```

- [ ] **Step 3: Verify build**

```bash
go build ./pkg/manageserver/...
```

Expected: no errors (scanjobs will still fail until Task 9).

- [ ] **Step 4: Update `pkg/manageserver/hosts/handlers_admin_test.go`**

In the `fakeStore`, remove `ListByZone`/`CountByZone` and add `SetTags`, `ResolveTagNames`, `ListByTag`, `CountByTag`:

```go
func (f *fakeStore) SetTags(_ context.Context, hostID uuid.UUID, tagIDs []uuid.UUID) error {
	return nil
}
func (f *fakeStore) ResolveTagNames(_ context.Context, names []string, _ string) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, len(names))
	for i := range names { ids[i] = uuid.New() }
	return ids, nil
}
func (f *fakeStore) ListByTag(_ context.Context, _ uuid.UUID) ([]hosts.Host, error) {
	return []hosts.Host{}, nil
}
func (f *fakeStore) CountByTag(_ context.Context, _ uuid.UUID) (int64, error) {
	return 0, nil
}
```

Remove `ListByZone`/`CountByZone` fake methods. Add a test for `SetTags` handler:

```go
func TestHandlers_SetTags(t *testing.T) {
	store := newFakeStore()
	h, _ := store.Create(context.Background(), hosts.Host{Hostname: "web-01", OS: "linux"})
	tagID := uuid.New()
	body, _ := json.Marshal(map[string]any{"tag_ids": []string{tagID.String()}})
	r := httptest.NewRequest(http.MethodPut, "/"+h.ID.String()+"/tags", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mountTest(store).ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}
```

Update `mountTest` to use the updated `MountAdminRoutes`.

- [ ] **Step 5: Run handler tests**

```bash
go test -v -run TestHandlers_ ./pkg/manageserver/hosts/
```

Expected: all handler tests PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/manageserver/hosts/handlers_admin.go pkg/manageserver/hosts/routes.go \
        pkg/manageserver/hosts/handlers_admin_test.go
git commit -m "feat(hosts): remove zone_id, add tag_ids/tags support, PUT /{id}/tags"
```

---

## Task 9: Update Scanjobs — Zones → Tags

**Files:**
- Modify: `pkg/manageserver/scanjobs/types.go`
- Modify: `pkg/manageserver/scanjobs/postgres.go`
- Modify: `pkg/manageserver/scanjobs/handlers_admin.go`

- [ ] **Step 1: Update `pkg/manageserver/scanjobs/types.go`**

Remove `ZoneID uuid.UUID` from `Job` struct:

```go
type Job struct {
	ID                 uuid.UUID  `json:"id"`
	TenantID           uuid.UUID  `json:"tenant_id"`
	// ZoneID removed — scan jobs are now targeted by tag via EnqueueReq.TagIDs.
	HostID             uuid.UUID  `json:"host_id"`
	Profile            Profile    `json:"profile"`
	CredentialsRef     *uuid.UUID `json:"credentials_ref,omitempty"`
	Status             Status     `json:"status"`
	CancelRequested    bool       `json:"cancel_requested"`
	WorkerID           string     `json:"worker_id,omitempty"`
	EnqueuedAt         time.Time  `json:"enqueued_at"`
	StartedAt          *time.Time `json:"started_at,omitempty"`
	FinishedAt         *time.Time `json:"finished_at,omitempty"`
	RunningHeartbeatAt *time.Time `json:"running_heartbeat_at,omitempty"`
	ProgressText       string     `json:"progress_text"`
	ErrorMessage       string     `json:"error_message"`
}
```

In `EnqueueReq`, rename `ZoneIDs` to `TagIDs`:

```go
type EnqueueReq struct {
	TenantID       uuid.UUID   `json:"-"`
	TagIDs         []uuid.UUID `json:"tags"`
	HostFilter     string      `json:"host_filter"`
	Profile        Profile     `json:"profile"`
	CredentialsRef *uuid.UUID  `json:"credentials_ref,omitempty"`
}
```

- [ ] **Step 2: Update `pkg/manageserver/scanjobs/postgres.go`**

Update `jobSelectCols` (remove `zone_id`):

```go
const jobSelectCols = `id, tenant_id, host_id, profile, credentials_ref, status, cancel_requested, COALESCE(worker_id,''), enqueued_at, started_at, finished_at, running_heartbeat_at, progress_text, error_message`
```

Update `scanJob` to remove the zone_id scan:

```go
func scanJob(row pgx.Row) (Job, error) {
	var j Job
	var cref *uuid.UUID
	if err := row.Scan(
		&j.ID, &j.TenantID, &j.HostID,
		&j.Profile, &cref, &j.Status, &j.CancelRequested, &j.WorkerID,
		&j.EnqueuedAt, &j.StartedAt, &j.FinishedAt, &j.RunningHeartbeatAt,
		&j.ProgressText, &j.ErrorMessage,
	); err != nil {
		return Job{}, err
	}
	j.CredentialsRef = cref
	return j, nil
}
```

Update `Enqueue` to use tag-based host expansion and tag-free INSERT:

```go
func (s *PostgresStore) Enqueue(ctx context.Context, req EnqueueReq) ([]Job, error) {
	if len(req.TagIDs) == 0 {
		return []Job{}, nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin enqueue tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx,
		`SELECT DISTINCT h.id FROM manage_hosts h
		 JOIN manage_host_tags ht ON ht.host_id = h.id
		 WHERE ht.tag_id = ANY($1) AND h.hostname LIKE $2`,
		req.TagIDs, sqlGlob(req.HostFilter),
	)
	if err != nil {
		return nil, fmt.Errorf("expand tags to hosts: %w", err)
	}
	var hostIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan host id: %w", err)
		}
		hostIDs = append(hostIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host ids: %w", err)
	}

	out := make([]Job, 0, len(hostIDs))
	for _, hid := range hostIDs {
		row := tx.QueryRow(ctx,
			`INSERT INTO manage_scan_jobs (tenant_id, host_id, profile, credentials_ref)
			 VALUES ($1, $2, $3, $4)
			 RETURNING `+jobSelectCols,
			req.TenantID, hid, string(req.Profile), credRefArg(req.CredentialsRef),
		)
		j, err := scanJob(row)
		if err != nil {
			return nil, fmt.Errorf("insert scan job for host %s: %w", hid, err)
		}
		out = append(out, j)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit enqueue tx: %w", err)
	}
	return out, nil
}
```

Update the `Count` query if it references `zone_id` (check `pkg/manageserver/scanjobs/postgres.go` for any other `zone_id` references and remove them).

- [ ] **Step 3: Update `pkg/manageserver/scanjobs/handlers_admin.go`**

In the enqueue request body handler, rename `ZoneIDs` to `TagIDs`:

```go
// Find the struct that decodes the enqueue body (around line 91):
var body struct {
    TagIDs         []uuid.UUID `json:"tags"`
    HostFilter     string      `json:"host_filter"`
    Profile        Profile     `json:"profile"`
    CredentialsRef *uuid.UUID  `json:"credentials_ref,omitempty"`
}
// ...
// Replace:
//   ZoneIDs: body.ZoneIDs,
// with:
//   TagIDs: body.TagIDs,
```

- [ ] **Step 4: Verify build**

```bash
go build ./...
```

Expected: no errors. This confirms the entire backend compiles with zones removed.

- [ ] **Step 5: Remove the zones package**

```bash
rm -rf pkg/manageserver/zones/
```

- [ ] **Step 6: Verify build again**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 7: Run all unit tests**

```bash
go test ./...
```

Expected: PASS (integration tests skipped without DB).

- [ ] **Step 8: Commit**

```bash
git add pkg/manageserver/scanjobs/ pkg/manageserver/
git rm -r pkg/manageserver/zones/
git commit -m "feat(scanjobs): replace zone targeting with tag targeting; drop zones package"
```

---

## Task 10: Frontend — API Types + Client

**Files:**
- Modify: `web/packages/api-client/src/manageServer.types.ts`
- Modify: `web/packages/api-client/src/manageServer.ts`

- [ ] **Step 1: Update `web/packages/api-client/src/manageServer.types.ts`**

Add `Tag` interface after the existing `Zone` interface (we'll delete Zone later):

```typescript
export interface Tag {
  id: string;
  name: string;
  color: string;
  host_count?: number;
  created_at: string;
}

export interface CreateTagReq {
  name: string;
  color: string;
}

export interface UpdateTagReq {
  name: string;
  color: string;
}
```

Update `Host` interface — remove `zone_id`, add `tags`:

```typescript
export interface Host {
  id: string;
  hostname: string;
  ip?: string;
  tags: Tag[];
  os: string;
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
}
```

Update `CreateHostReq` — remove `zone_id`, add `tag_ids` and `tags`:

```typescript
export interface CreateHostReq {
  hostname: string;
  ip?: string;
  os?: string;
  tag_ids?: string[];
  tags?: string[];  // name-based form for CSV import
}
```

Update `UpdateHostReq` similarly (remove `zone_id`).

Remove the `Zone` interface and related zone request types.

Update the `EnqueueReq` type if it exists (replace `zones` with `tags`):

```typescript
export interface EnqueueReq {
  tags: string[];  // tag UUIDs
  host_filter?: string;
  profile: 'quick' | 'standard' | 'comprehensive';
  credentials_ref?: string;
}
```

Update `Job` interface — remove `zone_id`:

```typescript
export interface Job {
  id: string;
  tenant_id: string;
  host_id: string;
  // zone_id removed
  profile: string;
  status: string;
  enqueued_at: string;
  started_at?: string;
  finished_at?: string;
  progress_text: string;
  error_message: string;
}
```

- [ ] **Step 2: Update `web/packages/api-client/src/manageServer.ts`**

Remove zone methods (`listZones`, `createZone`, `updateZone`, `deleteZone`).

Add tag methods:

```typescript
listTags: () =>
  http.get<Tag[]>('/v1/admin/tags/'),
createTag: (req: CreateTagReq) =>
  http.post<Tag>('/v1/admin/tags/', req),
updateTag: (id: string, req: UpdateTagReq) =>
  http.patch<Tag>(`/v1/admin/tags/${id}`, req),
deleteTag: (id: string) =>
  http.del<void>(`/v1/admin/tags/${id}`),
setHostTags: (hostID: string, tagIDs: string[]) =>
  http.put<Host>(`/v1/admin/hosts/${hostID}/tags`, { tag_ids: tagIDs }),
```

Update `listHosts` — replace `zoneID` with `tagID`:

```typescript
listHosts: (tagID?: string) => {
  const qs = tagID ? `?tag_id=${encodeURIComponent(tagID)}` : '';
  return http.get<Host[]>(`/v1/admin/hosts/${qs}`);
},
```

Remove `zone_id` from `enrolAgent` request type if present.

- [ ] **Step 3: Verify TypeScript compiles**

```bash
cd web && pnpm --filter @triton/api-client typecheck 2>&1 | tail -10
```

Expected: no type errors (or only errors in consuming apps that haven't been updated yet — those are fixed in subsequent tasks).

- [ ] **Step 4: Commit**

```bash
git add web/packages/api-client/
git commit -m "feat(api-client): add Tag types, remove Zone, update Host/Job for tags"
```

---

## Task 11: Frontend — Tags Store + Tags Page

**Files:**
- Create: `web/apps/manage-portal/src/stores/tags.ts`
- Create: `web/apps/manage-portal/src/views/Tags.vue`

- [ ] **Step 1: Create `web/apps/manage-portal/src/stores/tags.ts`**

```typescript
import { defineStore } from 'pinia';
import { ref } from 'vue';
import { api } from '../api';
import type { Tag, CreateTagReq, UpdateTagReq } from '@triton/api-client';

export const useTagsStore = defineStore('tags', () => {
  const items = ref<Tag[]>([]);
  const loading = ref(false);

  async function fetch() {
    loading.value = true;
    try {
      items.value = await api.listTags();
    } finally {
      loading.value = false;
    }
  }

  async function create(req: CreateTagReq): Promise<Tag> {
    const tag = await api.createTag(req);
    items.value.push(tag);
    items.value.sort((a, b) => a.name.localeCompare(b.name));
    return tag;
  }

  async function update(id: string, req: UpdateTagReq): Promise<Tag> {
    const tag = await api.updateTag(id, req);
    const idx = items.value.findIndex(t => t.id === id);
    if (idx !== -1) items.value[idx] = tag;
    return tag;
  }

  async function remove(id: string): Promise<void> {
    await api.deleteTag(id);
    items.value = items.value.filter(t => t.id !== id);
  }

  return { items, loading, fetch, create, update, remove };
});
```

- [ ] **Step 2: Create `web/apps/manage-portal/src/views/Tags.vue`**

```vue
<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useTagsStore } from '../stores/tags';
import type { Tag } from '@triton/api-client';
import TDataTable from '../components/TDataTable.vue';
import TConfirmDialog from '../components/TConfirmDialog.vue';

const tags = useTagsStore();

// Preset color palette (12 colors)
const palette = [
  '#EF4444','#F97316','#EAB308','#22C55E',
  '#06B6D4','#3B82F6','#6366F1','#A855F7',
  '#EC4899','#14B8A6','#64748B','#1E293B',
];

const showForm = ref(false);
const editing = ref<Tag | null>(null);
const formName = ref('');
const formColor = ref('#6366F1');
const formError = ref('');
const saving = ref(false);

const confirmDelete = ref(false);
const deleteTarget = ref<Tag | null>(null);

const columns = [
  { key: 'color', label: '' },
  { key: 'name', label: 'Name' },
  { key: 'host_count', label: 'Hosts' },
  { key: 'id', label: '' },
];

function openNew() {
  editing.value = null;
  formName.value = '';
  formColor.value = '#6366F1';
  formError.value = '';
  showForm.value = true;
}

function openEdit(tag: Tag) {
  editing.value = tag;
  formName.value = tag.name;
  formColor.value = tag.color;
  formError.value = '';
  showForm.value = true;
}

function cancelForm() {
  showForm.value = false;
}

async function submitForm() {
  if (!formName.value.trim()) {
    formError.value = 'Name is required';
    return;
  }
  saving.value = true;
  formError.value = '';
  try {
    if (editing.value) {
      await tags.update(editing.value.id, { name: formName.value.trim(), color: formColor.value });
    } else {
      await tags.create({ name: formName.value.trim(), color: formColor.value });
    }
    showForm.value = false;
  } catch (e: any) {
    formError.value = e?.message ?? 'Save failed';
  } finally {
    saving.value = false;
  }
}

function askDelete(tag: Tag) {
  deleteTarget.value = tag;
  confirmDelete.value = true;
}

async function onConfirmDelete() {
  if (!deleteTarget.value) return;
  await tags.remove(deleteTarget.value.id);
  confirmDelete.value = false;
  deleteTarget.value = null;
}

onMounted(() => tags.fetch());
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">Tags</h1>
        <p class="page-sub">Colour-coded labels for grouping and filtering hosts.</p>
      </div>
      <button class="btn btn-primary" @click="openNew">New tag</button>
    </div>

    <!-- Inline form -->
    <div v-if="showForm" class="tag-form card">
      <div class="tag-form-fields">
        <input
          v-model="formName"
          class="input"
          placeholder="Tag name"
          @keyup.enter="submitForm"
          @keyup.escape="cancelForm"
        />
        <div class="color-palette">
          <button
            v-for="c in palette"
            :key="c"
            class="color-swatch"
            :class="{ selected: formColor === c }"
            :style="{ background: c }"
            @click="formColor = c"
          />
        </div>
        <span v-if="formError" class="form-error">{{ formError }}</span>
      </div>
      <div class="tag-form-actions">
        <button class="btn btn-ghost" @click="cancelForm">Cancel</button>
        <button class="btn btn-primary" :disabled="saving" @click="submitForm">
          {{ editing ? 'Save' : 'Create' }}
        </button>
      </div>
    </div>

    <TDataTable :columns="columns" :rows="tags.items" :loading="tags.loading" empty="No tags yet.">
      <template #[`cell:color`]="{ row }">
        <span class="tag-chip" :style="{ background: row.color }">&nbsp;</span>
      </template>
      <template #[`cell:name`]="{ row }">
        <span class="tag-label" :style="{ color: row.color }">{{ row.name }}</span>
      </template>
      <template #[`cell:id`]="{ row }">
        <div class="row-actions">
          <button class="btn-link" @click="openEdit(row)">Edit</button>
          <button class="btn-link btn-danger" @click="askDelete(row)">Delete</button>
        </div>
      </template>
    </TDataTable>

    <TConfirmDialog
      :open="confirmDelete"
      title="Delete tag"
      :message="`Delete '${deleteTarget?.name}'? It will be removed from ${deleteTarget?.host_count ?? 0} host(s).`"
      confirm-label="Delete"
      @confirm="onConfirmDelete"
      @cancel="confirmDelete = false"
    />
  </div>
</template>
```

- [ ] **Step 3: Verify TypeScript**

```bash
cd web && pnpm --filter manage-portal typecheck 2>&1 | tail -15
```

Expected: no new errors from tags files.

- [ ] **Step 4: Commit**

```bash
git add web/apps/manage-portal/src/stores/tags.ts web/apps/manage-portal/src/views/Tags.vue
git commit -m "feat(manage-portal): Tags store + Tags page"
```

---

## Task 12: Frontend — Update Hosts Page + HostForm + HostBulkForm CSV Tab

**Files:**
- Modify: `web/apps/manage-portal/src/stores/hosts.ts`
- Modify: `web/apps/manage-portal/src/views/Hosts.vue`
- Modify: `web/apps/manage-portal/src/views/modals/HostForm.vue`
- Modify: `web/apps/manage-portal/src/views/modals/HostBulkForm.vue`

- [ ] **Step 1: Update `web/apps/manage-portal/src/stores/hosts.ts`**

Replace `zoneID` filter with `tagID`, update `fetch()` signature:

```typescript
// Replace the filter ref:
const filter = ref<{ tagID?: string }>(loadFilter());

// Update fetch():
async function fetch() {
  loading.value = true;
  try {
    items.value = await api.listHosts(filter.value.tagID);
  } finally {
    loading.value = false;
  }
}

// localStorage key stays the same but the stored object changes shape.
// Update loadFilter() to read tagID instead of zoneID:
function loadFilter(): { tagID?: string } {
  try {
    const raw = localStorage.getItem('manage-portal.hosts.filter');
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return { tagID: parsed.tagID };
  } catch {
    return {};
  }
}
```

Remove `bulkCreate` dependency on `zone_id` (it now accepts `tags: string[]`).

- [ ] **Step 2: Update `web/apps/manage-portal/src/views/Hosts.vue`**

Replace zone filter with tag multi-select (single select first — multi-select is a UX enhancement):

```vue
<!-- Replace zone filter dropdown with: -->
<select v-model="hosts.filter.tagID" class="select" @change="hosts.fetch()">
  <option value="">All tags</option>
  <option v-for="t in tags.items" :key="t.id" :value="t.id">{{ t.name }}</option>
</select>
```

Replace zone column in table with tags column:

```vue
<!-- Remove zone_id column, add tags column -->
```

Update `columns` array — remove `zone_id`, add `tags`:

```typescript
const columns = [
  { key: 'hostname', label: 'Hostname' },
  { key: 'ip', label: 'IP' },
  { key: 'tags', label: 'Tags' },
  { key: 'os', label: 'OS' },
  { key: 'last_seen_at', label: 'Last Seen' },
  { key: 'id', label: '' },
];
```

Add tag chips cell template:

```vue
<template #[`cell:tags`]="{ row }">
  <div class="tag-chips">
    <span
      v-for="tag in row.tags"
      :key="tag.id"
      class="tag-chip"
      :style="{ background: tag.color }"
    >{{ tag.name }}</span>
    <span v-if="!row.tags.length" class="muted">—</span>
  </div>
</template>
```

Update `onMounted` — replace `zones.fetch()` with `tags.fetch()`:

```typescript
import { useTagsStore } from '../stores/tags';
const tags = useTagsStore();
onMounted(() => Promise.all([tags.fetch(), hosts.fetch()]));
```

Update `HostForm` props — pass `tags.items` instead of `zones.items`:

```vue
<HostForm
  :open="showForm"
  :editing="editing"
  :tags="tags.items"
  @close="showForm = false"
  @submit="onSubmit"
/>
```

- [ ] **Step 3: Update `web/apps/manage-portal/src/views/modals/HostForm.vue`**

Replace `zones` prop with `tags`, replace zone select with tag multi-select:

```vue
<script setup lang="ts">
import { ref, watch } from 'vue';
import type { Host, Tag } from '@triton/api-client';

const props = defineProps<{
  open: boolean;
  editing?: Host | null;
  tags: Tag[];
}>();
const emit = defineEmits<{
  close: [];
  submit: [payload: { hostname: string; ip?: string; os?: string; tag_ids: string[] }];
}>();

const hostname = ref('');
const ip = ref('');
const os = ref('');
const selectedTagIDs = ref<string[]>([]);
const error = ref('');

watch([() => props.open, () => props.editing], () => {
  hostname.value = props.editing?.hostname ?? '';
  ip.value = props.editing?.ip ?? '';
  os.value = props.editing?.os ?? '';
  selectedTagIDs.value = props.editing?.tags.map(t => t.id) ?? [];
  error.value = '';
});

function onSubmit() {
  if (!hostname.value.trim()) {
    error.value = 'Hostname is required';
    return;
  }
  emit('submit', {
    hostname: hostname.value.trim(),
    ip: ip.value.trim() || undefined,
    os: os.value.trim() || undefined,
    tag_ids: selectedTagIDs.value,
  });
}
</script>

<template>
  <!-- ... modal wrapper ... -->
  <div class="form-group">
    <label>Tags</label>
    <div class="tag-multi-select">
      <label v-for="tag in tags" :key="tag.id" class="tag-checkbox">
        <input
          type="checkbox"
          :value="tag.id"
          v-model="selectedTagIDs"
        />
        <span class="tag-chip" :style="{ background: tag.color }">{{ tag.name }}</span>
      </label>
    </div>
  </div>
  <!-- ... rest of form fields ... -->
</template>
```

- [ ] **Step 4: Add CSV tab to `web/apps/manage-portal/src/views/modals/HostBulkForm.vue`**

Add a tab bar with "CSV" (default) and "JSON" tabs. The CSV tab contains:

```vue
<script setup lang="ts">
import { ref } from 'vue';

const props = defineProps<{ open: boolean }>();
const emit = defineEmits<{
  close: [];
  submit: [hosts: Array<{ hostname: string; ip?: string; os?: string; tags?: string[] }>];
}>();

const activeTab = ref<'csv' | 'json'>('csv');
const csvInput = ref('');
const jsonInput = ref('');
const parseError = ref('');
const preview = ref<Array<{ hostname: string; ip?: string; os?: string; tags?: string[]; _error?: string }>>([]);

// CSV parser
function parseCSV(raw: string) {
  parseError.value = '';
  preview.value = [];
  const lines = raw.trim().split('\n');
  if (lines.length < 2) { parseError.value = 'CSV must have a header row and at least one data row'; return; }

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const hostnameIdx = headers.indexOf('hostname');
  if (hostnameIdx === -1) { parseError.value = 'CSV must have a "hostname" column'; return; }
  const ipIdx = headers.indexOf('ip');
  const osIdx = headers.indexOf('os');
  const tagsIdx = headers.indexOf('tags');

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    // Handle quoted fields (simple CSV — no embedded newlines)
    const cells = line.match(/(".*?"|[^,]+|(?<=,)(?=,)|^(?=,)|(?<=,)$)/g)?.map(c =>
      c.startsWith('"') ? c.slice(1, -1) : c
    ) ?? line.split(',');

    const hostname = cells[hostnameIdx]?.trim() ?? '';
    const row: typeof preview.value[0] = { hostname };
    if (!hostname) { row._error = 'hostname is required'; }
    if (ipIdx !== -1 && cells[ipIdx]?.trim()) row.ip = cells[ipIdx].trim();
    if (osIdx !== -1 && cells[osIdx]?.trim()) row.os = cells[osIdx].trim();
    if (tagsIdx !== -1 && cells[tagsIdx]?.trim()) {
      row.tags = cells[tagsIdx].trim().replace(/^"|"$/g, '').split(',').map(t => t.trim()).filter(Boolean);
    }
    rows.push(row);
  }
  preview.value = rows;
}

function onCSVInput() { parseCSV(csvInput.value); }

function validRows() { return preview.value.filter(r => !r._error); }

function onSubmit() {
  if (activeTab.value === 'csv') {
    const rows = validRows();
    if (!rows.length) { parseError.value = 'No valid rows to import'; return; }
    emit('submit', rows.map(r => ({ hostname: r.hostname, ip: r.ip, os: r.os, tags: r.tags })));
  } else {
    // existing JSON logic
    try {
      const parsed = JSON.parse(jsonInput.value);
      if (!Array.isArray(parsed)) throw new Error('Must be a JSON array');
      for (let i = 0; i < parsed.length; i++) {
        if (!parsed[i].hostname?.trim()) throw new Error(`Entry ${i}: hostname is required`);
      }
      emit('submit', parsed);
    } catch (e: any) {
      parseError.value = e.message;
    }
  }
}
</script>

<template>
  <div v-if="open" class="modal-overlay">
    <div class="modal">
      <h2>Bulk import hosts</h2>

      <!-- Tab bar -->
      <div class="tab-bar">
        <button :class="{ active: activeTab === 'csv' }" @click="activeTab = 'csv'">CSV</button>
        <button :class="{ active: activeTab === 'json' }" @click="activeTab = 'json'">JSON</button>
      </div>

      <!-- CSV tab -->
      <div v-if="activeTab === 'csv'">
        <p class="help-text">
          Columns: <code>hostname</code> (required), <code>ip</code>, <code>os</code>,
          <code>tags</code> (comma-separated, quoted if multiple: <code>"prod,web"</code>)
        </p>
        <textarea
          v-model="csvInput"
          class="textarea"
          rows="8"
          placeholder="hostname,ip,os,tags&#10;web-01,10.0.0.10,linux,&quot;production,web&quot;&#10;db-01,10.0.0.20,linux,production"
          @input="onCSVInput"
        />
        <div v-if="preview.length" class="preview">
          <div v-for="(row, i) in preview" :key="i" :class="{ error: row._error }">
            <span v-if="row._error" class="row-error">Row {{ i + 1 }}: {{ row._error }}</span>
            <span v-else>{{ row.hostname }}<span v-if="row.ip"> — {{ row.ip }}</span></span>
          </div>
          <p class="preview-summary">
            {{ validRows().length }} valid / {{ preview.length - validRows().length }} errors
          </p>
        </div>
      </div>

      <!-- JSON tab -->
      <div v-else>
        <p class="help-text">JSON array: <code>[{"hostname":"web-01","ip":"10.0.0.10","os":"linux"}]</code></p>
        <textarea v-model="jsonInput" class="textarea" rows="8" placeholder='[{"hostname": "web-01"}]' />
      </div>

      <p v-if="parseError" class="form-error">{{ parseError }}</p>

      <div class="modal-footer">
        <button class="btn btn-ghost" @click="emit('close')">Cancel</button>
        <button
          class="btn btn-primary"
          :disabled="activeTab === 'csv' && validRows().length === 0"
          @click="onSubmit"
        >
          Import{{ activeTab === 'csv' && validRows().length ? ` ${validRows().length} hosts` : '' }}
        </button>
      </div>
    </div>
  </div>
</template>
```

- [ ] **Step 5: Verify TypeScript**

```bash
cd web && pnpm --filter manage-portal typecheck 2>&1 | tail -15
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add web/apps/manage-portal/src/stores/hosts.ts \
        web/apps/manage-portal/src/views/Hosts.vue \
        web/apps/manage-portal/src/views/modals/HostForm.vue \
        web/apps/manage-portal/src/views/modals/HostBulkForm.vue
git commit -m "feat(manage-portal): hosts page — tag chips, tag filter, CSV bulk import tab"
```

---

## Task 13: Frontend — ScanJobs + Nav/Router Cleanup

**Files:**
- Modify: `web/apps/manage-portal/src/views/ScanJobs.vue`
- Modify: `web/apps/manage-portal/src/nav.ts`
- Modify: `web/apps/manage-portal/src/router/index.ts`
- Delete: `web/apps/manage-portal/src/stores/zones.ts`
- Delete: `web/apps/manage-portal/src/views/Zones.vue`

- [ ] **Step 1: Update `web/apps/manage-portal/src/views/ScanJobs.vue`**

Replace `useZonesStore` with `useTagsStore`:

```typescript
// Remove:
import { useZonesStore } from '../stores/zones';
const zones = useZonesStore();

// Add:
import { useTagsStore } from '../stores/tags';
const tags = useTagsStore();
```

Replace `zone_id` column in the table columns array with a removed entry (or keep for historical display):

```typescript
// Remove from columns:
{ key: 'zone_id', label: 'Zone' },
```

Remove `zoneNameByID` computed and zone-related template:

```vue
<!-- Remove: -->
<template #[`cell:zone_id`]="{ row }">
  {{ row.zone_id ? (zoneNameByID.get(row.zone_id) ?? row.zone_id) : '—' }}
</template>
```

Update the enqueue form's zone select to a tag select:

```vue
<!-- Replace zone multi-select with tag multi-select in enqueue form -->
:zones="zones.items"  →  :tags="tags.items"
```

Update `onMounted`:

```typescript
// Replace zones.fetch() with tags.fetch()
onMounted(() => Promise.all([tags.fetch(), ...rest]));
```

- [ ] **Step 2: Update `web/apps/manage-portal/src/nav.ts`**

Replace the Zones nav entry with Tags:

```typescript
// Remove:
{ href: '#/inventory/zones', label: 'Zones' },
// Add:
{ href: '#/inventory/tags', label: 'Tags' },
```

- [ ] **Step 3: Update `web/apps/manage-portal/src/router/index.ts`**

Replace the zones route with tags:

```typescript
// Remove:
{ path: '/inventory/zones', name: 'zones', component: () => import('./views/Zones.vue') },
// Add:
{ path: '/inventory/tags', name: 'tags', component: () => import('./views/Tags.vue') },
```

- [ ] **Step 4: Delete removed files**

```bash
rm web/apps/manage-portal/src/stores/zones.ts
rm web/apps/manage-portal/src/views/Zones.vue
```

- [ ] **Step 5: Verify TypeScript and build**

```bash
cd web && pnpm --filter manage-portal typecheck 2>&1 | tail -10
pnpm --filter manage-portal build 2>&1 | tail -10
```

Expected: build succeeds, `pkg/manageserver/ui/dist/` updated.

- [ ] **Step 6: Rebuild manage server binary with new UI**

```bash
cd /Users/amirrudinyahaya/Workspace/triton && make build-manageserver
```

- [ ] **Step 7: Run backend unit tests**

```bash
go test ./...
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add web/apps/manage-portal/src/
git rm web/apps/manage-portal/src/stores/zones.ts web/apps/manage-portal/src/views/Zones.vue
git add pkg/manageserver/ui/dist/ bin/
git commit -m "feat(manage-portal): replace Zones with Tags in nav/router/scanjobs; rebuild UI"
```

---

## Self-Review

### Spec Coverage

| Spec Requirement | Task |
|---|---|
| `manage_tags` table with id/name/color | Task 1 |
| `manage_host_tags` junction table | Task 1 |
| Zones auto-migrated to tags | Task 1 |
| `manage_hosts.zone_id` dropped | Task 1 |
| Tags CRUD API | Tasks 2–4 |
| `GET /admin/hosts?tag_id=` filter | Task 8 |
| Host API returns `tags: [...]` | Tasks 6–7 |
| `PUT /admin/hosts/{id}/tags` | Task 8 |
| Bulk create accepts `tags: ["name"]` | Task 8 |
| CSV import (frontend) | Task 12 |
| Tags page with color picker | Task 11 |
| Host rows show tag chips | Task 12 |
| Tag filter on hosts list | Task 12 |
| Host form tag multi-select | Task 12 |
| Zones replaced in nav/router/scanjobs | Task 13 |
| Integration tests (tags CRUD) | Task 2–3 |
| Integration tests (hosts + tag ops) | Task 7 |
| Handler unit tests (tags) | Task 4 |
| Handler unit tests (hosts) | Task 8 |

All spec requirements are covered. ✅
