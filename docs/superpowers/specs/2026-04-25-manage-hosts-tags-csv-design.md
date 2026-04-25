# Manage Portal — Hosts Tags & CSV Import Design

## Goal

Replace the single-zone grouping on hosts with a flexible multi-tag system, and add CSV bulk import alongside the existing JSON import. Network discovery is out of scope for this sprint (next spec).

## Architecture

Tags are a first-class resource with their own management page. Hosts carry a many-to-many tag relationship via a junction table. CSV import is handled entirely in the browser — parsed rows are posted to the existing bulk endpoint. Existing zone data is auto-migrated to tags with no data loss.

## Tech Stack

Go 1.25, pgx/v5, Chi router, Vue 3, Pinia, TypeScript, Vite

---

## Data Model

### New table: `manage_tags`

```sql
CREATE TABLE manage_tags (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL UNIQUE,
    color      TEXT NOT NULL,           -- hex string e.g. "#6366F1"
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### New table: `manage_host_tags`

```sql
CREATE TABLE manage_host_tags (
    host_id UUID NOT NULL REFERENCES manage_hosts(id) ON DELETE CASCADE,
    tag_id  UUID NOT NULL REFERENCES manage_tags(id)  ON DELETE CASCADE,
    PRIMARY KEY (host_id, tag_id)
);
```

### Modified table: `manage_hosts`

- Drop column `zone_id UUID REFERENCES manage_zones(id)`
- Drop table `manage_zones`

### Migration strategy (one migration, transactional)

1. Create `manage_tags` and `manage_host_tags`.
2. For each distinct `zone_id` on `manage_hosts`: create a tag with the zone's name and color `#6366F1`; insert rows into `manage_host_tags` for every host in that zone.
3. Drop `zone_id` from `manage_hosts`.
4. Drop `manage_zones`.

---

## Backend API

### New package: `pkg/manageserver/tags/`

Files: `types.go`, `store.go`, `postgres.go`, `handlers_admin.go`

#### Tag type

```go
type Tag struct {
    ID        uuid.UUID
    Name      string
    Color     string    // hex e.g. "#6366F1"
    HostCount int       // populated on List only
    CreatedAt time.Time
}
```

#### Store interface

```go
type Store interface {
    Create(ctx context.Context, t Tag) (Tag, error)
    Get(ctx context.Context, id uuid.UUID) (Tag, error)
    List(ctx context.Context) ([]Tag, error)       // includes host_count
    Update(ctx context.Context, t Tag) (Tag, error)
    Delete(ctx context.Context, id uuid.UUID) error
}
```

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/tags` | List all tags with host count |
| `POST` | `/api/v1/admin/tags` | Create tag `{name, color}` |
| `PATCH` | `/api/v1/admin/tags/{id}` | Rename / recolor `{name?, color?}` |
| `DELETE` | `/api/v1/admin/tags/{id}` | Delete tag (cascades off host_tags) |

Validation:
- `name`: required, non-empty, unique (409 on conflict)
- `color`: required, must match `^#[0-9A-Fa-f]{6}$`

### Updated hosts package

#### Host type — add Tags field

```go
type Host struct {
    ID         uuid.UUID
    Hostname   string
    IP         string
    Tags       []tags.Tag  // populated on Get/List
    OS         string
    LastSeenAt *time.Time
    CreatedAt  time.Time
    UpdatedAt  time.Time
}
```

#### New store methods

```go
// Replace full tag set for a host (idempotent).
SetTags(ctx context.Context, hostID uuid.UUID, tagIDs []uuid.UUID) error

// Resolve tag names to IDs, creating missing tags with defaultColor.
ResolveTagNames(ctx context.Context, names []string, defaultColor string) ([]uuid.UUID, error)

// List hosts filtered by tag.
ListByTag(ctx context.Context, tagID uuid.UUID) ([]Host, error)
```

#### Updated endpoints

| Method | Path | Change |
|--------|------|--------|
| `GET` | `/api/v1/admin/hosts` | `?tag_id=` replaces `?zone_id=`; response includes `tags: [{id,name,color}]` |
| `POST` | `/api/v1/admin/hosts` | Accepts `tag_ids: []` (UUIDs) or `tags: []` (names, create-if-missing) |
| `POST` | `/api/v1/admin/hosts/bulk` | Each entry accepts `tags: ["name1","name2"]` (names, create-if-missing) |
| `PATCH` | `/api/v1/admin/hosts/{id}` | `zone_id` removed; no tag changes here |
| `PUT` | `/api/v1/admin/hosts/{id}/tags` | Replace full tag set `{tag_ids: []}` |

`POST /bulk` uses `ResolveTagNames` so CSV-imported tag names are created automatically with default color `#6366F1`. The bulk insert remains transactional (all-or-nothing).

---

## Frontend

### New: Tags page

- **Route:** `/tags`
- **Sidebar:** entry labelled "Tags", between Zones (removed) and Hosts
- **File:** `web/apps/manage-portal/src/views/Tags.vue`
- **Store:** `web/apps/manage-portal/src/stores/tags.ts`

#### Tags page layout

- Header: "Tags" title + "New tag" button
- Table columns: Color swatch | Name | Hosts | Actions (Edit, Delete)
- "New tag" → inline form row at top of table: text input for name + color picker (palette of 12 preset hex colors)
- Edit → same inline form on the row
- Delete → confirmation dialog: "This tag is assigned to N host(s). Remove from all?" — proceed deletes the tag and cascades

#### Color palette (12 presets)

```
#EF4444  #F97316  #EAB308  #22C55E
#06B6D4  #3B82F6  #6366F1  #A855F7
#EC4899  #14B8A6  #64748B  #1E293B
```

### Updated: Hosts page

- **File:** `web/apps/manage-portal/src/views/Hosts.vue`
- Zone filter dropdown → tag multi-select filter (select multiple tags; shows hosts matching ANY selected tag)
- Host table rows: show tag chips (colored pill badges with tag name) in a Tags column; remove Zone column
- "Bulk import" button: opens modal with two tabs — **CSV** (default) and **JSON** (existing)
- "New host" form: zone dropdown → tag multi-select with inline "Create tag" option (name + color picker)

### Updated: Host form modal

- **File:** `web/apps/manage-portal/src/views/modals/HostForm.vue`
- Replace `zone_id` select with tag multi-select
- Tag options loaded from tags store
- "Create new tag" option at bottom of dropdown: opens inline mini-form (name + color)

### New: CSV import tab in bulk modal

- **File:** `web/apps/manage-portal/src/views/modals/HostBulkForm.vue` (add CSV tab)

#### CSV format

```csv
hostname,ip,os,tags
web-01,10.0.0.10,linux,"production,web"
db-01,10.0.0.20,linux,"production,database"
win-01,10.0.1.5,windows,production
```

- `hostname`: required
- `ip`: optional, validated as IPv4/IPv6
- `os`: optional
- `tags`: optional, comma-separated tag names (quoted if multiple); unknown tags created with default color

#### CSV import UX flow

1. File picker (`.csv`) or paste textarea toggle
2. Parse on input → preview table with row-level validation errors highlighted in red
3. Valid row count shown: "12 hosts ready to import, 2 errors"
4. "Import 12 hosts" button (disabled if 0 valid rows)
5. Posts `{hosts: [...]}` to `POST /api/v1/admin/hosts/bulk`
6. On success: close modal, refresh hosts list, show "12 hosts imported" toast
7. On partial backend error: show error summary (backend is all-or-nothing, so all rows fail together)

### Updated: Host detail page

- Tags section replaces Zone field
- Displays tag chips; "Edit tags" button opens tag multi-select inline
- Calls `PUT /api/v1/admin/hosts/{id}/tags` on save

### Updated: API client

- **File:** `web/packages/api-client/src/manageServer.types.ts`
- Add `Tag`, `CreateTagReq`, `UpdateTagReq` types
- Update `Host`: remove `zone_id`, add `tags: Tag[]`
- Update `CreateHostReq`: remove `zone_id`, add `tag_ids?: string[]`, `tags?: string[]`
- Add tag API methods to client

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Duplicate tag name | 409 Conflict — "tag name already exists" |
| Invalid color hex | 400 Bad Request — "color must be a 6-digit hex color" |
| Delete tag assigned to hosts | Allowed — cascades; UI warns with host count first |
| CSV row missing hostname | Client-side validation error on that row; row excluded from import |
| CSV invalid IP | Client-side validation error on that row; row excluded from import |
| Bulk insert hostname collision | 409 from backend — entire batch rejected; shown as error |
| Host cap exceeded | 403 from backend — shown as error with cap info |

---

## Testing

### Backend (integration, `//go:build integration`)

- Tags CRUD: create, get, list (with host count), update, delete
- Duplicate name → 409
- Invalid color → 400
- Delete cascades: tag deleted → `manage_host_tags` rows gone, hosts still exist
- `SetTags`: assign tags to host → list host → tags present; replace tags → old tags gone
- `ResolveTagNames`: existing names resolved, missing names created with default color
- `ListByTag`: filter works; host with multiple tags appears under each tag's filter
- Updated hosts bulk: `tags` by name → created-if-missing, assigned correctly
- `GET /admin/hosts?tag_id=`: returns only hosts with that tag
- Migration: zones auto-converted to tags; no zone data lost

### Frontend (Vitest unit)

- CSV parser: valid CSV → correct host array; missing hostname → row error; bad IP → row error; quoted multi-tags → correct split
- Tags store: CRUD operations against mock API
- Tags page: renders tag list, inline create form, delete confirmation with host count
- Hosts page: tag chip rendering, multi-tag filter, CSV tab in bulk modal

---

## Out of Scope (Next Sprint)

- Network discovery service (CIDR scan, port probing, DNS reverse lookup)
- Discovery results page (review candidates, select to import)
- SSH credential management (belongs on Scans page)
