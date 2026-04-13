# Analytics Phase 3 — Category Filters Design Spec

**Date:** 2026-04-13
**Parent:** Analytics Phase roadmap (Phase 1 inventory/certificates/priority, Phase 2 executive summary)
**Goal:** Add server-side filtering to all three analytics views (Inventory, Certificates, Priority) so operators can drill down by hostname, algorithm, and PQC status.

---

## 1. Scope

### In scope

- New `GET /api/v1/filters` endpoint returning distinct hostnames, algorithms, and PQC statuses for the org
- Server-side `hostname`, `algorithm`, and `pqc_status` query parameters on existing analytics endpoints
- `<select>` dropdown UI for filters on each analytics view, defaulting to "All"
- Store layer: new `ListFilterOptions` method + `FilterParams` struct threaded through existing list methods
- Integration, handler, and E2E test coverage

### Out of scope

- Multi-select (select multiple hostnames at once) — Phase 4+
- Client-side filtering or caching of full datasets
- Filter chips/pills UI — using dropdowns for consistency
- New analytics views or routes
- Changes to the executive summary endpoint

---

## 2. Decision log

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Server-side filtering via query params | Scales to large deployments; less data over the wire |
| 2 | Dropdown `<select>` for all filters | Simple, consistent, scales to many hostnames |
| 3 | Separate `GET /api/v1/filters` endpoint | One call populates all views; avoids changing existing response shapes |
| 4 | PQC statuses hardcoded in filters response | Always exactly 4 values (SAFE/TRANSITIONAL/DEPRECATED/UNSAFE); no query needed |
| 5 | Empty param = no filter ("All") | Backward compatible; zero-value FilterParams means existing behavior unchanged |
| 6 | One hostname at a time | Multi-select deferred; single value keeps SQL simple |
| 7 | Filters cached client-side after first fetch | Avoid re-fetching on every view switch; refresh on page reload |

---

## 3. API Changes

### New endpoint

**`GET /api/v1/filters`**

Response:
```json
{
  "hostnames": ["web1.example.com", "db1.example.com"],
  "algorithms": ["RSA", "AES-256", "ECDSA-P256", "SHA-256"],
  "pqcStatuses": ["SAFE", "TRANSITIONAL", "DEPRECATED", "UNSAFE"]
}
```

- Tenant-scoped (org from JWT/session)
- `hostnames` and `algorithms` derived from `findings` table, latest scan per hostname
- `pqcStatuses` hardcoded `["SAFE","TRANSITIONAL","DEPRECATED","UNSAFE"]`
- Empty org (single-tenant mode): returns empty arrays

### Modified endpoints

| Endpoint | New optional params | Filter applied |
|---|---|---|
| `GET /api/v1/certificates/expiring` | `hostname`, `algorithm` | SQL WHERE clauses on findings |
| `GET /api/v1/inventory` | `hostname`, `pqc_status` | SQL WHERE clauses on findings |
| `GET /api/v1/priority` | `hostname`, `pqc_status` | SQL WHERE clauses on findings |

All params are optional, exact-match, single-value. Missing = "All" (no filter). Unknown values return empty results, not errors.

---

## 4. Store Changes

### New type

```go
type FilterParams struct {
    Hostname  string // exact match; empty = no filter
    Algorithm string // exact match; empty = no filter
    PQCStatus string // exact match; empty = no filter
}

type FilterOptions struct {
    Hostnames  []string `json:"hostnames"`
    Algorithms []string `json:"algorithms"`
    PQCStatuses []string `json:"pqcStatuses"`
}
```

### New method

```go
ListFilterOptions(ctx context.Context, orgID string) (FilterOptions, error)
```

Single query: `SELECT DISTINCT hostname, algorithm, pqc_status FROM findings WHERE scan_id IN (latest per host CTE) AND org_id = $1`

### Modified signatures

```go
ListInventory(ctx, orgID string, fp FilterParams) ([]InventoryRow, error)
ListExpiringCertificates(ctx, orgID string, within time.Duration, fp FilterParams) ([]ExpiringCertRow, error)
ListTopPriorityFindings(ctx, orgID string, limit int, fp FilterParams) ([]PriorityRow, error)
```

SQL: append `AND hostname = $N` when `fp.Hostname != ""`, etc. Use conditional WHERE clause building.

---

## 5. UI Changes

### Filter bar

Reusable `renderFilterBar(containerId, filters, activeValues, onChange)` function that renders `<select>` dropdowns in a `.filter-bar` row.

Each dropdown:
- First option: `All` (value `""`)
- Remaining options: sorted distinct values from `/api/v1/filters`

### Per-view filter mapping

| View | Dropdown 1 | Dropdown 2 |
|---|---|---|
| Certificates | Hostname | Algorithm |
| Inventory | Hostname | PQC Status |
| Priority | Hostname | PQC Status |

### State

Module-level objects per view:
```js
var certFilters = {hostname: '', algorithm: ''};
var inventoryFilters = {hostname: '', pqcStatus: ''};
var priorityFilters = {hostname: '', pqcStatus: ''};
```

### Flow

1. First analytics view navigation → `GET /api/v1/filters`, cache result
2. Render filter bar above table with cached options
3. On dropdown change → update filter state → re-fetch endpoint with params → re-render
4. Existing Certificates day-range chips combine with hostname/algorithm filters

### Layout (Certificates example)

```
[Hostname: All ▾]  [Algorithm: All ▾]
[30 days] [90 days] [180 days] [All]
┌────────────────────────────────────┐
│ Subject │ Host │ Algo │ Expires │  │
│ ...     │ ...  │ ...  │ ...     │  │
└────────────────────────────────────┘
```

### CSS

~20 lines for `.filter-bar` layout (flex row, gap, select styling). Appended to existing `style.css`.

---

## 6. Testing

### Integration tests (PostgreSQL, `//go:build integration`)

1. `ListFilterOptions` returns correct distinct hostnames + algorithms from seeded data
2. `ListExpiringCertificates` with hostname filter returns only that host's certs
3. `ListExpiringCertificates` with algorithm filter returns only matching certs
4. `ListInventory` with hostname filter returns only that host's inventory
5. `ListInventory` with pqc_status filter returns only matching rows
6. `ListTopPriorityFindings` with hostname filter returns only that host's findings
7. Each method with empty FilterParams returns same results as before (regression guard)

### Handler tests

8. `GET /api/v1/filters` returns expected shape with seeded data
9. `GET /api/v1/certificates/expiring?hostname=web1` passes param to store
10. `GET /api/v1/inventory?pqc_status=DEPRECATED` passes param to store

### E2E (Playwright)

11. Filter dropdowns render with "All" default + correct options
12. Selecting hostname filters Certificates table rows
13. Selecting "All" restores full Certificates results
14. Inventory and Priority filter dropdowns functional

**Total: ~14 new tests.**

---

## 7. Files

### New files

| Path | Purpose |
|------|---------|
| (none) | All changes extend existing files |

### Modified files

| Path | Change |
|------|--------|
| `pkg/store/store.go` | Add `FilterParams`, `FilterOptions` types; update 3 method signatures; add `ListFilterOptions` |
| `pkg/store/types.go` | Add `FilterOptions` struct |
| `pkg/store/findings.go` | Implement `ListFilterOptions`; update 3 list methods with conditional WHERE |
| `pkg/server/handlers_analytics.go` | Parse query params into `FilterParams`; add `handleFilterOptions` handler |
| `pkg/server/server.go` | Register `GET /api/v1/filters` route |
| `pkg/server/ui/dist/app.js` | Add `renderFilterBar` helper; extend `renderCertificates`, `renderInventory`, `renderPriority` |
| `pkg/server/ui/dist/style.css` | Add `.filter-bar` styles |
| `test/e2e/analytics.spec.js` | Add 4 E2E filter tests |

### Files NOT touched

- `pkg/analytics/` — pure math, no filtering concern
- `pkg/store/migrations.go` — no schema changes (filters use existing columns)
- `cmd/server.go` — no new env vars or wiring
