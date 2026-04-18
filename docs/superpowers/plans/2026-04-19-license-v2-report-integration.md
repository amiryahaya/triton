# License Server v2 + Report Portal integration — PR A Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement task-by-task. Steps use `- [ ]` checkboxes.

**Goal:** Expand the License Server to support feature flags, per-metric limits (windows: total · monthly · daily), usage-tracking, and near-real-time enforcement; wire the Report Portal to activate online, push usage every 60s, and migrate hard-coded tier gating to feature flags. Ship backward-compat so existing tokens keep working.

**Architecture:** License Server gains 4 JSONB/scalar columns on `licenses` + a new `license_usage` time-series table. New HTTP endpoints: `/v1/license/activate` (extended response), `/v1/license/usage` (new), `/v1/license/validate` (extended). Consumer-side library `internal/license/` gains a usage pusher and feature-flag reader. Report Server becomes licence-required at startup, pushes usage via the new pusher, and reads feature flags instead of tiers. Retention pruner added.

**Tech Stack:** Go 1.25 (`pgx/v5`, `go-chi/chi/v5`), Postgres migrations via existing `pkg/licensestore/migrations/` pattern, Vitest for the License Admin UI (Vue 3 + `@triton/ui`), Playwright for E2E.

**Spec reference:** `docs/superpowers/specs/2026-04-19-license-v2-and-manage-portal-design.md` (commit `1f4b507`).

**Scope — this PR:** License Server schema + API v2, consumer library updates, Report Portal licence-required + usage-push + feature-flag migration + retention pruner, License Admin Vue UI updates for limits editor + usage gauges. Backward compatibility verified against pre-v2 tokens.

**Out of scope — follow-on plans:** Manage Server standalone binary (PR B), Manage Portal Vue UI (PR C).

---

## File structure — created / modified by this plan

**Created:**

```
pkg/licensestore/
  migrations/008_license_v2.up.sql
  migrations/008_license_v2.down.sql
  limits.go                       # Features / LimitEntry / limit arithmetic
  limits_test.go
  usage.go                        # license_usage table access
  usage_test.go
  compat.go                       # legacy-tier → v2 features/limits mapping
  compat_test.go

pkg/licenseserver/
  handlers_usage.go               # POST /v1/license/usage
  handlers_usage_test.go

internal/license/
  usage_pusher.go                 # 60s-tick + event-driven pusher
  usage_pusher_test.go
  features.go                     # HasFeature / LimitCap / LimitRemaining
  features_test.go

pkg/server/
  handlers_setup.go               # POST /api/v1/setup/license
  handlers_setup_test.go
  retention.go                    # daily pruner goroutine
  retention_test.go
  usage_source.go                 # read current seats/tenants/... counters
  usage_source_test.go

web/apps/license-portal/src/views/
  LicenceCreate.vue               # new — create/edit licence with limits editor
  LicenceEdit.vue                 # alias/view-mode variant
web/apps/license-portal/src/components/
  LimitsEditor.vue                # add/edit/remove limit entries
  FeatureToggles.vue              # 6 checkboxes
  UsageGauges.vue                 # bar gauges per metric

test/integration/
  license_v2_test.go              # full activate/usage/validate cycle
  report_license_v2_test.go       # Report Portal end-to-end licence flow
```

**Modified:**

```
pkg/licensestore/store.go         # Get/Put Features/Limits; product_scope
pkg/licensestore/types.go         # License struct gains Features/Limits/SoftBufferPct/ProductScope
pkg/licenseserver/handlers.go     # /activate now returns {features, limits, soft_buffer_pct, usage}
pkg/licenseserver/routes.go       # mount /v1/license/usage
pkg/licenseserver/ui.go           # no change (Vue already ships)

internal/license/client.go        # Activate/Validate response shape; Usage call added
internal/license/guard.go         # feature-flag reads; compat fallback when features empty
internal/license/cache.go         # cached token now carries features/limits

pkg/server/server.go              # licence-required startup guard; setup routing when unset
pkg/server/license.go             # LicenceGate middleware reads feature flags
pkg/server/handlers.go            # format-allowlist from features.export_formats (fallback to tier)
pkg/server/report_server.go       # ← if exists; else wherever scan-format guard lives

cmd/server/main.go                # read TRITON_REPORT_LICENSE_KEY; 503 + setup mode if unset
cmd/licenseserver/main.go         # no change

web/apps/license-portal/src/views/Licences.vue         # list shows features + primary limit
web/apps/license-portal/src/views/LicenceDetail.vue    # new tab: Usage, showing gauges
web/apps/license-portal/src/router.ts                  # add /licenses/new + /licenses/:id/edit
web/apps/license-portal/src/nav.ts                     # unchanged
web/packages/api-client/src/licenseServer.ts           # new endpoints: createLicence(features/limits), usageSummary(id)
web/packages/api-client/src/types.ts                   # Features + LimitEntry types
```

**Migrated behavior (no file rewrite, semantic only):**

- `guard.EnforceProfile` now reads `features.comprehensive_profile`; falls back to tier compat when features empty.
- `guard.EnforceFormat` reads `features.export_formats` slice.
- `LicenceGate` on `/diff` / `/trend` reads `features.diff_trend`.
- Policy builtin-vs-custom check reads `features.custom_policy`.

---

## Phase 0 — License Server database migration

### Task 0.1: Migration — add v2 columns to `licenses` table

**Files:**
- Create: `pkg/licensestore/migrations/008_license_v2.up.sql`
- Create: `pkg/licensestore/migrations/008_license_v2.down.sql`

- [ ] **Step 1: Write `008_license_v2.up.sql`**

```sql
-- License Server v2: feature flags + per-metric limits + usage tracking.

BEGIN;

ALTER TABLE licenses
    ADD COLUMN features          JSONB       NOT NULL DEFAULT '{}',
    ADD COLUMN limits            JSONB       NOT NULL DEFAULT '[]',
    ADD COLUMN soft_buffer_pct   SMALLINT    NOT NULL DEFAULT 10,
    ADD COLUMN product_scope     TEXT        NOT NULL DEFAULT 'legacy';

ALTER TABLE licenses
    ADD CONSTRAINT licenses_product_scope_check
    CHECK (product_scope IN ('legacy', 'report', 'manage', 'bundle'));

ALTER TABLE licenses
    ADD CONSTRAINT licenses_soft_buffer_pct_check
    CHECK (soft_buffer_pct BETWEEN 0 AND 25);

-- Usage time-series. Latest-value-per-key pattern with UPSERT.
CREATE TABLE license_usage (
    license_id      UUID        NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    instance_id     UUID        NOT NULL,
    metric          TEXT        NOT NULL,
    window          TEXT        NOT NULL,
    value           BIGINT      NOT NULL,
    reported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (license_id, instance_id, metric, window)
);

CREATE INDEX license_usage_reported_at_idx ON license_usage (reported_at);
CREATE INDEX license_usage_license_metric_idx ON license_usage (license_id, metric, window);

COMMIT;
```

- [ ] **Step 2: Write `008_license_v2.down.sql`**

```sql
BEGIN;

DROP TABLE IF EXISTS license_usage;

ALTER TABLE licenses
    DROP CONSTRAINT IF EXISTS licenses_soft_buffer_pct_check,
    DROP CONSTRAINT IF EXISTS licenses_product_scope_check,
    DROP COLUMN IF EXISTS product_scope,
    DROP COLUMN IF EXISTS soft_buffer_pct,
    DROP COLUMN IF EXISTS limits,
    DROP COLUMN IF EXISTS features;

COMMIT;
```

- [ ] **Step 3: Run migration against test DB, verify columns present**

```sh
make db-up
psql "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" -c "\d+ licenses" | grep -E 'features|limits|soft_buffer_pct|product_scope'
psql "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" -c "\d+ license_usage"
```

Expected: 4 new columns present with correct types; `license_usage` table with PK + 2 indexes.

- [ ] **Step 4: Run migration down + up again to verify idempotency**

```sh
# apply down.sql manually then up.sql; both should succeed and end state match step 3
```

- [ ] **Step 5: Commit**

```sh
git add pkg/licensestore/migrations/
git commit -m "feat(licensestore): v2 schema — features, limits, soft_buffer_pct, license_usage"
```

---

## Phase 1 — License model + types (Go)

### Task 1.1: Define `Features` and `LimitEntry` types

**Files:**
- Create: `pkg/licensestore/limits.go`
- Create: `pkg/licensestore/limits_test.go`
- Modify: `pkg/licensestore/types.go`

- [ ] **Step 1: Failing test** — `pkg/licensestore/limits_test.go`:

```go
package licensestore

import (
	"encoding/json"
	"testing"
)

func TestFeatures_MarshalUnmarshal(t *testing.T) {
	f := Features{
		Report:               true,
		Manage:               true,
		ComprehensiveProfile: true,
		DiffTrend:            false,
		CustomPolicy:         false,
		SSO:                  false,
		ExportFormats:        []string{"html", "pdf", "csv"},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var f2 Features
	if err := json.Unmarshal(b, &f2); err != nil {
		t.Fatal(err)
	}
	if f2.Report != f.Report || len(f2.ExportFormats) != 3 {
		t.Fatalf("roundtrip mismatch: %+v", f2)
	}
}

func TestLimitEntry_Validate(t *testing.T) {
	good := LimitEntry{Metric: "scans", Window: "monthly", Cap: 1000}
	if err := good.Validate(); err != nil {
		t.Fatalf("good entry failed validation: %v", err)
	}

	bad := []LimitEntry{
		{Metric: "unknown", Window: "total", Cap: 1},
		{Metric: "scans", Window: "yearly", Cap: 1},
		{Metric: "scans", Window: "monthly", Cap: -1},
		{Metric: "retention_days", Window: "daily", Cap: 30}, // retention only 'total'
	}
	for i, e := range bad {
		if err := e.Validate(); err == nil {
			t.Errorf("bad[%d]: expected error, got nil for %+v", i, e)
		}
	}
}

func TestLimits_Find(t *testing.T) {
	ls := Limits{
		{Metric: "scans", Window: "total", Cap: 1000000},
		{Metric: "scans", Window: "monthly", Cap: 10000},
		{Metric: "hosts", Window: "total", Cap: 500},
	}
	if e := ls.Find("scans", "monthly"); e == nil || e.Cap != 10000 {
		t.Errorf("scans/monthly: want 10000, got %+v", e)
	}
	if e := ls.Find("hosts", "daily"); e != nil {
		t.Errorf("hosts/daily: want nil, got %+v", e)
	}
}

func TestLimitEntry_BufferCeiling(t *testing.T) {
	cases := []struct {
		cap, pct int
		want     int64
	}{
		{100, 10, 110},
		{3, 10, 3}, // ceil(3 * 1.1) = 4, but integer math gives 3 due to floor strategy; spec says hard cap for small numbers — use rounding strategy: cap + floor(cap*pct/100)
		{1000, 10, 1100},
		{0, 10, 0},
		{50, 0, 50},
	}
	for _, c := range cases {
		got := LimitEntry{Cap: int64(c.cap)}.BufferCeiling(c.pct)
		if got != c.want {
			t.Errorf("cap=%d pct=%d: want %d got %d", c.cap, c.pct, c.want, got)
		}
	}
}
```

- [ ] **Step 2: Implement** — `pkg/licensestore/limits.go`:

```go
package licensestore

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Features is the set of product entitlements a licence carries.
// JSON (de)serialised as-is from the `features` JSONB column.
//
// Agent entitlement is always implicit when any licence exists and is
// therefore not represented here.
type Features struct {
	Report               bool     `json:"report"`
	Manage               bool     `json:"manage"`
	ComprehensiveProfile bool     `json:"comprehensive_profile"`
	DiffTrend            bool     `json:"diff_trend"`
	CustomPolicy         bool     `json:"custom_policy"`
	SSO                  bool     `json:"sso"`
	ExportFormats        []string `json:"export_formats,omitempty"`
}

// Has returns true if the named feature is enabled.
func (f Features) Has(name string) bool {
	switch name {
	case "report":
		return f.Report
	case "manage":
		return f.Manage
	case "comprehensive_profile":
		return f.ComprehensiveProfile
	case "diff_trend":
		return f.DiffTrend
	case "custom_policy":
		return f.CustomPolicy
	case "sso":
		return f.SSO
	default:
		return false
	}
}

// AllowsFormat is a convenience wrapper over the ExportFormats slice.
// Empty slice means no format gating (all formats allowed).
func (f Features) AllowsFormat(format string) bool {
	if len(f.ExportFormats) == 0 {
		return true
	}
	return slices.Contains(f.ExportFormats, format)
}

// LimitEntry is a single row in the limits[] JSONB array.
type LimitEntry struct {
	Metric string `json:"metric"`
	Window string `json:"window"`
	Cap    int64  `json:"cap"`
}

var validMetrics = map[string]bool{
	"seats":             true,
	"tenants":           true,
	"hosts":             true,
	"scans":             true,
	"reports_generated": true,
	"report_downloads":  true,
	"retention_days":    true,
}

var validWindows = map[string]bool{
	"total":   true,
	"daily":   true,
	"monthly": true,
}

// Validate checks the entry is well-formed.
func (e LimitEntry) Validate() error {
	if !validMetrics[e.Metric] {
		return fmt.Errorf("unknown metric %q", e.Metric)
	}
	if !validWindows[e.Window] {
		return fmt.Errorf("unknown window %q", e.Window)
	}
	if e.Cap < 0 {
		return fmt.Errorf("cap must be ≥ 0 (got %d)", e.Cap)
	}
	if e.Metric == "retention_days" && e.Window != "total" {
		return fmt.Errorf("retention_days only supports window=total")
	}
	return nil
}

// BufferCeiling returns cap + floor(cap * pct / 100) — the hard ceiling
// above which soft-enforced metrics reject new work.
func (e LimitEntry) BufferCeiling(softBufferPct int) int64 {
	return e.Cap + (e.Cap*int64(softBufferPct))/100
}

// Limits is the array of LimitEntry values stored in licenses.limits.
type Limits []LimitEntry

// Find returns the matching entry, or nil if absent (unlimited).
func (ls Limits) Find(metric, window string) *LimitEntry {
	for i := range ls {
		if ls[i].Metric == metric && ls[i].Window == window {
			return &ls[i]
		}
	}
	return nil
}

// Validate runs each entry's Validate and returns the first error.
func (ls Limits) Validate() error {
	for i, e := range ls {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("limits[%d]: %w", i, err)
		}
	}
	return nil
}

// MarshalJSON ensures nil Limits serialises as `[]`, not `null`.
func (ls Limits) MarshalJSON() ([]byte, error) {
	if ls == nil {
		return []byte(`[]`), nil
	}
	return json.Marshal([]LimitEntry(ls))
}
```

- [ ] **Step 3: Modify `pkg/licensestore/types.go`** — add fields to the `License` struct. Read the existing file first to find the struct; append after `Seats`:

```go
// License row with v2 additions.
type License struct {
	ID             string    `json:"id"`
	OrgID          string    `json:"org_id"`
	Key            string    `json:"key"`
	Tier           string    `json:"tier"`          // legacy, kept for compat
	Seats          int       `json:"seats"`         // legacy seat count
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Bound          bool      `json:"bound"`
	MachineID      string    `json:"machine_id,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	RevokedBy      *string    `json:"revoked_by,omitempty"`

	// v2 fields
	Features       Features   `json:"features"`
	Limits         Limits     `json:"limits"`
	SoftBufferPct  int        `json:"soft_buffer_pct"`
	ProductScope   string     `json:"product_scope"`
}
```

If the existing struct differs (e.g., fields named slightly differently), adapt — the key addition is the last four fields.

- [ ] **Step 4: Run tests — expect PASS**

```sh
go test ./pkg/licensestore/...
```

- [ ] **Step 5: Commit**

```sh
git add pkg/licensestore/limits.go pkg/licensestore/limits_test.go pkg/licensestore/types.go
git commit -m "feat(licensestore): Features + LimitEntry types with validation"
```

---

### Task 1.2: Store-side CRUD for new columns

**Files:**
- Modify: `pkg/licensestore/store.go` — `Create` / `Get` / `Update` methods must read/write new columns
- Modify / extend: `pkg/licensestore/store_test.go`

- [ ] **Step 1: Read existing store.go** to understand the method shape

```sh
grep -n 'INSERT INTO licenses\|SELECT.*FROM licenses\|UPDATE licenses' pkg/licensestore/store.go | head -20
```

- [ ] **Step 2: Extend `INSERT` to include new columns**

For each place `INSERT INTO licenses (...)` appears, add `features, limits, soft_buffer_pct, product_scope` to the column list and `$N, $N, $N, $N` to the VALUES. Parameters supplied from `License` struct (`l.Features`, `l.Limits`, `l.SoftBufferPct`, `l.ProductScope`).

Example pattern:

```go
const insertSQL = `
INSERT INTO licenses (
    id, org_id, key, tier, seats, issued_at, expires_at, bound, machine_id,
    features, limits, soft_buffer_pct, product_scope
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9,
    $10, $11, $12, $13
)`

// When inserting:
_, err := db.Exec(ctx, insertSQL,
    l.ID, l.OrgID, l.Key, l.Tier, l.Seats, l.IssuedAt, l.ExpiresAt, l.Bound, l.MachineID,
    l.Features, l.Limits, l.SoftBufferPct, l.ProductScope,
)
```

Note: `Features` and `Limits` have JSON methods so `pgx/v5` will serialise them via `encoding/json` automatically when the column is `JSONB`. If the driver complains, wrap in explicit `json.RawMessage`:

```go
featBytes, _ := json.Marshal(l.Features)
limBytes, _ := json.Marshal(l.Limits)
// pass as parameters with $N casts:  $10::jsonb, $11::jsonb
```

- [ ] **Step 3: Extend `SELECT`** to include the 4 new columns and scan into the struct:

```go
const selectSQL = `
SELECT id, org_id, key, tier, seats, issued_at, expires_at, bound, machine_id,
       revoked_at, revoked_by,
       features, limits, soft_buffer_pct, product_scope
FROM licenses WHERE ...`

err := row.Scan(
    &l.ID, &l.OrgID, &l.Key, &l.Tier, &l.Seats, &l.IssuedAt, &l.ExpiresAt, &l.Bound, &l.MachineID,
    &l.RevokedAt, &l.RevokedBy,
    &l.Features, &l.Limits, &l.SoftBufferPct, &l.ProductScope,
)
```

Features/Limits need `Scan` methods because pgx's default JSONB scan returns `[]byte`. Add to `limits.go`:

```go
// Scan implements the sql.Scanner interface for JSONB.
func (f *Features) Scan(src any) error {
	switch v := src.(type) {
	case []byte:
		return json.Unmarshal(v, f)
	case string:
		return json.Unmarshal([]byte(v), f)
	case nil:
		*f = Features{}
		return nil
	default:
		return fmt.Errorf("cannot scan %T into Features", src)
	}
}

// Value implements the driver.Valuer interface.
func (f Features) Value() (driver.Value, error) {
	return json.Marshal(f)
}

// Scan implements sql.Scanner for Limits.
func (ls *Limits) Scan(src any) error {
	switch v := src.(type) {
	case []byte:
		return json.Unmarshal(v, ls)
	case string:
		return json.Unmarshal([]byte(v), ls)
	case nil:
		*ls = Limits{}
		return nil
	default:
		return fmt.Errorf("cannot scan %T into Limits", src)
	}
}

// Value implements driver.Valuer for Limits.
func (ls Limits) Value() (driver.Value, error) {
	if ls == nil {
		return []byte(`[]`), nil
	}
	return json.Marshal([]LimitEntry(ls))
}
```

Add imports `database/sql/driver` and keep `encoding/json`.

- [ ] **Step 4: Add integration test** — `pkg/licensestore/store_test.go` append:

```go
//go:build integration

func TestStore_CreateGetWithV2Fields(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	defer store.Close()

	orgID := mustCreateOrg(t, store, "ACME")
	lic := License{
		ID:           uuid.NewString(),
		OrgID:        orgID,
		Key:          "ACME-BUNDLE-TEST",
		Tier:         "enterprise",
		Seats:        100,
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(365 * 24 * time.Hour),
		Bound:        false,
		ProductScope: "bundle",
		SoftBufferPct: 10,
		Features: Features{
			Report:               true,
			Manage:               true,
			ComprehensiveProfile: true,
			DiffTrend:            true,
			ExportFormats:        []string{"html", "pdf", "csv", "json", "sarif"},
		},
		Limits: Limits{
			{Metric: "seats", Window: "total", Cap: 100},
			{Metric: "scans", Window: "monthly", Cap: 10000},
			{Metric: "retention_days", Window: "total", Cap: 365},
		},
	}
	if err := store.CreateLicense(ctx, &lic); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetLicense(ctx, lic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Features.Report || !got.Features.Manage {
		t.Errorf("features round-trip failed: %+v", got.Features)
	}
	if e := got.Limits.Find("scans", "monthly"); e == nil || e.Cap != 10000 {
		t.Errorf("limits round-trip failed: %+v", got.Limits)
	}
	if got.SoftBufferPct != 10 || got.ProductScope != "bundle" {
		t.Errorf("scalar v2 fields: pct=%d scope=%q", got.SoftBufferPct, got.ProductScope)
	}
}
```

- [ ] **Step 5: Run integration tests**

```sh
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" go test -tags integration -run TestStore_CreateGetWithV2Fields ./pkg/licensestore/...
```

- [ ] **Step 6: Commit**

```sh
git add pkg/licensestore/store.go pkg/licensestore/store_test.go pkg/licensestore/limits.go
git commit -m "feat(licensestore): Create/Get licence persist v2 JSONB columns"
```

---

### Task 1.3: Legacy-tier compat mapping

**Files:**
- Create: `pkg/licensestore/compat.go`
- Create: `pkg/licensestore/compat_test.go`

- [ ] **Step 1: Failing test** — `pkg/licensestore/compat_test.go`:

```go
package licensestore

import "testing"

func TestCompatFeatures(t *testing.T) {
	tests := []struct {
		tier         string
		wantReport   bool
		wantManage   bool
		wantDiffTrend bool
		wantCompProf bool
		wantCustom   bool
	}{
		{"free", true, false, false, false, false},
		{"pro", true, false, true, true, false},
		{"enterprise", true, true, true, true, true},
	}
	for _, tt := range tests {
		f := CompatFeatures(tt.tier)
		if f.Report != tt.wantReport {
			t.Errorf("%s: Report = %v, want %v", tt.tier, f.Report, tt.wantReport)
		}
		if f.Manage != tt.wantManage {
			t.Errorf("%s: Manage = %v, want %v", tt.tier, f.Manage, tt.wantManage)
		}
		if f.DiffTrend != tt.wantDiffTrend {
			t.Errorf("%s: DiffTrend = %v, want %v", tt.tier, f.DiffTrend, tt.wantDiffTrend)
		}
		if f.ComprehensiveProfile != tt.wantCompProf {
			t.Errorf("%s: CompProfile = %v, want %v", tt.tier, f.ComprehensiveProfile, tt.wantCompProf)
		}
		if f.CustomPolicy != tt.wantCustom {
			t.Errorf("%s: CustomPolicy = %v, want %v", tt.tier, f.CustomPolicy, tt.wantCustom)
		}
	}
}

func TestCompatLimits(t *testing.T) {
	free := CompatLimits("free")
	if e := free.Find("seats", "total"); e == nil || e.Cap != 5 {
		t.Errorf("free seats: want 5, got %+v", e)
	}
	pro := CompatLimits("pro")
	if e := pro.Find("seats", "total"); e == nil || e.Cap != 50 {
		t.Errorf("pro seats: want 50, got %+v", e)
	}
	ent := CompatLimits("enterprise")
	if e := ent.Find("seats", "total"); e == nil || e.Cap != 500 {
		t.Errorf("enterprise seats: want 500, got %+v", e)
	}
	if e := ent.Find("tenants", "total"); e == nil || e.Cap != 10 {
		t.Errorf("enterprise tenants: want 10, got %+v", e)
	}
}
```

- [ ] **Step 2: Implement** — `pkg/licensestore/compat.go`:

```go
package licensestore

// CompatFeatures returns the feature set implied by a legacy tier.
// Used when a licence row has `features = '{}'` (v1 legacy) — preserves
// existing customer behaviour until re-issued as v2.
func CompatFeatures(tier string) Features {
	switch tier {
	case "free":
		return Features{
			Report:        true,
			ExportFormats: []string{"json"},
		}
	case "pro":
		return Features{
			Report:               true,
			ComprehensiveProfile: true,
			DiffTrend:            true,
			ExportFormats:        []string{"html", "pdf", "csv", "json"},
		}
	case "enterprise":
		return Features{
			Report:               true,
			Manage:               true,
			ComprehensiveProfile: true,
			DiffTrend:            true,
			CustomPolicy:         true,
			SSO:                  true,
			ExportFormats:        []string{"html", "pdf", "csv", "json", "sarif"},
		}
	default:
		return Features{}
	}
}

// CompatLimits returns the per-metric caps implied by a legacy tier.
func CompatLimits(tier string) Limits {
	switch tier {
	case "free":
		return Limits{
			{Metric: "seats", Window: "total", Cap: 5},
		}
	case "pro":
		return Limits{
			{Metric: "seats", Window: "total", Cap: 50},
		}
	case "enterprise":
		return Limits{
			{Metric: "seats", Window: "total", Cap: 500},
			{Metric: "tenants", Window: "total", Cap: 10},
		}
	default:
		return Limits{}
	}
}

// ResolveFeatures returns the licence's v2 features; if the licence has no
// v2 features set (all-false), falls back to the legacy tier compat mapping.
// This is the canonical accessor consumers should use.
func ResolveFeatures(l *License) Features {
	if featuresAnySet(l.Features) {
		return l.Features
	}
	return CompatFeatures(l.Tier)
}

// ResolveLimits returns the licence's v2 limits; falls back to the legacy
// tier compat mapping when v2 limits are empty.
func ResolveLimits(l *License) Limits {
	if len(l.Limits) > 0 {
		return l.Limits
	}
	return CompatLimits(l.Tier)
}

func featuresAnySet(f Features) bool {
	return f.Report || f.Manage || f.ComprehensiveProfile || f.DiffTrend ||
		f.CustomPolicy || f.SSO || len(f.ExportFormats) > 0
}
```

- [ ] **Step 3: Run tests — expect PASS**

```sh
go test ./pkg/licensestore/...
```

- [ ] **Step 4: Commit**

```sh
git add pkg/licensestore/compat.go pkg/licensestore/compat_test.go
git commit -m "feat(licensestore): legacy tier → v2 features/limits compat mapping"
```

---

### Task 1.4: `license_usage` store access

**Files:**
- Create: `pkg/licensestore/usage.go`
- Create: `pkg/licensestore/usage_test.go`

- [ ] **Step 1: Failing test** — `pkg/licensestore/usage_test.go`:

```go
//go:build integration

package licensestore

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUsageUpsertAndSummary(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	defer store.Close()

	orgID := mustCreateOrg(t, store, "UsageOrg")
	lic := &License{
		ID: uuid.NewString(), OrgID: orgID, Key: "K",
		Tier: "pro", Seats: 50,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		ProductScope: "bundle", SoftBufferPct: 10,
	}
	if err := store.CreateLicense(ctx, lic); err != nil {
		t.Fatal(err)
	}

	instID := uuid.NewString()
	reports := []UsageReport{
		{LicenseID: lic.ID, InstanceID: instID, Metric: "seats", Window: "total", Value: 12},
		{LicenseID: lic.ID, InstanceID: instID, Metric: "scans", Window: "monthly", Value: 150},
	}
	if err := store.UpsertUsage(ctx, reports); err != nil {
		t.Fatal(err)
	}

	// Second push overwrites.
	reports[0].Value = 13
	if err := store.UpsertUsage(ctx, reports); err != nil {
		t.Fatal(err)
	}

	sum, err := store.UsageSummary(ctx, lic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sum["seats"]["total"] != 13 {
		t.Errorf("seats/total: want 13, got %d", sum["seats"]["total"])
	}
	if sum["scans"]["monthly"] != 150 {
		t.Errorf("scans/monthly: want 150, got %d", sum["scans"]["monthly"])
	}
}
```

- [ ] **Step 2: Implement** — `pkg/licensestore/usage.go`:

```go
package licensestore

import (
	"context"
	"fmt"
	"time"
)

// UsageReport is one row in the POST /v1/license/usage body + the DB.
type UsageReport struct {
	LicenseID  string    `json:"-"`
	InstanceID string    `json:"-"`
	Metric     string    `json:"metric"`
	Window     string    `json:"window"`
	Value      int64     `json:"value"`
	ReportedAt time.Time `json:"reported_at,omitempty"`
}

// UpsertUsage writes a batch of usage reports, upserting on the composite
// PK (license_id, instance_id, metric, window). Zero-batch is a no-op.
func (s *PostgresStore) UpsertUsage(ctx context.Context, reports []UsageReport) error {
	if len(reports) == 0 {
		return nil
	}
	const sql = `
INSERT INTO license_usage (license_id, instance_id, metric, window, value, reported_at)
VALUES ($1, $2, $3, $4, $5, NOW())
ON CONFLICT (license_id, instance_id, metric, window)
DO UPDATE SET value = EXCLUDED.value, reported_at = NOW()`

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for _, r := range reports {
		if _, err := tx.Exec(ctx, sql, r.LicenseID, r.InstanceID, r.Metric, r.Window, r.Value); err != nil {
			return fmt.Errorf("upsert %s/%s: %w", r.Metric, r.Window, err)
		}
	}
	return tx.Commit(ctx)
}

// UsageSummary aggregates the latest value per (metric, window) across all
// instances of a licence. Returned as summary[metric][window] = sum.
// License Server enforces caps against this sum.
func (s *PostgresStore) UsageSummary(ctx context.Context, licenseID string) (map[string]map[string]int64, error) {
	const sql = `
SELECT metric, window, COALESCE(SUM(value), 0)
FROM license_usage
WHERE license_id = $1
GROUP BY metric, window`

	rows, err := s.pool.Query(ctx, sql, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]map[string]int64)
	for rows.Next() {
		var metric, window string
		var val int64
		if err := rows.Scan(&metric, &window, &val); err != nil {
			return nil, err
		}
		if out[metric] == nil {
			out[metric] = make(map[string]int64)
		}
		out[metric][window] = val
	}
	return out, rows.Err()
}

// UsageByInstance returns per-instance usage for observability.
func (s *PostgresStore) UsageByInstance(ctx context.Context, licenseID string) ([]UsageReport, error) {
	const sql = `
SELECT instance_id, metric, window, value, reported_at
FROM license_usage
WHERE license_id = $1
ORDER BY instance_id, metric, window`

	rows, err := s.pool.Query(ctx, sql, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UsageReport
	for rows.Next() {
		r := UsageReport{LicenseID: licenseID}
		if err := rows.Scan(&r.InstanceID, &r.Metric, &r.Window, &r.Value, &r.ReportedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
```

- [ ] **Step 3: Run integration test — expect PASS**

- [ ] **Step 4: Commit**

```sh
git add pkg/licensestore/usage.go pkg/licensestore/usage_test.go
git commit -m "feat(licensestore): UpsertUsage + UsageSummary for license_usage table"
```

---

## Phase 2 — License Server API

### Task 2.1: Extend `/v1/license/activate` response

**Files:**
- Modify: `pkg/licenseserver/handlers.go`
- Extend: `pkg/licenseserver/handlers_test.go`

- [ ] **Step 1: Find the existing activate handler**

```sh
grep -n 'activate' pkg/licenseserver/handlers.go pkg/licenseserver/routes.go
```

- [ ] **Step 2: Extend the response type**

```go
// In pkg/licenseserver/handlers.go

type ActivateResponse struct {
	OK             bool                    `json:"ok"`
	Tier           string                  `json:"tier"`              // legacy
	Features       licensestore.Features   `json:"features"`
	Limits         licensestore.Limits     `json:"limits"`
	SoftBufferPct  int                     `json:"soft_buffer_pct"`
	Usage          map[string]map[string]int64 `json:"usage"`
	GraceSeconds   int                     `json:"grace_seconds"`
	SignedToken    string                  `json:"signed_token"`
	// Back-compat — existing fields kept.
}
```

- [ ] **Step 3: In the activate handler**, after successful licence lookup + bind, call:

```go
features := licensestore.ResolveFeatures(lic)
limits := licensestore.ResolveLimits(lic)
usage, err := s.store.UsageSummary(r.Context(), lic.ID)
if err != nil {
    // log, proceed with empty usage
    usage = map[string]map[string]int64{}
}

// Enforce hard-cap check for the requested product.
if req.Product == "report" && !features.Report {
    http.Error(w, "licence does not grant report product", http.StatusForbidden)
    return
}
if req.Product == "manage" && !features.Manage {
    http.Error(w, "licence does not grant manage product", http.StatusForbidden)
    return
}

// Sign token with the v2 payload. Reuse internal/license token-signing.
tok, err := s.signV2Token(lic, features, limits)
if err != nil {
    http.Error(w, "sign token: "+err.Error(), http.StatusInternalServerError)
    return
}

json.NewEncoder(w).Encode(ActivateResponse{
    OK:            true,
    Tier:          lic.Tier,
    Features:      features,
    Limits:        limits,
    SoftBufferPct: lic.SoftBufferPct,
    Usage:         usage,
    GraceSeconds:  7 * 24 * 3600,
    SignedToken:   tok,
})
```

- [ ] **Step 4: Add `signV2Token` method** in same file or a new file `pkg/licenseserver/signing.go`. The v1 token signer already exists — extend its payload:

```go
type TokenClaims struct {
	Subject       string                `json:"sub"`
	Tier          string                `json:"tier,omitempty"`     // legacy
	Seats         int                   `json:"seats,omitempty"`    // legacy
	Features      licensestore.Features `json:"features"`
	Limits        licensestore.Limits   `json:"limits"`
	SoftBufferPct int                   `json:"sbp"`
	ProductScope  string                `json:"ps"`
	ExpiresAt     int64                 `json:"exp"`
	IssuedAt      int64                 `json:"iat"`
	MachineID     string                `json:"mid,omitempty"`
}
```

Keep the legacy `tier` + `seats` in the claims so v1 clients decoding the token still see them. Sign with the existing Ed25519 key (path `pkg/licenseserver/signing.go` or wherever `IssueToken` lives).

- [ ] **Step 5: Integration test** — extend `pkg/licenseserver/handlers_test.go`:

```go
//go:build integration

func TestActivate_ReturnsV2FieldsForBundleLicense(t *testing.T) {
    srv := setupTestServer(t)
    defer srv.Close()

    lic := seedV2Licence(t, srv, licensestore.Features{Report: true, Manage: true, DiffTrend: true},
        licensestore.Limits{{Metric: "seats", Window: "total", Cap: 100}})

    body, _ := json.Marshal(map[string]any{
        "license_key": lic.Key,
        "instance_id": uuid.NewString(),
        "product":     "report",
        "fingerprint": "abc",
    })
    resp, err := http.Post(srv.URL+"/v1/license/activate", "application/json", bytes.NewReader(body))
    if err != nil {
        t.Fatal(err)
    }
    if resp.StatusCode != 200 {
        t.Fatalf("status %d", resp.StatusCode)
    }
    var out ActivateResponse
    _ = json.NewDecoder(resp.Body).Decode(&out)
    if !out.Features.Report {
        t.Errorf("features.report should be true")
    }
    if e := out.Limits.Find("seats", "total"); e == nil || e.Cap != 100 {
        t.Errorf("limits seats/total: %+v", e)
    }
    if out.SignedToken == "" {
        t.Errorf("signed_token empty")
    }
}
```

- [ ] **Step 6: Commit**

```sh
git add pkg/licenseserver/handlers.go pkg/licenseserver/handlers_test.go pkg/licenseserver/signing.go
git commit -m "feat(licenseserver): /v1/license/activate returns v2 features+limits+usage"
```

---

### Task 2.2: New `/v1/license/usage` endpoint

**Files:**
- Create: `pkg/licenseserver/handlers_usage.go`
- Create: `pkg/licenseserver/handlers_usage_test.go`
- Modify: `pkg/licenseserver/routes.go`

- [ ] **Step 1: Failing test** — `handlers_usage_test.go`:

```go
//go:build integration

package licenseserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

func TestUsagePost_UpsertsAndReturnsRemaining(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	lic := seedV2Licence(t, srv, licensestore.Features{Report: true},
		licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 50},
			{Metric: "scans", Window: "monthly", Cap: 1000},
		})

	body, _ := json.Marshal(map[string]any{
		"license_key": lic.Key,
		"instance_id": uuid.NewString(),
		"metrics": []map[string]any{
			{"metric": "seats", "window": "total", "value": 12},
			{"metric": "scans", "window": "monthly", "value": 45},
		},
	})
	resp, err := http.Post(srv.URL+"/v1/license/usage", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out UsageResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if !out.OK {
		t.Errorf("ok false")
	}
	if got := out.Remaining["seats"]["total"]; got != 38 {
		t.Errorf("seats remaining: want 38, got %d", got)
	}
	if got := out.Remaining["scans"]["monthly"]; got != 955 {
		t.Errorf("scans remaining: want 955, got %d", got)
	}
}

func TestUsagePost_ReturnsOverCap(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	lic := seedV2Licence(t, srv, licensestore.Features{Report: true},
		licensestore.Limits{{Metric: "seats", Window: "total", Cap: 10}})

	body, _ := json.Marshal(map[string]any{
		"license_key": lic.Key,
		"instance_id": uuid.NewString(),
		"metrics": []map[string]any{
			{"metric": "seats", "window": "total", "value": 12},
		},
	})
	resp, _ := http.Post(srv.URL+"/v1/license/usage", "application/json", bytes.NewReader(body))
	var out UsageResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if len(out.OverCap) != 1 || out.OverCap[0].Metric != "seats" {
		t.Errorf("over_cap not flagged: %+v", out.OverCap)
	}
}
```

- [ ] **Step 2: Implement** — `handlers_usage.go`:

```go
package licenseserver

import (
	"encoding/json"
	"net/http"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

type UsageRequest struct {
	LicenseKey string                    `json:"license_key"`
	InstanceID string                    `json:"instance_id"`
	Metrics    []licensestore.UsageReport `json:"metrics"`
}

type OverCapRef struct {
	Metric string `json:"metric"`
	Window string `json:"window"`
}

type UsageResponse struct {
	OK        bool                         `json:"ok"`
	Remaining map[string]map[string]int64  `json:"remaining"`
	OverCap   []OverCapRef                 `json:"over_cap"`
	InBuffer  []OverCapRef                 `json:"in_buffer"`
}

func (s *Server) handleUsagePost(w http.ResponseWriter, r *http.Request) {
	var req UsageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.LicenseKey == "" || req.InstanceID == "" {
		http.Error(w, "license_key and instance_id required", http.StatusBadRequest)
		return
	}

	lic, err := s.store.GetLicenseByKey(r.Context(), req.LicenseKey)
	if err != nil {
		http.Error(w, "licence not found", http.StatusNotFound)
		return
	}

	// Stamp each report with ID + instance.
	for i := range req.Metrics {
		req.Metrics[i].LicenseID = lic.ID
		req.Metrics[i].InstanceID = req.InstanceID
	}
	if err := s.store.UpsertUsage(r.Context(), req.Metrics); err != nil {
		http.Error(w, "upsert: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Compute remaining + over-cap per metric.
	summary, err := s.store.UsageSummary(r.Context(), lic.ID)
	if err != nil {
		http.Error(w, "summary: "+err.Error(), http.StatusInternalServerError)
		return
	}
	limits := licensestore.ResolveLimits(lic)

	remaining := make(map[string]map[string]int64)
	var overCap, inBuffer []OverCapRef
	for _, e := range limits {
		current := summary[e.Metric][e.Window]
		if remaining[e.Metric] == nil {
			remaining[e.Metric] = make(map[string]int64)
		}
		r := e.Cap - current
		if r < 0 {
			r = 0
		}
		remaining[e.Metric][e.Window] = r

		if current > e.Cap {
			if current > e.BufferCeiling(lic.SoftBufferPct) {
				overCap = append(overCap, OverCapRef{e.Metric, e.Window})
			} else {
				inBuffer = append(inBuffer, OverCapRef{e.Metric, e.Window})
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UsageResponse{
		OK:        true,
		Remaining: remaining,
		OverCap:   overCap,
		InBuffer:  inBuffer,
	})
}
```

- [ ] **Step 3: Mount route** — in `pkg/licenseserver/routes.go`:

```go
// Inside registerClientRoutes or equivalent — NO admin-key gate; activation
// + usage are secured by the license-key + instance_id combination.
r.Post("/v1/license/usage", s.handleUsagePost)
```

- [ ] **Step 4: Run integration tests — expect PASS**

- [ ] **Step 5: Commit**

```sh
git add pkg/licenseserver/handlers_usage.go pkg/licenseserver/handlers_usage_test.go pkg/licenseserver/routes.go
git commit -m "feat(licenseserver): POST /v1/license/usage for near-real-time push"
```

---

### Task 2.3: Extend `/v1/license/validate` response

**Files:**
- Modify: `pkg/licenseserver/handlers.go` (validate handler)

- [ ] **Step 1: Update response shape to match Activate (minus SignedToken)**

Add `Features`, `Limits`, `SoftBufferPct`, and `Usage` to the existing validate response. Clients can then compare their cached token's features/limits against server-side authoritative values.

```go
type ValidateResponse struct {
	OK            bool                       `json:"ok"`
	Tier          string                     `json:"tier"`
	Features      licensestore.Features      `json:"features"`
	Limits        licensestore.Limits        `json:"limits"`
	SoftBufferPct int                        `json:"soft_buffer_pct"`
	Usage         map[string]map[string]int64 `json:"usage"`
}
```

In the handler, after loading the licence:

```go
features := licensestore.ResolveFeatures(lic)
limits := licensestore.ResolveLimits(lic)
usage, _ := s.store.UsageSummary(r.Context(), lic.ID)

json.NewEncoder(w).Encode(ValidateResponse{
    OK: true,
    Tier: lic.Tier,
    Features: features,
    Limits: limits,
    SoftBufferPct: lic.SoftBufferPct,
    Usage: usage,
})
```

- [ ] **Step 2: Commit**

```sh
git add pkg/licenseserver/handlers.go
git commit -m "feat(licenseserver): /v1/license/validate includes v2 fields"
```

---

## Phase 3 — Consumer-side library (`internal/license/`)

### Task 3.1: `features.go` helpers

**Files:**
- Create: `internal/license/features.go`
- Create: `internal/license/features_test.go`

- [ ] **Step 1: Test** — `features_test.go`:

```go
package license

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

func TestGuard_HasFeature(t *testing.T) {
	g := &Guard{
		features: licensestore.Features{Report: true, DiffTrend: true},
	}
	if !g.HasFeature("report") {
		t.Errorf("report should be true")
	}
	if g.HasFeature("manage") {
		t.Errorf("manage should be false")
	}
}

func TestGuard_LimitCap(t *testing.T) {
	g := &Guard{
		limits: licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 100},
		},
	}
	if cap := g.LimitCap("seats", "total"); cap != 100 {
		t.Errorf("seats cap: want 100, got %d", cap)
	}
	if cap := g.LimitCap("hosts", "total"); cap != -1 {
		t.Errorf("hosts unlimited: want -1, got %d", cap)
	}
}

func TestGuard_CompatFallback(t *testing.T) {
	// Legacy token with only tier set — features empty.
	g := &Guard{tier: "pro"}
	if !g.HasFeature("diff_trend") {
		t.Errorf("pro tier should grant diff_trend via compat")
	}
}
```

- [ ] **Step 2: Implement** — `internal/license/features.go`:

```go
package license

import "github.com/amiryahaya/triton/pkg/licensestore"

// HasFeature consults features (v2) first; falls back to legacy tier mapping.
func (g *Guard) HasFeature(name string) bool {
	// v2 path.
	if featuresAnySet(g.features) {
		return g.features.Has(name)
	}
	// v1 compat path.
	return licensestore.CompatFeatures(g.tier).Has(name)
}

// LimitCap returns the cap for a metric/window, or -1 if unlimited.
func (g *Guard) LimitCap(metric, window string) int64 {
	limits := g.limits
	if len(limits) == 0 {
		limits = licensestore.CompatLimits(g.tier)
	}
	if e := limits.Find(metric, window); e != nil {
		return e.Cap
	}
	return -1
}

// SoftBufferCeiling returns the hard ceiling for a soft-enforced metric,
// taking into account the licence's soft_buffer_pct.
func (g *Guard) SoftBufferCeiling(metric, window string) int64 {
	cap := g.LimitCap(metric, window)
	if cap < 0 {
		return -1
	}
	pct := g.softBufferPct
	if pct == 0 {
		pct = 10
	}
	return cap + (cap*int64(pct))/100
}

// AllowsFormat returns whether a report format is permitted.
func (g *Guard) AllowsFormat(format string) bool {
	if featuresAnySet(g.features) {
		return g.features.AllowsFormat(format)
	}
	return licensestore.CompatFeatures(g.tier).AllowsFormat(format)
}

func featuresAnySet(f licensestore.Features) bool {
	return f.Report || f.Manage || f.ComprehensiveProfile || f.DiffTrend ||
		f.CustomPolicy || f.SSO || len(f.ExportFormats) > 0
}
```

- [ ] **Step 3: Add fields to the `Guard` struct** (in `internal/license/guard.go`):

```go
type Guard struct {
    // existing fields (tier, seats, machineID, expiry, etc.)
    tier          string
    features      licensestore.Features
    limits        licensestore.Limits
    softBufferPct int
    // ...
}
```

And ensure the Guard constructors set these from the token claims.

- [ ] **Step 4: Run unit tests — expect PASS**

```sh
go test ./internal/license/...
```

- [ ] **Step 5: Commit**

```sh
git add internal/license/features.go internal/license/features_test.go internal/license/guard.go
git commit -m "feat(license): Guard.HasFeature/LimitCap with compat fallback"
```

---

### Task 3.2: Usage pusher

**Files:**
- Create: `internal/license/usage_pusher.go`
- Create: `internal/license/usage_pusher_test.go`

- [ ] **Step 1: Test** — `usage_pusher_test.go`:

```go
package license

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestUsagePusher_PushesOnTick(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["license_key"] != "K" {
			t.Errorf("license_key not forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"remaining":{},"over_cap":[],"in_buffer":[]}`))
	}))
	defer srv.Close()

	source := func() []UsageMetric {
		return []UsageMetric{{Metric: "seats", Window: "total", Value: 7}}
	}
	p := NewUsagePusher(UsagePusherConfig{
		LicenseServer: srv.URL,
		LicenseKey:    "K",
		InstanceID:    "i",
		Source:        source,
		Interval:      50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)
	time.Sleep(180 * time.Millisecond)
	cancel()

	got := atomic.LoadInt64(&hits)
	if got < 2 {
		t.Errorf("expected ≥2 pushes, got %d", got)
	}
}

func TestUsagePusher_PushNow(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte(`{"ok":true,"remaining":{},"over_cap":[],"in_buffer":[]}`))
	}))
	defer srv.Close()

	p := NewUsagePusher(UsagePusherConfig{
		LicenseServer: srv.URL,
		LicenseKey:    "K",
		InstanceID:    "i",
		Source:        func() []UsageMetric { return nil },
		Interval:      time.Hour, // no tick pushes in this test
	})
	ctx, cancel := context.WithCancel(context.Background())
	go p.Run(ctx)

	time.Sleep(20 * time.Millisecond) // let Run start
	p.PushNow()
	time.Sleep(50 * time.Millisecond)
	cancel()

	if atomic.LoadInt64(&hits) != 1 {
		t.Errorf("PushNow should trigger exactly 1 push")
	}
}
```

- [ ] **Step 2: Implement** — `internal/license/usage_pusher.go`:

```go
package license

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// UsageMetric is one reported value from the consumer to the licence server.
type UsageMetric struct {
	Metric string `json:"metric"`
	Window string `json:"window"`
	Value  int64  `json:"value"`
}

type UsageSource func() []UsageMetric

type UsagePusherConfig struct {
	LicenseServer string
	LicenseKey    string
	InstanceID    string
	Source        UsageSource
	Interval      time.Duration // default 60s
	HTTPClient    *http.Client
}

type UsagePusher struct {
	cfg     UsagePusherConfig
	trigger chan struct{}
}

func NewUsagePusher(cfg UsagePusherConfig) *UsagePusher {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &UsagePusher{
		cfg:     cfg,
		trigger: make(chan struct{}, 1),
	}
}

// Run blocks until ctx is cancelled, pushing usage every Interval plus any
// immediate trigger from PushNow.
func (p *UsagePusher) Run(ctx context.Context) {
	tick := time.NewTicker(p.cfg.Interval)
	defer tick.Stop()

	// Initial push so limit-deltas are visible as soon as the process starts.
	p.push(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.push(ctx)
		case <-p.trigger:
			p.push(ctx)
		}
	}
}

// PushNow schedules an immediate push (non-blocking). Used on limit-sensitive
// events (tenant created, scan completed, etc.) to surface changes to the
// licence server without waiting for the next tick.
func (p *UsagePusher) PushNow() {
	select {
	case p.trigger <- struct{}{}:
	default:
	}
}

func (p *UsagePusher) push(ctx context.Context) {
	metrics := p.cfg.Source()
	body, err := json.Marshal(map[string]any{
		"license_key": p.cfg.LicenseKey,
		"instance_id": p.cfg.InstanceID,
		"metrics":     metrics,
	})
	if err != nil {
		log.Printf("license usage push: marshal: %v", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/v1/license/usage", p.cfg.LicenseServer),
		bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		log.Printf("license usage push: %v", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 200 {
		log.Printf("license usage push: status %d", resp.StatusCode)
	}
}
```

- [ ] **Step 3: Run unit tests — expect PASS**

- [ ] **Step 4: Commit**

```sh
git add internal/license/usage_pusher.go internal/license/usage_pusher_test.go
git commit -m "feat(license): UsagePusher with 60s tick + PushNow trigger"
```

---

### Task 3.3: Wire the v2 token into `guard.go` + `cache.go`

**Files:**
- Modify: `internal/license/guard.go`
- Modify: `internal/license/cache.go`

- [ ] **Step 1:** Read existing guard.go / cache.go to see token decode path:

```sh
grep -n 'DecodeToken\|ParseClaims\|unmarshal' internal/license/*.go
```

- [ ] **Step 2:** In the token-claims struct, add the v2 fields:

```go
type tokenClaims struct {
    Sub           string                  `json:"sub"`
    Tier          string                  `json:"tier,omitempty"`
    Seats         int                     `json:"seats,omitempty"`
    Features      licensestore.Features   `json:"features,omitempty"`
    Limits        licensestore.Limits     `json:"limits,omitempty"`
    SoftBufferPct int                     `json:"sbp,omitempty"`
    ProductScope  string                  `json:"ps,omitempty"`
    Expires       int64                   `json:"exp"`
    IssuedAt      int64                   `json:"iat,omitempty"`
    MachineID     string                  `json:"mid,omitempty"`
}
```

- [ ] **Step 3:** After decoding a token, populate the Guard's v2 fields:

```go
g := &Guard{
    tier:          claims.Tier,
    seats:         claims.Seats,
    features:      claims.Features,
    limits:        claims.Limits,
    softBufferPct: claims.SoftBufferPct,
    // ...
}
```

- [ ] **Step 4:** In `cache.go`, extend `CacheMeta` JSON to persist v2 fields so the offline-grace cached token survives a restart with full fidelity. Fields: `features`, `limits`, `soft_buffer_pct`, `product_scope`.

- [ ] **Step 5:** Write a round-trip test verifying a v2 token encodes → signs → decodes → gives the right Guard.

- [ ] **Step 6: Commit**

```sh
git add internal/license/guard.go internal/license/cache.go internal/license/guard_test.go internal/license/cache_test.go
git commit -m "feat(license): v2 token claims flow through Guard and offline cache"
```

---

## Phase 4 — Report Portal integration

### Task 4.1: Usage source — seat/tenant/scan/report counters

**Files:**
- Create: `pkg/server/usage_source.go`
- Create: `pkg/server/usage_source_test.go`

- [ ] **Step 1: Test** — `usage_source_test.go`:

```go
//go:build integration

func TestUsageSource_ReportsAllMetrics(t *testing.T) {
    ctx := context.Background()
    store := openTestStore(t)
    defer store.Close()
    seedTestData(t, store) // 3 tenants, 42 scans this month, 5 reports, etc.

    src := NewUsageSource(store)
    metrics := src.Collect(ctx)

    find := func(m, w string) *UsageMetric {
        for i := range metrics { if metrics[i].Metric == m && metrics[i].Window == w { return &metrics[i] } }
        return nil
    }

    if find("tenants", "total").Value != 3 { t.Errorf("tenants") }
    if find("scans", "monthly").Value != 42 { t.Errorf("scans monthly") }
    if find("reports_generated", "total").Value != 5 { t.Errorf("reports") }
}
```

- [ ] **Step 2: Implement** — `usage_source.go`:

```go
package server

import (
    "context"
    "time"
    "github.com/amiryahaya/triton/internal/license"
    "github.com/amiryahaya/triton/pkg/store"
)

type UsageSource struct {
    store store.Store
}

func NewUsageSource(s store.Store) *UsageSource { return &UsageSource{store: s} }

// Collect returns the current count for every metric the licence server
// cares about. Returns nil entries for metrics with no cap (caller filters).
func (u *UsageSource) Collect(ctx context.Context) []license.UsageMetric {
    var out []license.UsageMetric

    if v, err := u.store.CountActiveSeats(ctx); err == nil {
        out = append(out, license.UsageMetric{Metric: "seats", Window: "total", Value: v})
    }
    if v, err := u.store.CountActiveTenants(ctx); err == nil {
        out = append(out, license.UsageMetric{Metric: "tenants", Window: "total", Value: v})
    }

    if v, err := u.store.CountScansSince(ctx, monthStart()); err == nil {
        out = append(out, license.UsageMetric{Metric: "scans", Window: "monthly", Value: v})
    }
    if v, err := u.store.CountScansSince(ctx, time.Time{}); err == nil {
        out = append(out, license.UsageMetric{Metric: "scans", Window: "total", Value: v})
    }

    if v, err := u.store.CountReportsGenerated(ctx, time.Time{}); err == nil {
        out = append(out, license.UsageMetric{Metric: "reports_generated", Window: "total", Value: v})
    }
    if v, err := u.store.CountReportDownloads(ctx, time.Time{}); err == nil {
        out = append(out, license.UsageMetric{Metric: "report_downloads", Window: "total", Value: v})
    }

    return out
}

func monthStart() time.Time {
    n := time.Now().UTC()
    return time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC)
}
```

- [ ] **Step 3: Add matching store methods** — in `pkg/store/postgres.go`:

```go
func (s *PostgresStore) CountActiveSeats(ctx context.Context) (int64, error) {
    var n int64
    err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_activations WHERE revoked_at IS NULL`).Scan(&n)
    return n, err
}
func (s *PostgresStore) CountActiveTenants(ctx context.Context) (int64, error) {
    var n int64
    err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL`).Scan(&n)
    return n, err
}
func (s *PostgresStore) CountScansSince(ctx context.Context, since time.Time) (int64, error) {
    var n int64
    err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM scans WHERE submitted_at >= $1`, since).Scan(&n)
    return n, err
}
func (s *PostgresStore) CountReportsGenerated(ctx context.Context, since time.Time) (int64, error) {
    var n int64
    err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM reports WHERE generated_at >= $1`, since).Scan(&n)
    return n, err
}
func (s *PostgresStore) CountReportDownloads(ctx context.Context, since time.Time) (int64, error) {
    var n int64
    err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM report_downloads WHERE downloaded_at >= $1`, since).Scan(&n)
    return n, err
}
```

If `report_downloads` table doesn't exist yet, add a migration: `CREATE TABLE report_downloads (id UUID PRIMARY KEY, report_id UUID, tenant_id UUID, downloaded_by UUID, downloaded_at TIMESTAMPTZ DEFAULT NOW())`. Instrument the download handler to INSERT.

- [ ] **Step 4: Add Store interface methods** — in `pkg/store/store.go`, add the 5 count methods to the interface.

- [ ] **Step 5: Integration test — expect PASS**

- [ ] **Step 6: Commit**

```sh
git add pkg/server/usage_source.go pkg/server/usage_source_test.go pkg/store/postgres.go pkg/store/store.go pkg/store/migrations/
git commit -m "feat(server): UsageSource collects seats/tenants/scans/reports counters"
```

---

### Task 4.2: Licence-required startup + setup endpoint

**Files:**
- Create: `pkg/server/handlers_setup.go`
- Create: `pkg/server/handlers_setup_test.go`
- Modify: `cmd/server/main.go`
- Modify: `pkg/server/server.go`

- [ ] **Step 1:** Add setup state to `Server` struct:

```go
type Server struct {
    // ...existing...
    licenceActivated bool          // true once setup completed
    licenceGuard     *license.Guard // may be nil during setup
}
```

- [ ] **Step 2:** In `cmd/server/main.go`:

```go
licenceKey := os.Getenv("TRITON_REPORT_LICENSE_KEY")
licenceServerURL := os.Getenv("TRITON_REPORT_LICENSE_SERVER")

if licenceKey == "" {
    log.Println("TRITON_REPORT_LICENSE_KEY unset — Report Server starts in setup mode")
    // Serve only /api/v1/setup/license + /ui/#/setup
    srv.setSetupMode()
} else {
    // Activate online, start usage pusher, instantiate guard.
    g, err := activateOnStartup(ctx, licenceKey, licenceServerURL, srv)
    if err != nil {
        log.Fatalf("licence activation failed: %v", err)
    }
    srv.setLicenceGuard(g)
    startUsagePusher(ctx, g, srv)
}
```

- [ ] **Step 3:** Setup handler `pkg/server/handlers_setup.go`:

```go
package server

import (
    "context"
    "encoding/json"
    "net/http"
    "github.com/amiryahaya/triton/internal/license"
)

type SetupLicenseRequest struct {
    LicenseKey     string `json:"license_key"`
    LicenseServer  string `json:"license_server"`
}
type SetupLicenseResponse struct {
    OK       bool               `json:"ok"`
    Features license.Features   `json:"features"`
    Limits   license.Limits     `json:"limits"`
}

func (s *Server) handleSetupLicence(w http.ResponseWriter, r *http.Request) {
    if s.licenceActivated {
        http.Error(w, "already activated", http.StatusConflict)
        return
    }
    var req SetupLicenseRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    client := license.NewServerClient(req.LicenseServer)
    resp, err := client.Activate(r.Context(), license.ActivateRequest{
        LicenseKey:  req.LicenseKey,
        InstanceID:  s.instanceID,
        Product:     "report",
        Fingerprint: license.MachineFingerprint(),
    })
    if err != nil {
        http.Error(w, "activation failed: "+err.Error(), http.StatusBadRequest)
        return
    }
    // Persist the signed token + URL to disk for restart.
    if err := persistLicenceConfig(req.LicenseServer, req.LicenseKey, resp.SignedToken); err != nil {
        http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
        return
    }
    g := license.NewGuardFromToken(resp.SignedToken)
    s.setLicenceGuard(g)
    s.licenceActivated = true
    startUsagePusher(r.Context(), g, s)

    _ = json.NewEncoder(w).Encode(SetupLicenseResponse{OK: true, Features: g.Features(), Limits: g.Limits()})
}
```

- [ ] **Step 4:** Mount the route in `server.go`. Setup endpoint is unauthenticated (needs to work before any admin user exists).

- [ ] **Step 5:** Add a middleware that returns 503 with JSON `{"setup_required": true}` for all `/api/v1/*` paths EXCEPT `/api/v1/setup/*` when `s.licenceActivated == false`.

- [ ] **Step 6: Test + commit**

```sh
git add pkg/server/handlers_setup.go pkg/server/handlers_setup_test.go pkg/server/server.go cmd/server/main.go
git commit -m "feat(server): licence-required startup + /api/v1/setup/license"
```

---

### Task 4.3: Wire the usage pusher into Report Server

**Files:**
- Modify: `pkg/server/server.go` (or wherever the server start lifecycle lives)

- [ ] **Step 1:** Construct the pusher at startup (or at setup completion):

```go
func startUsagePusher(ctx context.Context, g *license.Guard, s *Server) {
    src := NewUsageSource(s.store)
    pusher := license.NewUsagePusher(license.UsagePusherConfig{
        LicenseServer: g.LicenseServerURL(),
        LicenseKey:    g.Key(),
        InstanceID:    s.instanceID,
        Source:        src.Collect,
        Interval:      60 * time.Second,
    })
    go pusher.Run(ctx)
    s.licencePusher = pusher  // store reference so handlers can call PushNow()
}
```

- [ ] **Step 2:** Wire `PushNow()` into tenant-create, scan-submit, report-generate handlers (after they successfully write to DB):

```go
// e.g. in handleCreateTenant:
if err := s.store.CreateTenant(ctx, t); err != nil { ... }
if s.licencePusher != nil { s.licencePusher.PushNow() }
```

- [ ] **Step 3: Commit**

```sh
git commit -am "feat(server): wire UsagePusher into tenant/scan/report handlers"
```

---

### Task 4.4: Feature-flag migration for profile / diff-trend / exports

**Files:**
- Modify: `internal/license/guard.go` — rewrite `EnforceProfile`, `EnforceFormat`, keep legacy as fallback
- Modify: `pkg/server/license.go` — `LicenceGate` middleware uses `g.HasFeature("diff_trend")`
- Modify: `pkg/policy/engine.go` — builtin-vs-custom uses `g.HasFeature("custom_policy")`

- [ ] **Step 1:** `EnforceProfile`:

```go
func (g *Guard) EnforceProfile(profile string) error {
    if profile == "comprehensive" && !g.HasFeature("comprehensive_profile") {
        return ErrProfileNotAllowed
    }
    // quick, standard always allowed
    return nil
}
```

- [ ] **Step 2:** `EnforceFormat`:

```go
func (g *Guard) EnforceFormat(format string) error {
    if !g.AllowsFormat(format) {
        return fmt.Errorf("format %q not allowed by licence", format)
    }
    return nil
}
```

- [ ] **Step 3:** `LicenceGate` middleware:

```go
func (g *Guard) LicenceGateForPath(path string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if strings.HasPrefix(path, "/diff") || strings.HasPrefix(path, "/trend") {
                if !g.HasFeature("diff_trend") {
                    http.Error(w, "diff/trend requires higher-tier licence", http.StatusForbidden)
                    return
                }
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

- [ ] **Step 4: Tests** — add to existing `guard_test.go` + `license_test.go` (integration):

```go
func TestEnforceProfile_ViaFeature(t *testing.T) {
    g := &Guard{features: licensestore.Features{ComprehensiveProfile: false}}
    if err := g.EnforceProfile("comprehensive"); err == nil {
        t.Errorf("should reject comprehensive without feature")
    }
    g.features.ComprehensiveProfile = true
    if err := g.EnforceProfile("comprehensive"); err != nil {
        t.Errorf("should accept: %v", err)
    }
}
```

- [ ] **Step 5: Commit**

```sh
git commit -am "feat(license): EnforceProfile/Format/LicenceGate read feature flags (compat-safe)"
```

---

### Task 4.5: Retention pruner

**Files:**
- Create: `pkg/server/retention.go`
- Create: `pkg/server/retention_test.go`
- Modify: `pkg/server/server.go` (start the pruner goroutine)

- [ ] **Step 1: Test**:

```go
//go:build integration

func TestRetentionPruner_DeletesOldData(t *testing.T) {
    ctx := context.Background()
    store := openTestStore(t)
    defer store.Close()

    // Seed: 1 scan 400 days old, 1 scan 10 days old.
    oldScan := seedScan(t, store, time.Now().Add(-400*24*time.Hour))
    newScan := seedScan(t, store, time.Now().Add(-10*24*time.Hour))

    p := NewRetentionPruner(store, 365)
    if err := p.RunOnce(ctx); err != nil {
        t.Fatal(err)
    }

    if _, err := store.GetScan(ctx, oldScan); err == nil {
        t.Errorf("old scan should be pruned")
    }
    if _, err := store.GetScan(ctx, newScan); err != nil {
        t.Errorf("new scan should be kept: %v", err)
    }
}
```

- [ ] **Step 2: Implement** — `retention.go`:

```go
package server

import (
    "context"
    "log"
    "time"
    "github.com/amiryahaya/triton/pkg/store"
)

type RetentionPruner struct {
    store          store.Store
    retentionDays  int
}

func NewRetentionPruner(s store.Store, days int) *RetentionPruner {
    return &RetentionPruner{store: s, retentionDays: days}
}

func (p *RetentionPruner) RunOnce(ctx context.Context) error {
    cutoff := time.Now().Add(-time.Duration(p.retentionDays) * 24 * time.Hour)

    if n, err := p.store.PruneScansBefore(ctx, cutoff); err != nil {
        return err
    } else {
        log.Printf("retention: pruned %d scans older than %d days", n, p.retentionDays)
    }
    if n, err := p.store.PruneReportsBefore(ctx, cutoff); err != nil {
        return err
    } else {
        log.Printf("retention: pruned %d reports older than %d days", n, p.retentionDays)
    }
    return nil
}

// RunDaily blocks until ctx is cancelled; runs the pruner once per day.
func (p *RetentionPruner) RunDaily(ctx context.Context) {
    if err := p.RunOnce(ctx); err != nil {
        log.Printf("retention first-run: %v", err)
    }
    t := time.NewTicker(24 * time.Hour)
    defer t.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-t.C:
            if err := p.RunOnce(ctx); err != nil {
                log.Printf("retention: %v", err)
            }
        }
    }
}
```

- [ ] **Step 3:** Add `PruneScansBefore` / `PruneReportsBefore` to Store interface + Postgres implementation.

- [ ] **Step 4:** Start it from `server.go`:

```go
days := g.LimitCap("retention_days", "total")
if days <= 0 {
    days = 365 // sensible default
}
p := NewRetentionPruner(s.store, int(days))
go p.RunDaily(ctx)
```

- [ ] **Step 5: Commit**

```sh
git commit -am "feat(server): retention pruner — daily DELETE scans+reports older than licence cap"
```

---

## Phase 5 — License Admin Vue UI updates

### Task 5.1: API client + types for v2

**Files:**
- Modify: `web/packages/api-client/src/types.ts`
- Modify: `web/packages/api-client/src/licenseServer.ts`

- [ ] **Step 1:** Add to `types.ts`:

```ts
export interface Features {
  report: boolean;
  manage: boolean;
  comprehensive_profile: boolean;
  diff_trend: boolean;
  custom_policy: boolean;
  sso: boolean;
  export_formats: string[];
}

export type LimitWindow = 'total' | 'daily' | 'monthly';
export type LimitMetric =
  | 'seats' | 'tenants' | 'hosts' | 'scans'
  | 'reports_generated' | 'report_downloads' | 'retention_days';

export interface LimitEntry {
  metric: LimitMetric;
  window: LimitWindow;
  cap: number;
}

// Extend existing Licence
export interface Licence {
  // existing fields...
  features?: Features;
  limits?: LimitEntry[];
  soft_buffer_pct?: number;
  product_scope?: 'legacy' | 'report' | 'manage' | 'bundle';
}

export interface UsageSummary {
  [metric: string]: { [window: string]: number };
}
```

- [ ] **Step 2:** Add to `licenseServer.ts`:

```ts
export function createLicenseApi(http: Http) {
  return {
    // ...existing...
    createLicence: (body: {
      org_id: string;
      tier?: string; // legacy tier for compat
      product_scope: 'report' | 'manage' | 'bundle';
      features: Features;
      limits: LimitEntry[];
      soft_buffer_pct: number;
      expires_at: string;
    }) => http.post<Licence>('/v1/licenses', body),

    usageSummary: (id: string) => http.get<UsageSummary>(`/v1/licenses/${id}/usage`),
  };
}
```

- [ ] **Step 3:** Vitest types smoke + commit.

---

### Task 5.2: `<FeatureToggles>` + `<LimitsEditor>` components

**Files:**
- Create: `web/apps/license-portal/src/components/FeatureToggles.vue`
- Create: `web/apps/license-portal/src/components/LimitsEditor.vue`

(Scoped to license-portal app rather than `@triton/ui` because they're product-specific forms, not library atoms.)

- [ ] **Step 1: `FeatureToggles.vue`** — 6 labelled `TToggle`s (report, manage, comprehensive_profile, diff_trend, custom_policy, sso) + a multi-check for export formats. `v-model:modelValue` binds to a `Features` object.

- [ ] **Step 2: `LimitsEditor.vue`** — a `TDataTable` showing current limits with `+ Add limit` button that opens a small inline form (`TSelect` metric, `TSelect` window, `TInput` cap). Delete button per row. `v-model:modelValue` binds to `LimitEntry[]`.

- [ ] **Step 3:** Unit tests via `@vue/test-utils` — add/remove/edit round-trip.

- [ ] **Step 4: Commit**

---

### Task 5.3: Create / edit licence view

**Files:**
- Create: `web/apps/license-portal/src/views/LicenceCreate.vue`
- Create: `web/apps/license-portal/src/views/LicenceEdit.vue` (thin wrapper — same form, PUT instead of POST)
- Modify: `web/apps/license-portal/src/router.ts`

- [ ] **Step 1:** Form composes `TFormField` + `<FeatureToggles>` + `<LimitsEditor>` + `TSlider` (or TInput number) for soft_buffer_pct. Submit calls `createLicence` or `updateLicence`. Success toasts + redirect to `/licenses/:id`.

- [ ] **Step 2:** Router entry: `{ path: '/licenses/new', component: LicenceCreate }`, `{ path: '/licenses/:id/edit', component: LicenceEdit }`.

- [ ] **Step 3:** Add "+ New licence" button in `Licences.vue` list view.

- [ ] **Step 4: Commit**

---

### Task 5.4: Usage gauges on licence detail

**Files:**
- Create: `web/apps/license-portal/src/components/UsageGauges.vue`
- Modify: `web/apps/license-portal/src/views/LicenceDetail.vue`

- [ ] **Step 1: `UsageGauges.vue`** — accepts `limits: LimitEntry[]` + `usage: UsageSummary` props. For each limit, renders a gauge:
  - Bar coloured green (≤ cap), amber (cap → cap + buffer), red (> cap + buffer).
  - Label: "seats · total · 12 / 50 · 38 remaining".

- [ ] **Step 2: Fetch usage in `LicenceDetail.vue`** on mount; poll every 30 s while the page is open (lightweight `setInterval`, cleared on unmount).

- [ ] **Step 3: Commit**

---

## Phase 6 — End-to-end integration

### Task 6.1: Full activate / usage / validate cycle

**Files:**
- Create: `test/integration/license_v2_test.go`

Test: seed a bundle licence → client activates → pushes usage → over-cap scenario returns `over_cap` array → validate reflects latest usage.

- [ ] **Step 1: Write test, run, commit.**

### Task 6.2: Report Portal end-to-end

**Files:**
- Create: `test/integration/report_license_v2_test.go`

Test: start Report Server with `TRITON_REPORT_LICENSE_KEY` unset → `GET /api/v1/stats` returns 503 with `setup_required:true` → POST `/api/v1/setup/license` → subsequent `/api/v1/stats` returns 200 → verify usage arrives at a fake License Server within 60 s.

- [ ] **Step 1: Write test, run, commit.**

### Task 6.3: Playwright — admin UI create + usage

**Files:**
- Modify: `test/e2e/license-admin.spec.js`

Add two tests:
1. `test('create bundle licence with features + limits')` — fills the form, submits, sees new licence in list.
2. `test('licence detail shows live usage gauges')` — opens detail, asserts a `<UsageGauges>` row is visible.

- [ ] **Step 1: Write, run `make test-e2e-license`, commit.**

---

## Phase 7 — Acceptance + cutover

### Task 7.1: Backward-compat verification

- [ ] **Step 1: Manual test** — use an existing v1 token (from a prior install of the License Server before this PR): decode with the new Guard; verify compat mapping kicks in; verify `EnforceProfile`/`EnforceFormat` behave correctly for the legacy tier.

- [ ] **Step 2: Integration test** — `test/integration/license_compat_test.go`:

```go
func TestV1TierOnlyToken_StillWorks(t *testing.T) {
    tok := issueV1TierOnlyToken(t, "enterprise", 500)
    g := license.NewGuardFromToken(tok)
    if !g.HasFeature("diff_trend") {
        t.Errorf("enterprise should grant diff_trend via compat")
    }
    if cap := g.LimitCap("seats", "total"); cap != 500 {
        t.Errorf("seats cap: want 500, got %d", cap)
    }
}
```

- [ ] **Step 3: Commit.**

### Task 7.2: CI + container verification

- [ ] **Step 1: Rebuild container images** — `make container-build-licenseserver`, `make container-build` (report). Both must boot clean.

- [ ] **Step 2: Run full test suites** — `make test`, `make test-integration`, `make test-e2e-license`. All green.

- [ ] **Step 3: Open PR.**

---

## Acceptance checklist

- [ ] Migration `008_license_v2.up.sql` applies cleanly; `008_license_v2.down.sql` rolls back to v1 state.
- [ ] `pkg/licensestore` round-trips `Features` + `Limits` + `SoftBufferPct` + `ProductScope` through PG.
- [ ] `POST /v1/license/activate` returns `{features, limits, soft_buffer_pct, usage, grace_seconds, signed_token}`.
- [ ] `POST /v1/license/usage` upserts and returns `{ok, remaining, over_cap, in_buffer}`.
- [ ] Pre-v2 tier-only tokens still validate and Guard returns correct feature/limit values via compat mapping.
- [ ] Report Server without `TRITON_REPORT_LICENSE_KEY` serves only `/api/v1/setup/license` until activated.
- [ ] After setup, Report Server pushes usage every 60 s; License Server persists to `license_usage`; Admin UI shows live gauges.
- [ ] `EnforceProfile`, `EnforceFormat`, `LicenceGate` all read feature flags; legacy tier customers unaffected.
- [ ] Retention pruner runs daily, deletes scans + reports older than `retention_days.cap` (or 365 default).
- [ ] License Admin Vue UI lets operator create a licence with full v2 form (features + limits editor).
- [ ] Licence detail page shows live usage gauges per metric.
- [ ] All 3 new integration tests pass.
- [ ] Existing `make test-e2e-license` suite still green.
- [ ] `make container-build-licenseserver` + `make container-build` both succeed.

---

## Follow-on plans

1. **PR B — Manage Server standalone backend + scanner** (docs/superpowers/plans/2026-04-19-manage-server-backend.md, future)
2. **PR C — Manage Portal Vue UI + cutover** (docs/superpowers/plans/2026-04-19-manage-portal-vue.md, future)

Both land on top of this PR's License Server v2 surface; the `product=manage` activation path and the usage-pusher are already exercised here via Report Portal integration, so Manage's licence integration is largely configuration rather than new code.
