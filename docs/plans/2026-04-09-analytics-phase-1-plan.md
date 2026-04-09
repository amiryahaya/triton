# Analytics Phase 1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **⚠️ PLAN CORRECTIONS (2026-04-09, during execution):** Several tasks were authored with incorrect assumptions about the real `pkg/model` and `pkg/store` APIs. Corrections for Tasks 1.1, 1.2, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.12, 1.13, 2.1, 3.1, 4.1, and 4.2 live in **Appendix A** at the bottom of this document. **When implementing any of those tasks, use the Appendix A version verbatim and IGNORE the corresponding inline code above.** Affected tasks are marked with ⚠️ next to their heading. Tasks not in Appendix A are unaffected.

**Goal:** Ship three new read-only analytical views (Crypto Inventory, Expiring Certificates, Migration Priority) in the report server, backed by a denormalized `findings` read-model table with auto-backfill on first boot.

**Architecture:** New `findings` PostgreSQL table populated transactionally on scan submit and retroactively via a first-boot background goroutine. Three new aggregation endpoints (filtered to latest-scan-per-host) serve three new UI views under a new "Analytics" sidebar section. Three Prometheus metrics expose backfill progress.

**Tech Stack:** Go 1.25, Chi v5, pgx v5, PostgreSQL 18, vanilla JS + Chart.js UI, Playwright E2E.

**Spec reference:** `docs/plans/2026-04-09-analytics-phase-1-design.md` — read §2 (decision log) and §6 (query shapes) before starting to understand the constraints.

---

## Ground rules

- **TDD:** every behaviour change = failing test first, then the minimum code to make it pass, then refactor.
- **Integration tests** use `//go:build integration` and need PostgreSQL on port 5435 (per project convention). Run with `TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" go test -tags integration ./...`.
- **Commits:** four total per the spec — one scaffolding commit + one per view. Don't commit between tasks within the same commit group; the final task of each group is the commit step.
- **Branch:** create `feat/analytics-phase-1` off `main` before Task 1.
- **Formatting:** run `make fmt` before each commit.

---

## File structure

### New files

| Path | Purpose |
|------|---------|
| `pkg/store/extract.go` | Pure `ExtractFindings(scan) []Finding` function |
| `pkg/store/extract_test.go` | Unit tests for extraction (no DB) |
| `pkg/store/findings.go` | `ListInventory`, `ListExpiringCertificates`, `ListTopPriorityFindings` + `SaveScanWithFindings` implementations on `PostgresStore` |
| `pkg/store/findings_test.go` | Integration tests for the three aggregation queries + save path |
| `pkg/store/backfill.go` | `BackfillFindings` background loop |
| `pkg/store/backfill_test.go` | Integration tests for backfill (crash recovery, idempotency) |
| `pkg/server/handlers_analytics.go` | The three new handler functions |
| `pkg/server/handlers_analytics_test.go` | Unit + integration tests for the handlers |
| `test/e2e/analytics.spec.js` | Playwright E2E covering all three views |

### Modified files

| Path | Change |
|------|--------|
| `pkg/store/types.go` | Add `Finding`, `InventoryRow`, `ExpiringCertRow`, `PriorityRow` types |
| `pkg/store/store.go` | Add 4 new methods to `Store` interface |
| `pkg/store/migrations.go` | Add Version 7 migration (findings table + marker) |
| `pkg/server/server.go` | Register 3 routes; add atomic fields to `Server` struct |
| `pkg/server/handlers.go` | `handleSubmitScan` → use `SaveScanWithFindings`; add cascade test for `handleDeleteScan` |
| `pkg/server/handlers_metrics.go` | Emit 3 new backfill metric lines |
| `pkg/server/handlers_metrics_test.go` | Assert new metrics in scrape output |
| `cmd/server.go` | Wire backfill goroutine after migrations |
| `pkg/server/ui/dist/index.html` | Add Analytics section + 3 nav links |
| `pkg/server/ui/dist/style.css` | Add analytics table, banner, chip, section-label styles |
| `pkg/server/ui/dist/app.js` | Add 3 router cases, 3 render functions, backfill banner helper |
| `test/e2e/cmd/testserver/main.go` | Add `?backfill=true` toggle for E2E backfill banner test |
| `docs/DEPLOYMENT_GUIDE.md` | Add analytics section + rollback runbook |
| `docs/SYSTEM_ARCHITECTURE.md` | Add findings read-model paragraph |

---

## Commit group 1 — Schema, extraction, backfill, metrics

### Task 1.0: Create branch

- [ ] **Step 1: Branch off main**

```bash
git checkout main
git pull origin main
git checkout -b feat/analytics-phase-1
```

### Task 1.1: Add new types to `pkg/store/types.go`

**Files:**
- Modify: `pkg/store/types.go` (append after existing types)

- [ ] **Step 1: Open the file and append these type definitions at the bottom**

```go
// Finding is the denormalized per-finding row stored in the findings
// table. Populated from model.Finding.CryptoAsset during extraction;
// findings without a crypto asset are skipped.
type Finding struct {
	ID                string
	ScanID            string
	OrgID             string
	Hostname          string
	FindingIndex      int
	Module            string
	Category          string
	FilePath          string
	LineNumber        int
	Algorithm         string
	KeySize           int
	PQCStatus         string
	MigrationPriority int
	NotAfter          *time.Time
	Subject           string
	Issuer            string
	Reachability      string
	CreatedAt         time.Time
}

// InventoryRow is one row in the Crypto Inventory view — one per
// (algorithm, key_size) combination within an org.
type InventoryRow struct {
	Algorithm   string `json:"algorithm"`
	KeySize     int    `json:"keySize,omitempty"`
	PQCStatus   string `json:"pqcStatus"`
	Instances   int    `json:"instances"`
	Machines    int    `json:"machines"`
	MaxPriority int    `json:"maxPriority"`
}

// ExpiringCertRow is one row in the Expiring Certificates view.
type ExpiringCertRow struct {
	FindingID     string    `json:"findingId"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer,omitempty"`
	Hostname      string    `json:"hostname"`
	Algorithm     string    `json:"algorithm"`
	KeySize       int       `json:"keySize,omitempty"`
	NotAfter      time.Time `json:"notAfter"`
	DaysRemaining int       `json:"daysRemaining"`
	Status        string    `json:"status"`
}

// PriorityRow is one row in the Migration Priority view.
type PriorityRow struct {
	FindingID  string `json:"findingId"`
	Priority   int    `json:"priority"`
	Algorithm  string `json:"algorithm"`
	KeySize    int    `json:"keySize,omitempty"`
	PQCStatus  string `json:"pqcStatus"`
	Module     string `json:"module"`
	Category   string `json:"category"`
	Hostname   string `json:"hostname"`
	FilePath   string `json:"filePath,omitempty"`
	LineNumber int    `json:"lineNumber,omitempty"`
}
```

- [ ] **Step 2: Verify time is imported (it should be for existing types — but confirm)**

```bash
grep '"time"' pkg/store/types.go
```

Expected: one line output.

- [ ] **Step 3: Compile check**

```bash
go build ./pkg/store/...
```

Expected: clean (no output, exit 0).

---

### Task 1.2: Migration v7 — findings table + marker column

**Files:**
- Modify: `pkg/store/migrations.go`

- [ ] **Step 1: Append the Version 7 migration to the `migrations` slice**

Add this as the new final entry in `migrations` (after the Version 6 audit_events migration):

```go
	// Version 7: Denormalized findings read-model (Analytics Phase 1).
	//
	// Extracts per-finding crypto data from scans.result_json into a
	// queryable table. scans remains the source of truth; findings is a
	// rebuildable read-model populated on scan submit (inline via
	// SaveScanWithFindings) and for existing rows via the first-boot
	// backfill (pkg/store/backfill.go).
	//
	// Only findings with a non-nil CryptoAsset are extracted — non-crypto
	// findings stay in the blob and are irrelevant to the analytics views.
	`CREATE TABLE IF NOT EXISTS findings (
		id                  UUID PRIMARY KEY,
		scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		org_id              UUID NOT NULL,
		hostname            TEXT NOT NULL,
		finding_index       INTEGER NOT NULL,
		module              TEXT NOT NULL,
		category            TEXT NOT NULL,
		file_path           TEXT NOT NULL DEFAULT '',
		line_number         INTEGER NOT NULL DEFAULT 0,
		algorithm           TEXT NOT NULL,
		key_size            INTEGER NOT NULL DEFAULT 0,
		pqc_status          TEXT NOT NULL DEFAULT '',
		migration_priority  INTEGER NOT NULL DEFAULT 0,
		not_after           TIMESTAMPTZ,
		subject             TEXT NOT NULL DEFAULT '',
		issuer              TEXT NOT NULL DEFAULT '',
		reachability        TEXT NOT NULL DEFAULT '',
		created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
		UNIQUE (scan_id, finding_index)
	);

	CREATE INDEX IF NOT EXISTS idx_findings_org_algorithm
		ON findings (org_id, algorithm, key_size);

	CREATE INDEX IF NOT EXISTS idx_findings_org_not_after
		ON findings (org_id, not_after)
		WHERE not_after IS NOT NULL;

	CREATE INDEX IF NOT EXISTS idx_findings_org_priority
		ON findings (org_id, migration_priority DESC);

	CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);

	ALTER TABLE scans ADD COLUMN IF NOT EXISTS findings_extracted_at TIMESTAMPTZ;`,
```

- [ ] **Step 2: Compile check**

```bash
go build ./pkg/store/...
```

Expected: clean.

- [ ] **Step 3: Run the existing idempotent-migration test against a fresh DB**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestNewPostgresStore_IdempotentMigrations ./pkg/store/...
```

Expected: PASS. This test calls `NewPostgresStore` twice and verifies the migrations are idempotent — confirms our new migration runs cleanly both the first time (CREATE TABLE) and the second time (the `IF NOT EXISTS` guards kick in).

- [ ] **Step 4: Manually verify the table exists**

```bash
podman exec triton-db psql -U triton -d triton_test -c "\d findings"
```

Expected: table definition output listing all 18 columns from the migration.

---

### Task 1.3: Add 4 methods to the `Store` interface

**Files:**
- Modify: `pkg/store/store.go`

- [ ] **Step 1: Add these methods to the `Store` interface at the appropriate place (with the other Scan-related methods)**

```go
	// SaveScanWithFindings atomically stores a scan and inserts its
	// extracted crypto findings. Marks the scan as backfilled on success
	// so the background goroutine skips it.
	SaveScanWithFindings(ctx context.Context, scan *model.ScanResult, findings []Finding) error

	// ListInventory aggregates findings into (algorithm, key_size) rows
	// for the given org, filtered to the latest scan per hostname.
	// Sorted by worst PQC status first, then instances descending.
	// Returns an empty slice (not nil) when there are no findings.
	ListInventory(ctx context.Context, orgID string) ([]InventoryRow, error)

	// ListExpiringCertificates returns findings with not_after set,
	// filtered to the latest scan per hostname, expiring within the
	// given duration from now. Already-expired certs are ALWAYS
	// included regardless of the window. Callers wanting "all future
	// expiries" pass a large duration (e.g. 100 years).
	ListExpiringCertificates(ctx context.Context, orgID string, within time.Duration) ([]ExpiringCertRow, error)

	// ListTopPriorityFindings returns the top N findings by
	// migration_priority descending, filtered to the latest scan per
	// hostname. Findings with priority 0 are excluded. limit=0 is
	// treated as limit=20.
	ListTopPriorityFindings(ctx context.Context, orgID string, limit int) ([]PriorityRow, error)
```

- [ ] **Step 2: Confirm `time` is imported in store.go**

```bash
grep '"time"' pkg/store/store.go
```

Expected: one match. If absent, add it to the imports.

- [ ] **Step 3: Compile check**

```bash
go build ./pkg/store/...
```

Expected: error messages mentioning that `PostgresStore` doesn't implement `Store` (the 4 methods are missing). **This is the expected failure** — we'll satisfy them in the next tasks.

---

### Task 1.4: `ExtractFindings` pure function + unit tests

**Files:**
- Create: `pkg/store/extract.go`
- Create: `pkg/store/extract_test.go`

- [ ] **Step 1: Create `extract_test.go` with the failing test suite**

```go
package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestExtractFindings_EmptyScan(t *testing.T) {
	scan := &model.ScanResult{ID: "s1", OrgID: "o1", Hostname: "h1"}
	got := ExtractFindings(scan)
	assert.Empty(t, got)
}

func TestExtractFindings_NoCryptoFindings(t *testing.T) {
	scan := &model.ScanResult{
		ID: "s1", OrgID: "o1", Hostname: "h1",
		Findings: []model.Finding{
			{Module: "file", CryptoAsset: nil},
			{Module: "file", CryptoAsset: nil},
		},
	}
	assert.Empty(t, ExtractFindings(scan))
}

func TestExtractFindings_AllCryptoFindings(t *testing.T) {
	scan := &model.ScanResult{
		ID: "s1", OrgID: "o1", Hostname: "h1",
		Findings: []model.Finding{
			{Module: "key", Category: "key", FilePath: "/a", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}},
			{Module: "key", Category: "key", FilePath: "/b", CryptoAsset: &model.CryptoAsset{Algorithm: "ECDSA", KeySize: 256, PQCStatus: "TRANSITIONAL", MigrationPriority: 55}},
		},
	}
	got := ExtractFindings(scan)
	require.Len(t, got, 2)
	assert.Equal(t, "RSA", got[0].Algorithm)
	assert.Equal(t, 2048, got[0].KeySize)
	assert.Equal(t, "DEPRECATED", got[0].PQCStatus)
	assert.Equal(t, 80, got[0].MigrationPriority)
	assert.Equal(t, 0, got[0].FindingIndex)
	assert.Equal(t, "ECDSA", got[1].Algorithm)
	assert.Equal(t, 1, got[1].FindingIndex)
}

func TestExtractFindings_MixedFindingsPreservesIndex(t *testing.T) {
	scan := &model.ScanResult{
		ID: "s1", OrgID: "o1", Hostname: "h1",
		Findings: []model.Finding{
			{Module: "file", CryptoAsset: nil},                                                    // index 0 — dropped
			{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}},      // index 1 — kept
			{Module: "file", CryptoAsset: nil},                                                    // index 2 — dropped
			{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "AES", KeySize: 256}},       // index 3 — kept
		},
	}
	got := ExtractFindings(scan)
	require.Len(t, got, 2)
	assert.Equal(t, 1, got[0].FindingIndex, "RSA finding keeps its original index")
	assert.Equal(t, 3, got[1].FindingIndex, "AES finding keeps its original index")
}

func TestExtractFindings_CertificateFields(t *testing.T) {
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	scan := &model.ScanResult{
		ID: "s1", OrgID: "o1", Hostname: "h1",
		Findings: []model.Finding{{
			Module: "certificate",
			CryptoAsset: &model.CryptoAsset{
				Algorithm: "RSA",
				KeySize:   2048,
				NotAfter:  &notAfter,
				Subject:   "CN=api.test",
				Issuer:    "CN=Test CA",
			},
		}},
	}
	got := ExtractFindings(scan)
	require.Len(t, got, 1)
	require.NotNil(t, got[0].NotAfter)
	assert.Equal(t, notAfter, *got[0].NotAfter)
	assert.Equal(t, "CN=api.test", got[0].Subject)
	assert.Equal(t, "CN=Test CA", got[0].Issuer)
}

func TestExtractFindings_DepsReachability(t *testing.T) {
	scan := &model.ScanResult{
		ID: "s1", OrgID: "o1", Hostname: "h1",
		Findings: []model.Finding{{
			Module: "deps",
			CryptoAsset: &model.CryptoAsset{
				Algorithm:    "RSA",
				KeySize:      2048,
				Reachability: "transitive",
			},
		}},
	}
	got := ExtractFindings(scan)
	require.Len(t, got, 1)
	assert.Equal(t, "transitive", got[0].Reachability)
}

func TestExtractFindings_NilNotAfterStaysNil(t *testing.T) {
	scan := &model.ScanResult{
		ID: "s1", OrgID: "o1", Hostname: "h1",
		Findings: []model.Finding{{
			Module: "key",
			CryptoAsset: &model.CryptoAsset{Algorithm: "AES", KeySize: 256, NotAfter: nil},
		}},
	}
	got := ExtractFindings(scan)
	require.Len(t, got, 1)
	assert.Nil(t, got[0].NotAfter, "nil NotAfter must stay nil, not silently become a zero value")
}

func TestExtractFindings_ScanFieldsPropagate(t *testing.T) {
	scan := &model.ScanResult{
		ID: "scan-abc", OrgID: "org-xyz", Hostname: "host-123",
		Findings: []model.Finding{{
			Module: "key",
			CryptoAsset: &model.CryptoAsset{Algorithm: "AES"},
		}},
	}
	got := ExtractFindings(scan)
	require.Len(t, got, 1)
	assert.Equal(t, "scan-abc", got[0].ScanID)
	assert.Equal(t, "org-xyz", got[0].OrgID)
	assert.Equal(t, "host-123", got[0].Hostname)
}
```

- [ ] **Step 2: Run the tests — they should all fail because `ExtractFindings` doesn't exist yet**

```bash
go test -run TestExtractFindings ./pkg/store/...
```

Expected: compile error — `undefined: ExtractFindings`.

- [ ] **Step 3: Create `extract.go` with the implementation**

```go
package store

import (
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// ExtractFindings walks a ScanResult and produces one Finding row per
// model.Finding whose CryptoAsset is non-nil. Pure function — no DB
// access. Used by both the submit path and the backfill goroutine so
// they produce identical rows. See docs/plans/2026-04-09-analytics-
// phase-1-design.md §6 for the design rationale.
func ExtractFindings(scan *model.ScanResult) []Finding {
	if scan == nil || len(scan.Findings) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(scan.Findings))
	now := time.Now().UTC()
	for i := range scan.Findings {
		f := &scan.Findings[i]
		if f.CryptoAsset == nil {
			continue
		}
		ca := f.CryptoAsset
		out = append(out, Finding{
			ID:                uuid.Must(uuid.NewV7()).String(),
			ScanID:            scan.ID,
			OrgID:             scan.OrgID,
			Hostname:          scan.Hostname,
			FindingIndex:      i,
			Module:            f.Module,
			Category:          string(f.Category),
			FilePath:          f.FilePath,
			LineNumber:        f.LineNumber,
			Algorithm:         ca.Algorithm,
			KeySize:           ca.KeySize,
			PQCStatus:         ca.PQCStatus,
			MigrationPriority: ca.MigrationPriority,
			NotAfter:          ca.NotAfter,
			Subject:           ca.Subject,
			Issuer:            ca.Issuer,
			Reachability:      ca.Reachability,
			CreatedAt:         now,
		})
	}
	return out
}
```

- [ ] **Step 4: Run the tests — they should all pass now**

```bash
go test -run TestExtractFindings ./pkg/store/...
```

Expected: PASS (8 tests).

- [ ] **Step 5: Check line coverage**

```bash
go test -run TestExtractFindings -cover ./pkg/store/...
```

Expected: high coverage (>90%) on extract.go.

---

### Task 1.5: `SaveScanWithFindings` transactional write path

**Files:**
- Create: `pkg/store/findings.go`
- Create: `pkg/store/findings_test.go`

- [ ] **Step 1: Create `findings_test.go` with the failing test for SaveScanWithFindings**

```go
//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestSaveScanWithFindings_StoresScanAndFindings(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	scan := testScanResult(testUUID("swf-1"), "host-1", "quick")
	scan.OrgID = testUUID("org-a")
	scan.Findings = []model.Finding{
		{Module: "key", Category: "key", FilePath: "/a", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}},
		{Module: "key", Category: "key", FilePath: "/b", CryptoAsset: &model.CryptoAsset{Algorithm: "AES", KeySize: 256, PQCStatus: "SAFE", MigrationPriority: 10}},
	}

	extracted := ExtractFindings(scan)
	require.Len(t, extracted, 2)

	err := s.SaveScanWithFindings(ctx, scan, extracted)
	require.NoError(t, err)

	// Verify scan row exists
	retrieved, err := s.GetScan(ctx, scan.ID, scan.OrgID)
	require.NoError(t, err)
	assert.Equal(t, scan.ID, retrieved.ID)

	// Verify findings rows exist
	rows := queryFindingsCount(t, s, scan.ID)
	assert.Equal(t, 2, rows)

	// Verify scan is marked backfilled
	assert.True(t, queryScanBackfilled(t, s, scan.ID))
}

func TestSaveScanWithFindings_SkipsNonCryptoFindings(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	scan := testScanResult(testUUID("swf-2"), "host-2", "quick")
	scan.OrgID = testUUID("org-a")
	scan.Findings = []model.Finding{
		{Module: "file", CryptoAsset: nil}, // non-crypto, skipped
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}},
	}
	extracted := ExtractFindings(scan)
	require.Len(t, extracted, 1)

	require.NoError(t, s.SaveScanWithFindings(ctx, scan, extracted))

	rows := queryFindingsCount(t, s, scan.ID)
	assert.Equal(t, 1, rows, "only crypto findings get a row")
}

// queryFindingsCount is a test helper that counts findings for a scan.
func queryFindingsCount(t *testing.T, s *PostgresStore, scanID string) int {
	t.Helper()
	var count int
	err := s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM findings WHERE scan_id = $1`, scanID).Scan(&count)
	require.NoError(t, err)
	return count
}

// queryScanBackfilled returns true if the scan row has findings_extracted_at set.
func queryScanBackfilled(t *testing.T, s *PostgresStore, scanID string) bool {
	t.Helper()
	var markedAt *time.Time
	err := s.pool.QueryRow(context.Background(),
		`SELECT findings_extracted_at FROM scans WHERE id = $1`, scanID).Scan(&markedAt)
	require.NoError(t, err)
	return markedAt != nil
}

// Fresh UUID for each test to avoid test-to-test collisions.
func newScanID() string { return uuid.Must(uuid.NewV7()).String() }
```

**Note on `time` import:** add `"time"` to the imports at the top of the file (after `"testing"`).

- [ ] **Step 2: Run the tests — expect compile failure on `SaveScanWithFindings`**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestSaveScanWithFindings ./pkg/store/...
```

Expected: compile error — `PostgresStore.SaveScanWithFindings undefined`.

- [ ] **Step 3: Create `findings.go` with the transactional implementation**

```go
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/amiryahaya/triton/pkg/model"
)

// SaveScanWithFindings atomically creates a scan row and inserts the
// extracted crypto findings into the findings table. Marks the scan
// as backfilled on success so the background goroutine skips it.
//
// See docs/plans/2026-04-09-analytics-phase-1-design.md §6 for the
// transactional design. Replaces SaveScan on the hot-path write;
// SaveScan remains for legacy callers.
func (s *PostgresStore) SaveScanWithFindings(ctx context.Context, scan *model.ScanResult, findings []Finding) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// 1. Upsert the scan row using the same logic as SaveScan but
		//    inside this transaction. We duplicate the insert SQL here
		//    instead of calling SaveScan to keep everything on tx.
		payload, err := marshalScanPayload(scan, s.encryptor)
		if err != nil {
			return fmt.Errorf("marshal scan payload: %w", err)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO scans (id, org_id, hostname, timestamp, profile, total_findings, safe, transitional, deprecated, unsafe, result_json, findings_extracted_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
			ON CONFLICT (id) DO UPDATE SET
				org_id = EXCLUDED.org_id,
				hostname = EXCLUDED.hostname,
				timestamp = EXCLUDED.timestamp,
				profile = EXCLUDED.profile,
				total_findings = EXCLUDED.total_findings,
				safe = EXCLUDED.safe,
				transitional = EXCLUDED.transitional,
				deprecated = EXCLUDED.deprecated,
				unsafe = EXCLUDED.unsafe,
				result_json = EXCLUDED.result_json,
				findings_extracted_at = EXCLUDED.findings_extracted_at
		`,
			scan.ID, scan.OrgID, scan.Hostname, scan.Metadata.Timestamp, scan.Metadata.Profile,
			scan.Summary.TotalCryptoAssets, scan.Summary.Safe, scan.Summary.Transitional,
			scan.Summary.Deprecated, scan.Summary.Unsafe, payload)
		if err != nil {
			return fmt.Errorf("insert scan: %w", err)
		}

		// 2. Bulk insert the findings. Idempotent via ON CONFLICT so
		//    retries are safe.
		if err := insertFindingsInTx(ctx, tx, findings); err != nil {
			return fmt.Errorf("insert findings: %w", err)
		}
		return nil
	})
}

// insertFindingsInTx bulk-inserts findings using chunked VALUES lists
// to avoid the pgx parameter limit (65535). 1000 rows per chunk keeps
// us well under the limit at 17 columns per row.
func insertFindingsInTx(ctx context.Context, tx pgx.Tx, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	const chunkSize = 1000
	for start := 0; start < len(findings); start += chunkSize {
		end := start + chunkSize
		if end > len(findings) {
			end = len(findings)
		}
		if err := insertFindingsChunk(ctx, tx, findings[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func insertFindingsChunk(ctx context.Context, tx pgx.Tx, chunk []Finding) error {
	const cols = 18
	args := make([]any, 0, len(chunk)*cols)
	valueStrs := make([]string, 0, len(chunk))
	for i, f := range chunk {
		base := i * cols
		valueStrs = append(valueStrs, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9,
			base+10, base+11, base+12, base+13, base+14, base+15, base+16, base+17, base+18,
		))
		args = append(args,
			f.ID, f.ScanID, f.OrgID, f.Hostname, f.FindingIndex,
			f.Module, f.Category, f.FilePath, f.LineNumber,
			f.Algorithm, f.KeySize, f.PQCStatus, f.MigrationPriority,
			f.NotAfter, f.Subject, f.Issuer, f.Reachability, f.CreatedAt,
		)
	}

	sql := `INSERT INTO findings (
		id, scan_id, org_id, hostname, finding_index,
		module, category, file_path, line_number,
		algorithm, key_size, pqc_status, migration_priority,
		not_after, subject, issuer, reachability, created_at
	) VALUES ` + joinStrings(valueStrs, ",") + `
	ON CONFLICT (scan_id, finding_index) DO NOTHING`

	_, err := tx.Exec(ctx, sql, args...)
	return err
}

// joinStrings is a tiny helper to avoid pulling in strings.Join for a single use.
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += sep + p
	}
	return out
}
```

**Important:** The SaveScan implementation in `pkg/store/postgres.go` has the `marshalScanPayload` helper referenced here. If it's not exported or named differently, open `postgres.go:122` and copy the equivalent logic from `SaveScan` into this new method — do NOT call `s.SaveScan()` from inside the transaction, because that would open a second connection.

- [ ] **Step 4: Run the tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestSaveScanWithFindings ./pkg/store/...
```

Expected: PASS (2 tests).

---

### Task 1.6: `ListInventory` query

**Files:**
- Modify: `pkg/store/findings.go` (append method)
- Modify: `pkg/store/findings_test.go` (append tests)

- [ ] **Step 1: Append tests to `findings_test.go`**

```go
func TestListInventory_EmptyOrg(t *testing.T) {
	s := testStore(t)
	rows, err := s.ListInventory(context.Background(), testUUID("empty-org"))
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListInventory_SingleFinding(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	scan := testScanResult(testUUID("inv-1"), "host-1", "quick")
	scan.OrgID = testUUID("inv-org")
	scan.Findings = []model.Finding{{
		Module: "key",
		CryptoAsset: &model.CryptoAsset{
			Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80,
		},
	}}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListInventory(ctx, scan.OrgID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "RSA", rows[0].Algorithm)
	assert.Equal(t, 2048, rows[0].KeySize)
	assert.Equal(t, "DEPRECATED", rows[0].PQCStatus)
	assert.Equal(t, 1, rows[0].Instances)
	assert.Equal(t, 1, rows[0].Machines)
	assert.Equal(t, 80, rows[0].MaxPriority)
}

func TestListInventory_GroupsByAlgorithmAndSize(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("inv-grp")
	scan := testScanResult(testUUID("inv-grp-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}},
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 75}},
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 4096, PQCStatus: "SAFE", MigrationPriority: 0}},
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListInventory(ctx, orgID)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	// Row for RSA-2048 — grouped, 2 instances, max priority 80
	rsa2048 := findInventoryRow(rows, "RSA", 2048)
	require.NotNil(t, rsa2048)
	assert.Equal(t, 2, rsa2048.Instances)
	assert.Equal(t, 1, rsa2048.Machines)
	assert.Equal(t, 80, rsa2048.MaxPriority)

	// Row for RSA-4096 — 1 instance, SAFE
	rsa4096 := findInventoryRow(rows, "RSA", 4096)
	require.NotNil(t, rsa4096)
	assert.Equal(t, "SAFE", rsa4096.PQCStatus)
}

func TestListInventory_TenantIsolation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgA := testUUID("inv-tenant-a")
	orgB := testUUID("inv-tenant-b")

	scanA := testScanResult(testUUID("inv-tenant-scan-a"), "host-a", "quick")
	scanA.OrgID = orgA
	scanA.Findings = []model.Finding{{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED"}}}
	require.NoError(t, s.SaveScanWithFindings(ctx, scanA, ExtractFindings(scanA)))

	scanB := testScanResult(testUUID("inv-tenant-scan-b"), "host-b", "quick")
	scanB.OrgID = orgB
	scanB.Findings = []model.Finding{{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "AES", KeySize: 256, PQCStatus: "SAFE"}}}
	require.NoError(t, s.SaveScanWithFindings(ctx, scanB, ExtractFindings(scanB)))

	rowsA, err := s.ListInventory(ctx, orgA)
	require.NoError(t, err)
	require.Len(t, rowsA, 1)
	assert.Equal(t, "RSA", rowsA[0].Algorithm, "org A sees only its own findings")

	rowsB, err := s.ListInventory(ctx, orgB)
	require.NoError(t, err)
	require.Len(t, rowsB, 1)
	assert.Equal(t, "AES", rowsB[0].Algorithm, "org B sees only its own findings")
}

func TestListInventory_LatestScanPerHostOnly(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("inv-latest")

	// Old scan: RSA-1024 (which no longer exists on the host)
	oldScan := testScanResult(testUUID("inv-latest-old"), "host-1", "quick")
	oldScan.OrgID = orgID
	oldScan.Metadata.Timestamp = time.Now().UTC().Add(-48 * time.Hour)
	oldScan.Findings = []model.Finding{{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 1024, PQCStatus: "UNSAFE"}}}
	require.NoError(t, s.SaveScanWithFindings(ctx, oldScan, ExtractFindings(oldScan)))

	// New scan: upgraded to RSA-4096
	newScan := testScanResult(testUUID("inv-latest-new"), "host-1", "quick")
	newScan.OrgID = orgID
	newScan.Metadata.Timestamp = time.Now().UTC()
	newScan.Findings = []model.Finding{{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 4096, PQCStatus: "SAFE"}}}
	require.NoError(t, s.SaveScanWithFindings(ctx, newScan, ExtractFindings(newScan)))

	rows, err := s.ListInventory(ctx, orgID)
	require.NoError(t, err)
	require.Len(t, rows, 1, "only the latest scan per host counts")
	assert.Equal(t, 4096, rows[0].KeySize, "should reflect the new scan, not the old one")
}

// findInventoryRow is a test helper that locates a row by (algorithm, keySize).
func findInventoryRow(rows []InventoryRow, algo string, size int) *InventoryRow {
	for i := range rows {
		if rows[i].Algorithm == algo && rows[i].KeySize == size {
			return &rows[i]
		}
	}
	return nil
}
```

- [ ] **Step 2: Run the tests — expect compile failure**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestListInventory ./pkg/store/...
```

Expected: compile error — `PostgresStore.ListInventory undefined`.

- [ ] **Step 3: Append `ListInventory` to `findings.go`**

```go
// ListInventory aggregates findings by (algorithm, key_size) for the
// given org, filtered to the latest scan per hostname. Sorted by worst
// PQC status first, then instances descending.
func (s *PostgresStore) ListInventory(ctx context.Context, orgID string) ([]InventoryRow, error) {
	const q = `
WITH latest_scans AS (
    SELECT DISTINCT ON (hostname) id
    FROM scans
    WHERE org_id = $1
    ORDER BY hostname, timestamp DESC
)
SELECT
    f.algorithm,
    f.key_size,
    MIN(
        CASE f.pqc_status
            WHEN 'UNSAFE'       THEN 1
            WHEN 'DEPRECATED'   THEN 2
            WHEN 'TRANSITIONAL' THEN 3
            WHEN 'SAFE'         THEN 4
            ELSE 5
        END
    ) AS status_rank,
    COUNT(*)                               AS instances,
    COUNT(DISTINCT f.hostname)             AS machines,
    COALESCE(MAX(f.migration_priority), 0) AS max_priority
FROM findings f
WHERE f.org_id = $1
  AND f.scan_id IN (SELECT id FROM latest_scans)
GROUP BY f.algorithm, f.key_size
ORDER BY status_rank ASC, instances DESC
`
	rows, err := s.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("ListInventory query: %w", err)
	}
	defer rows.Close()

	out := make([]InventoryRow, 0)
	for rows.Next() {
		var r InventoryRow
		var rank int
		if err := rows.Scan(&r.Algorithm, &r.KeySize, &rank, &r.Instances, &r.Machines, &r.MaxPriority); err != nil {
			return nil, fmt.Errorf("ListInventory scan: %w", err)
		}
		r.PQCStatus = pqcStatusFromRank(rank)
		out = append(out, r)
	}
	return out, rows.Err()
}

// pqcStatusFromRank converts the SQL CASE rank back to its string form.
func pqcStatusFromRank(rank int) string {
	switch rank {
	case 1:
		return "UNSAFE"
	case 2:
		return "DEPRECATED"
	case 3:
		return "TRANSITIONAL"
	case 4:
		return "SAFE"
	default:
		return ""
	}
}
```

- [ ] **Step 4: Run the tests — they should pass**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestListInventory ./pkg/store/...
```

Expected: PASS (5 tests).

---

### Task 1.7: `ListExpiringCertificates` query

**Files:**
- Modify: `pkg/store/findings.go` (append method)
- Modify: `pkg/store/findings_test.go` (append tests)

- [ ] **Step 1: Append tests to `findings_test.go`**

```go
func TestListExpiringCerts_EmptyOrg(t *testing.T) {
	s := testStore(t)
	rows, err := s.ListExpiringCertificates(context.Background(), testUUID("cert-empty"), 90*24*time.Hour)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListExpiringCerts_WithinWindow(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("cert-window")
	in30 := time.Now().UTC().Add(30 * 24 * time.Hour)
	in200 := time.Now().UTC().Add(200 * 24 * time.Hour)

	scan := testScanResult(testUUID("cert-win-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &in30, Subject: "CN=soon"}},
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &in200, Subject: "CN=later"}},
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListExpiringCertificates(ctx, orgID, 90*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 1, "only the 30-day cert is inside the 90-day window")
	assert.Equal(t, "CN=soon", rows[0].Subject)
}

func TestListExpiringCerts_AlreadyExpiredAlwaysIncluded(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("cert-expired")
	expired := time.Now().UTC().Add(-10 * 24 * time.Hour)

	scan := testScanResult(testUUID("cert-expired-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &expired, Subject: "CN=dead"}},
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	// Even with a very short window, expired certs are always included.
	rows, err := s.ListExpiringCertificates(ctx, orgID, 1*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "CN=dead", rows[0].Subject)
	assert.True(t, rows[0].DaysRemaining < 0, "negative days for expired certs")
}

func TestListExpiringCerts_NullNotAfterExcluded(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("cert-null")
	scan := testScanResult(testUUID("cert-null-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "AES", KeySize: 256}}, // no NotAfter
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListExpiringCertificates(ctx, orgID, 90*24*time.Hour)
	require.NoError(t, err)
	assert.Empty(t, rows, "non-cert findings must not leak into the cert view")
}

func TestListExpiringCerts_SortedAscending(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("cert-sort")
	in15 := time.Now().UTC().Add(15 * 24 * time.Hour)
	in45 := time.Now().UTC().Add(45 * 24 * time.Hour)
	in5 := time.Now().UTC().Add(5 * 24 * time.Hour)

	scan := testScanResult(testUUID("cert-sort-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in15, Subject: "CN=fifteen"}},
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in45, Subject: "CN=forty-five"}},
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in5, Subject: "CN=five"}},
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListExpiringCertificates(ctx, orgID, 90*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, "CN=five", rows[0].Subject, "soonest first")
	assert.Equal(t, "CN=fifteen", rows[1].Subject)
	assert.Equal(t, "CN=forty-five", rows[2].Subject)
}

func TestListExpiringCerts_LargeWithinReturnsFuture(t *testing.T) {
	// "All future expiries" semantics: handler passes 100 years.
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("cert-all")
	inYear := time.Now().UTC().Add(400 * 24 * time.Hour)

	scan := testScanResult(testUUID("cert-all-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", NotAfter: &inYear, Subject: "CN=far"}},
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListExpiringCertificates(ctx, orgID, 100*365*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "CN=far", rows[0].Subject)
}
```

- [ ] **Step 2: Run — expect compile failure**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestListExpiringCerts ./pkg/store/...
```

Expected: compile error — `ListExpiringCertificates undefined`.

- [ ] **Step 3: Append `ListExpiringCertificates` to `findings.go`**

```go
// ListExpiringCertificates returns findings with not_after IS NOT NULL,
// filtered to the latest scan per hostname, expiring within the given
// duration from now. Already-expired certs are ALWAYS included.
func (s *PostgresStore) ListExpiringCertificates(ctx context.Context, orgID string, within time.Duration) ([]ExpiringCertRow, error) {
	const q = `
WITH latest_scans AS (
    SELECT DISTINCT ON (hostname) id
    FROM scans
    WHERE org_id = $1
    ORDER BY hostname, timestamp DESC
)
SELECT f.id, f.subject, f.issuer, f.hostname, f.algorithm, f.key_size, f.not_after
FROM findings f
WHERE f.org_id = $1
  AND f.scan_id IN (SELECT id FROM latest_scans)
  AND f.not_after IS NOT NULL
  AND (f.not_after <= NOW() + $2::interval OR f.not_after < NOW())
ORDER BY f.not_after ASC
`
	// pgx/v5 accepts time.Duration as an interval when passed via make_interval,
	// but the simpler path is to format it as a seconds string.
	interval := fmt.Sprintf("%d seconds", int64(within.Seconds()))
	rows, err := s.pool.Query(ctx, q, orgID, interval)
	if err != nil {
		return nil, fmt.Errorf("ListExpiringCertificates query: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	out := make([]ExpiringCertRow, 0)
	for rows.Next() {
		var r ExpiringCertRow
		var notAfter time.Time
		if err := rows.Scan(&r.FindingID, &r.Subject, &r.Issuer, &r.Hostname, &r.Algorithm, &r.KeySize, &notAfter); err != nil {
			return nil, fmt.Errorf("ListExpiringCertificates scan: %w", err)
		}
		r.NotAfter = notAfter
		r.DaysRemaining = int(notAfter.Sub(now).Hours() / 24)
		r.Status = certStatusFromDays(r.DaysRemaining)
		out = append(out, r)
	}
	return out, rows.Err()
}

// certStatusFromDays maps days-remaining to a status badge label.
// Matches the UI colour scheme: red <=0 expired, orange 1-30 urgent,
// yellow 31-90 warning, green >90 ok.
func certStatusFromDays(days int) string {
	switch {
	case days < 0:
		return "expired"
	case days <= 30:
		return "urgent"
	case days <= 90:
		return "warning"
	default:
		return "ok"
	}
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestListExpiringCerts ./pkg/store/...
```

Expected: PASS (6 tests).

---

### Task 1.8: `ListTopPriorityFindings` query

**Files:**
- Modify: `pkg/store/findings.go` (append method)
- Modify: `pkg/store/findings_test.go` (append tests)

- [ ] **Step 1: Append tests**

```go
func TestListPriority_EmptyOrg(t *testing.T) {
	s := testStore(t)
	rows, err := s.ListTopPriorityFindings(context.Background(), testUUID("prio-empty"), 20)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListPriority_SortedDescending(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("prio-sort")
	scan := testScanResult(testUUID("prio-sort-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50}},
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "MD5", MigrationPriority: 95}},
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "SHA-1", MigrationPriority: 80}},
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListTopPriorityFindings(ctx, orgID, 20)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, 95, rows[0].Priority)
	assert.Equal(t, 80, rows[1].Priority)
	assert.Equal(t, 50, rows[2].Priority)
}

func TestListPriority_LimitRespected(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("prio-limit")
	scan := testScanResult(testUUID("prio-limit-1"), "host-1", "quick")
	scan.OrgID = orgID
	for i := 0; i < 30; i++ {
		scan.Findings = append(scan.Findings, model.Finding{
			Module: "key",
			CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i},
		})
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListTopPriorityFindings(ctx, orgID, 10)
	require.NoError(t, err)
	assert.Len(t, rows, 10)

	rowsAll, err := s.ListTopPriorityFindings(ctx, orgID, 100)
	require.NoError(t, err)
	assert.Len(t, rowsAll, 30)
}

func TestListPriority_ExcludesZeroPriority(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("prio-zero")
	scan := testScanResult(testUUID("prio-zero-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "AES", MigrationPriority: 0}}, // excluded
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50}},
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListTopPriorityFindings(ctx, orgID, 20)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "RSA", rows[0].Algorithm)
}

func TestListPriority_LimitZeroDefaultsTo20(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	orgID := testUUID("prio-default")
	scan := testScanResult(testUUID("prio-default-1"), "host-1", "quick")
	scan.OrgID = orgID
	for i := 0; i < 25; i++ {
		scan.Findings = append(scan.Findings, model.Finding{
			Module: "key",
			CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i},
		})
	}
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))

	rows, err := s.ListTopPriorityFindings(ctx, orgID, 0)
	require.NoError(t, err)
	assert.Len(t, rows, 20, "limit=0 must default to 20 per the interface contract")
}
```

- [ ] **Step 2: Run — expect failure**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestListPriority ./pkg/store/...
```

Expected: compile error — `ListTopPriorityFindings undefined`.

- [ ] **Step 3: Append implementation to `findings.go`**

```go
// ListTopPriorityFindings returns the top N findings by
// migration_priority descending, filtered to the latest scan per
// hostname. limit=0 is treated as limit=20.
func (s *PostgresStore) ListTopPriorityFindings(ctx context.Context, orgID string, limit int) ([]PriorityRow, error) {
	if limit <= 0 {
		limit = 20
	}
	const q = `
WITH latest_scans AS (
    SELECT DISTINCT ON (hostname) id
    FROM scans
    WHERE org_id = $1
    ORDER BY hostname, timestamp DESC
)
SELECT f.id, f.migration_priority, f.algorithm, f.key_size, f.pqc_status,
       f.module, f.category, f.hostname, f.file_path, f.line_number
FROM findings f
WHERE f.org_id = $1
  AND f.scan_id IN (SELECT id FROM latest_scans)
  AND f.migration_priority > 0
ORDER BY f.migration_priority DESC
LIMIT $2
`
	rows, err := s.pool.Query(ctx, q, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("ListTopPriorityFindings query: %w", err)
	}
	defer rows.Close()

	out := make([]PriorityRow, 0)
	for rows.Next() {
		var r PriorityRow
		if err := rows.Scan(&r.FindingID, &r.Priority, &r.Algorithm, &r.KeySize, &r.PQCStatus,
			&r.Module, &r.Category, &r.Hostname, &r.FilePath, &r.LineNumber); err != nil {
			return nil, fmt.Errorf("ListTopPriorityFindings scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestListPriority ./pkg/store/...
```

Expected: PASS (5 tests).

---

### Task 1.9: `BackfillFindings` goroutine

**Files:**
- Create: `pkg/store/backfill.go`
- Create: `pkg/store/backfill_test.go`

- [ ] **Step 1: Create `backfill_test.go` with failing tests**

```go
//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestBackfillFindings_EmptyDB(t *testing.T) {
	s := testStore(t)
	err := s.BackfillFindings(context.Background())
	assert.NoError(t, err)
}

func TestBackfillFindings_PopulatesUnmarkedScans(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Insert a scan via the legacy SaveScan (no findings table write)
	// then clear its findings_extracted_at marker to simulate a pre-migration scan.
	scan := testScanResult(testUUID("bf-1"), "host-1", "quick")
	scan.OrgID = testUUID("bf-org")
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}},
	}
	require.NoError(t, s.SaveScan(ctx, scan))
	_, err := s.pool.Exec(ctx, `UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	require.NoError(t, err)

	require.NoError(t, s.BackfillFindings(ctx))

	count := queryFindingsCount(t, s, scan.ID)
	assert.Equal(t, 1, count)
	assert.True(t, queryScanBackfilled(t, s, scan.ID))
}

func TestBackfillFindings_SkipsAlreadyMarked(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	scan := testScanResult(testUUID("bf-skip"), "host-1", "quick")
	scan.OrgID = testUUID("bf-skip-org")
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}},
	}
	// Save via the NEW path which already marks it.
	require.NoError(t, s.SaveScanWithFindings(ctx, scan, ExtractFindings(scan)))
	countBefore := queryFindingsCount(t, s, scan.ID)

	// Run backfill — should not touch already-marked scans.
	require.NoError(t, s.BackfillFindings(ctx))
	countAfter := queryFindingsCount(t, s, scan.ID)
	assert.Equal(t, countBefore, countAfter, "backfill must not re-insert findings for already-marked scans")
}

func TestBackfillFindings_Idempotent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	scan := testScanResult(testUUID("bf-idem"), "host-1", "quick")
	scan.OrgID = testUUID("bf-idem-org")
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}},
	}
	require.NoError(t, s.SaveScan(ctx, scan))
	_, _ = s.pool.Exec(ctx, `UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)

	require.NoError(t, s.BackfillFindings(ctx))
	// Clear marker again and re-run — ON CONFLICT DO NOTHING keeps it safe.
	_, _ = s.pool.Exec(ctx, `UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	require.NoError(t, s.BackfillFindings(ctx))

	count := queryFindingsCount(t, s, scan.ID)
	assert.Equal(t, 1, count, "running backfill twice must not duplicate findings")
}

func TestBackfillFindings_ContextCancellationAllowsResume(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Seed 3 scans, all unmarked.
	for i := 0; i < 3; i++ {
		scan := testScanResult(testUUID("bf-resume-"+string(rune('a'+i))), "host-"+string(rune('a'+i)), "quick")
		scan.OrgID = testUUID("bf-resume-org")
		scan.Findings = []model.Finding{
			{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}},
		}
		require.NoError(t, s.SaveScan(ctx, scan))
		_, _ = s.pool.Exec(ctx, `UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	}

	// Cancel immediately — no scans should be processed, no panic.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = s.BackfillFindings(cancelledCtx)

	// Resume with a fresh context — all scans should be processed.
	require.NoError(t, s.BackfillFindings(ctx))

	var unmarked int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM scans WHERE org_id = $1 AND findings_extracted_at IS NULL`,
		testUUID("bf-resume-org")).Scan(&unmarked)
	require.NoError(t, err)
	assert.Equal(t, 0, unmarked, "all scans should be marked after the second run")
}

func TestBackfillFindings_CountersIncrement(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Seed one scan.
	scan := testScanResult(testUUID("bf-count"), "host-1", "quick")
	scan.OrgID = testUUID("bf-count-org")
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}},
	}
	require.NoError(t, s.SaveScan(ctx, scan))
	_, _ = s.pool.Exec(ctx, `UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)

	// Reset counters (only relevant if this test shares a package-level counter).
	s.backfillScansTotal.Store(0)
	s.backfillScansFailed.Store(0)

	require.NoError(t, s.BackfillFindings(ctx))

	assert.Equal(t, uint64(1), s.backfillScansTotal.Load())
	assert.Equal(t, uint64(0), s.backfillScansFailed.Load())
}

// Helper to wait a short moment in resumability scenarios.
func waitMillis(ms int) { time.Sleep(time.Duration(ms) * time.Millisecond) }
```

- [ ] **Step 2: Run — expect compile failure (BackfillFindings + counters undefined)**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestBackfillFindings ./pkg/store/...
```

Expected: compile errors on `s.BackfillFindings`, `s.backfillScansTotal`, `s.backfillScansFailed`.

- [ ] **Step 3: Add atomic counters to `PostgresStore` struct in `pkg/store/postgres.go`**

Find the `PostgresStore` struct definition near the top of the file. Add:

```go
import "sync/atomic"  // if not already present
```

Then add to the struct:

```go
type PostgresStore struct {
    pool      *pgxpool.Pool
    encryptor *Encryptor
    // ... existing fields ...

    // Backfill counters — read by the metrics handler, written by
    // BackfillFindings. Lock-free atomics so the hot path (metric
    // scrape) costs nothing. Analytics Phase 1.
    backfillScansTotal  atomic.Uint64
    backfillScansFailed atomic.Uint64
}
```

- [ ] **Step 4: Create `backfill.go` with the implementation**

```go
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// BackfillFindings walks every scan row where findings_extracted_at
// IS NULL, unpacks result_json, extracts crypto findings, inserts them,
// and sets the marker. Safe to call repeatedly. Safe to interrupt mid-
// run — next call resumes from the next unprocessed scan.
//
// Intended to be called once from cmd/server.go after migrations run,
// in a goroutine so it doesn't block the HTTP listener. Progress is
// logged every batch. On per-scan failure the scan is MARKED anyway so
// we don't retry forever on a corrupt blob.
//
// See docs/plans/2026-04-09-analytics-phase-1-design.md §5.
func (s *PostgresStore) BackfillFindings(ctx context.Context) error {
	const batchSize = 100
	total := 0
	start := time.Now()

	for {
		if err := ctx.Err(); err != nil {
			log.Printf("backfill: context cancelled after %d scans: %v", total, err)
			return nil
		}

		scans, err := s.selectUnbackfilledScans(ctx, batchSize)
		if err != nil {
			return fmt.Errorf("backfill: select unbackfilled: %w", err)
		}
		if len(scans) == 0 {
			log.Printf("backfill: done — processed %d scans in %s", total, time.Since(start))
			return nil
		}

		for _, scanID := range scans {
			if err := ctx.Err(); err != nil {
				log.Printf("backfill: context cancelled mid-batch after %d scans", total)
				return nil
			}
			if err := s.extractAndInsertOneScan(ctx, scanID); err != nil {
				log.Printf("backfill: scan %s failed: %v — marking as processed anyway", scanID, err)
				s.backfillScansFailed.Add(1)
			} else {
				s.backfillScansTotal.Add(1)
			}
			// Always mark so we don't retry forever on a corrupt row.
			if err := s.markScanBackfilled(ctx, scanID); err != nil {
				return fmt.Errorf("backfill: mark scan %s: %w", scanID, err)
			}
			total++
		}
		log.Printf("backfill: progress — %d scans processed", total)
	}
}

// selectUnbackfilledScans returns up to `limit` scan IDs whose
// findings_extracted_at is NULL. Ordered by ID for determinism.
func (s *PostgresStore) selectUnbackfilledScans(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM scans
		WHERE findings_extracted_at IS NULL
		ORDER BY id
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// extractAndInsertOneScan fetches a scan, decrypts + unmarshals its
// payload, runs ExtractFindings, and bulk-inserts the result inside a
// transaction.
func (s *PostgresStore) extractAndInsertOneScan(ctx context.Context, scanID string) error {
	var payload []byte
	err := s.pool.QueryRow(ctx, `SELECT result_json FROM scans WHERE id = $1`, scanID).Scan(&payload)
	if err != nil {
		return fmt.Errorf("fetch scan payload: %w", err)
	}

	// Decrypt if an encryptor is configured. The existing SaveScan/
	// GetScan path handles this; we replicate the decrypt step here.
	plaintext, err := maybeDecrypt(payload, s.encryptor)
	if err != nil {
		return fmt.Errorf("decrypt scan payload: %w", err)
	}

	var scan model.ScanResult
	if err := json.Unmarshal(plaintext, &scan); err != nil {
		return fmt.Errorf("unmarshal scan: %w", err)
	}
	// SaveScan may not persist OrgID/Hostname inside result_json — they're
	// on the row. Re-hydrate from the scans table row so extraction has
	// the right values.
	if err := s.pool.QueryRow(ctx, `SELECT org_id, hostname FROM scans WHERE id = $1`, scanID).Scan(&scan.OrgID, &scan.Hostname); err != nil {
		return fmt.Errorf("rehydrate org/hostname: %w", err)
	}
	scan.ID = scanID

	findings := ExtractFindings(&scan)
	if len(findings) == 0 {
		return nil // scan had no crypto findings, still valid
	}

	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return insertFindingsInTx(ctx, tx, findings)
	})
}

// markScanBackfilled sets findings_extracted_at = NOW() for the given scan.
func (s *PostgresStore) markScanBackfilled(ctx context.Context, scanID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE scans SET findings_extracted_at = NOW() WHERE id = $1`, scanID)
	return err
}
```

**⚠️ Important:** the `maybeDecrypt` helper referenced above must already exist in `pkg/store/encryption.go`. If it's named differently (e.g. `decryptPayload`, `unwrapEnvelope`), replace the call. If no such helper exists, inline the equivalent logic from the existing `GetScan` method (which also decrypts). Also make sure `model` and `pgx` are imported at the top of `backfill.go`.

- [ ] **Step 5: Run the tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestBackfillFindings ./pkg/store/...
```

Expected: PASS (6 tests). If `maybeDecrypt` was the wrong name, fix the reference and re-run.

---

### Task 1.10: Server struct atomic fields + backfill wiring

**Files:**
- Modify: `pkg/server/server.go` (add atomic field + accessor)
- Modify: `cmd/server.go` (goroutine launcher)

- [ ] **Step 1: Add `backfillInProgress` field to the `Server` struct in `pkg/server/server.go`**

Find the `type Server struct` definition. Add inside:

```go
	// Set to true while the first-boot findings backfill goroutine is
	// running. Analytics handlers read this to emit the
	// X-Backfill-In-Progress header so the UI can show a banner.
	// Analytics Phase 1.
	backfillInProgress atomic.Bool
```

And ensure `"sync/atomic"` is imported at the top of the file.

- [ ] **Step 2: In `cmd/server.go`, after the store is initialized and before (or alongside) the HTTP listener starts, launch the backfill goroutine**

Find where the store is created (`store.NewPostgresStore(...)`) and the Server is initialized. Add:

```go
	// Kick off a one-shot background backfill of the findings
	// read-model. Runs exactly once per process start; the scan-level
	// findings_extracted_at marker makes this idempotent across
	// restarts. Bounded to 30 minutes; panics are recovered.
	// Analytics Phase 1 — see docs/plans/2026-04-09-analytics-phase-1-design.md §5.
	srv.BackfillInProgress().Store(true)
	go func() {
		defer srv.BackfillInProgress().Store(false)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("backfill: PANIC recovered: %v", r)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if err := db.BackfillFindings(ctx); err != nil {
			log.Printf("backfill: %v", err)
		}
	}()
```

- [ ] **Step 3: Add the `BackfillInProgress()` accessor to `pkg/server/server.go`**

Find the `Server` struct's method list. Add:

```go
// BackfillInProgress exposes the atomic flag so cmd/server.go can
// flip it around the backfill goroutine. Handlers read it directly
// via s.backfillInProgress.Load().
func (s *Server) BackfillInProgress() *atomic.Bool {
	return &s.backfillInProgress
}
```

- [ ] **Step 4: Compile check**

```bash
go build ./...
```

Expected: clean.

---

### Task 1.11: Update `handleSubmitScan` to use `SaveScanWithFindings`

**Files:**
- Modify: `pkg/server/handlers.go:51` (`handleSubmitScan`)

- [ ] **Step 1: Read the current handleSubmitScan to find the SaveScan call**

```bash
grep -n 'SaveScan\|store.ExtractFindings' pkg/server/handlers.go
```

- [ ] **Step 2: Replace the `s.store.SaveScan(ctx, scanResult)` call with the new extraction + combined save**

Change:

```go
if err := s.store.SaveScan(r.Context(), scanResult); err != nil {
    // ... existing error handling ...
}
```

to:

```go
findings := store.ExtractFindings(scanResult)
if err := s.store.SaveScanWithFindings(r.Context(), scanResult, findings); err != nil {
    // ... existing error handling ...
}
```

Make sure `"github.com/amiryahaya/triton/pkg/store"` is imported in `handlers.go` (it probably already is — check with grep).

- [ ] **Step 3: Run the existing scan submission integration tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/server/... 2>&1 | tail -30
```

Expected: existing tests still pass. Any test that stubbed `SaveScan` will need updating to stub `SaveScanWithFindings` too — the compiler errors will tell you which.

---

### Task 1.12: Cascade-delete test for `handleDeleteScan`

**Files:**
- Modify: `pkg/server/handlers.go` integration test file (probably `handlers_test.go` or similar)

- [ ] **Step 1: Locate the existing delete scan test**

```bash
grep -rn 'TestHandle.*DeleteScan\|handleDeleteScan' pkg/server/*_test.go
```

- [ ] **Step 2: Add a new test after the existing ones**

```go
func TestHandleDeleteScan_CascadesToFindings(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)

	// Submit a scan with a couple of findings.
	scan := testScanResult(testUUID("cascade-1"), "host-1", "quick")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}},
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "AES", KeySize: 256}},
	}
	require.NoError(t, db.SaveScanWithFindings(t.Context(), scan, store.ExtractFindings(scan)))

	countBefore := queryFindingsCount(t, db, scan.ID)
	require.Equal(t, 2, countBefore)

	// Delete the scan.
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")
	w := authReq(t, srv, http.MethodDelete, "/api/v1/scans/"+scan.ID, token, nil)
	require.Equal(t, http.StatusNoContent, w.Code, "scan delete should return 204")

	// Verify findings were cascade-deleted.
	countAfter := queryFindingsCount(t, db, scan.ID)
	assert.Equal(t, 0, countAfter, "ON DELETE CASCADE should have removed the findings rows")
}
```

**Note:** `queryFindingsCount` was created in Task 1.5 in `pkg/store/findings_test.go`. If it's in a different package, either export it (rename to `QueryFindingsCount`) or duplicate the minimal query inline in this test.

- [ ] **Step 3: Run the test**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestHandleDeleteScan_CascadesToFindings ./pkg/server/...
```

Expected: PASS.

---

### Task 1.13: Three Prometheus metrics in `handleMetrics`

**Files:**
- Modify: `pkg/server/handlers_metrics.go`
- Modify: `pkg/server/handlers_metrics_test.go`

- [ ] **Step 1: Add a failing test to `handlers_metrics_test.go`**

Append:

```go
func TestHandleMetrics_IncludesBackfillMetrics(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/metrics", "", nil)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	assert.Contains(t, body, "# HELP triton_backfill_scans_processed_total")
	assert.Contains(t, body, "# TYPE triton_backfill_scans_processed_total counter")
	assert.Contains(t, body, "triton_backfill_scans_processed_total 0")

	assert.Contains(t, body, "# HELP triton_backfill_scans_failed_total")
	assert.Contains(t, body, "triton_backfill_scans_failed_total 0")

	assert.Contains(t, body, "# HELP triton_backfill_in_progress")
	assert.Contains(t, body, "# TYPE triton_backfill_in_progress gauge")
	assert.Contains(t, body, "triton_backfill_in_progress 0")
}
```

- [ ] **Step 2: Run the test — expect failure**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestHandleMetrics_IncludesBackfillMetrics ./pkg/server/...
```

Expected: FAIL, missing strings.

- [ ] **Step 3: Add the metric output to `handleMetrics` in `handlers_metrics.go`**

Find the existing `handleMetrics` function and append (just before the closing brace / return):

```go
	// Analytics Phase 1 — backfill observability.
	// The counters live on the PostgresStore; the in-progress flag lives
	// on the Server. Type assertion to *store.PostgresStore keeps the
	// Store interface untouched. If the test harness uses a non-Postgres
	// store, the metrics appear as 0.
	scansTotal, scansFailed := uint64(0), uint64(0)
	if pg, ok := s.store.(*store.PostgresStore); ok {
		scansTotal = pg.BackfillScansTotal()
		scansFailed = pg.BackfillScansFailed()
	}
	inProgress := 0
	if s.backfillInProgress.Load() {
		inProgress = 1
	}
	fmt.Fprintf(w, "# HELP triton_backfill_scans_processed_total Scans processed by the findings backfill loop.\n")
	fmt.Fprintf(w, "# TYPE triton_backfill_scans_processed_total counter\n")
	fmt.Fprintf(w, "triton_backfill_scans_processed_total %d\n", scansTotal)
	fmt.Fprintf(w, "# HELP triton_backfill_scans_failed_total Scans that failed extraction and were marked to skip.\n")
	fmt.Fprintf(w, "# TYPE triton_backfill_scans_failed_total counter\n")
	fmt.Fprintf(w, "triton_backfill_scans_failed_total %d\n", scansFailed)
	fmt.Fprintf(w, "# HELP triton_backfill_in_progress 1 if the first-boot backfill goroutine is running, 0 otherwise.\n")
	fmt.Fprintf(w, "# TYPE triton_backfill_in_progress gauge\n")
	fmt.Fprintf(w, "triton_backfill_in_progress %d\n", inProgress)
```

- [ ] **Step 4: Add accessor methods on `PostgresStore` in `pkg/store/postgres.go`**

```go
// BackfillScansTotal returns the running count of scans successfully
// processed by the findings backfill loop. Exposed for the metrics
// endpoint. Analytics Phase 1.
func (s *PostgresStore) BackfillScansTotal() uint64 {
	return s.backfillScansTotal.Load()
}

// BackfillScansFailed returns the running count of scans that failed
// extraction and were marked to skip. Analytics Phase 1.
func (s *PostgresStore) BackfillScansFailed() uint64 {
	return s.backfillScansFailed.Load()
}
```

- [ ] **Step 5: Run the metrics test again — should pass**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestHandleMetrics_IncludesBackfillMetrics ./pkg/server/...
```

Expected: PASS.

---

### Task 1.14: Full test run + commit 1

- [ ] **Step 1: Format and vet**

```bash
make fmt
go vet ./...
```

Expected: clean.

- [ ] **Step 2: Run unit tests**

```bash
go test ./...
```

Expected: all packages PASS.

- [ ] **Step 3: Run integration tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./...
```

Expected: all packages PASS.

- [ ] **Step 4: Stage and commit**

```bash
git add \
  pkg/store/types.go \
  pkg/store/store.go \
  pkg/store/migrations.go \
  pkg/store/extract.go \
  pkg/store/extract_test.go \
  pkg/store/findings.go \
  pkg/store/findings_test.go \
  pkg/store/backfill.go \
  pkg/store/backfill_test.go \
  pkg/store/postgres.go \
  pkg/server/server.go \
  pkg/server/handlers.go \
  pkg/server/handlers_metrics.go \
  pkg/server/handlers_metrics_test.go \
  pkg/server/server_test.go \
  cmd/server.go

git commit -m "$(cat <<'EOF'
feat(server): analytics phase 1 scaffolding — findings read-model + backfill

Introduce the denormalized findings table (schema v7) and populate it
via two paths: (a) transactional extraction on scan submit in the new
SaveScanWithFindings method, (b) a first-boot background goroutine
that walks historical scans, extracts crypto findings, and marks each
scan via the new findings_extracted_at column.

Aggregation queries for the three phase-1 views (ListInventory,
ListExpiringCertificates, ListTopPriorityFindings) all filter to the
latest scan per hostname via a shared CTE, so "47 RSA-2048 instances"
means currently deployed, not historical total.

Adds three Prometheus metrics (triton_backfill_scans_processed_total,
triton_backfill_scans_failed_total, triton_backfill_in_progress) for
operator visibility into backfill progress.

Handlers, routes, and UI views land in the next three commits.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Commit group 2 — Inventory view

### Task 2.1: `handleInventory` handler + param tests

**Files:**
- Create: `pkg/server/handlers_analytics.go`
- Create: `pkg/server/handlers_analytics_test.go`

- [ ] **Step 1: Create the failing unit test for the handler**

Create `pkg/server/handlers_analytics_test.go`:

```go
//go:build integration

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

func TestHandleInventory_EmptyReturns200(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.InventoryRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Empty(t, rows)
}

func TestHandleInventory_PopulatedReturnsRows(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID("inv-h-1"), "host-1", "quick")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		{Module: "key", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}},
	}
	require.NoError(t, db.SaveScanWithFindings(t.Context(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.InventoryRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	require.Len(t, rows, 1)
	assert.Equal(t, "RSA", rows[0].Algorithm)
	assert.Equal(t, 2048, rows[0].KeySize)
}

func TestHandleInventory_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleInventory_BackfillHeaderWhenInProgress(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	srv.BackfillInProgress().Store(true)
	defer srv.BackfillInProgress().Store(false)

	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", token, nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true", w.Header().Get("X-Backfill-In-Progress"))
}
```

- [ ] **Step 2: Run — expect failure (route not registered)**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestHandleInventory ./pkg/server/...
```

Expected: 404 from unrouted path, or compile errors if `InventoryRow` isn't importable.

- [ ] **Step 3: Create `pkg/server/handlers_analytics.go` with the handler**

```go
package server

import (
	"log"
	"net/http"

	"github.com/amiryahaya/triton/pkg/store"
)

// GET /api/v1/inventory
//
// Returns the crypto inventory aggregated by (algorithm, key_size) for
// the authenticated tenant. No query parameters. Empty array if no
// findings yet. Analytics Phase 1 — see
// docs/plans/2026-04-09-analytics-phase-1-design.md §7.
func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if s.backfillInProgress.Load() {
		w.Header().Set("X-Backfill-In-Progress", "true")
	}
	orgID := TenantFromContext(r.Context())
	rows, err := s.store.ListInventory(r.Context(), orgID)
	if err != nil {
		log.Printf("inventory: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.InventoryRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}
```

- [ ] **Step 4: Register the route in `pkg/server/server.go`**

Find the existing tenant-scoped routes inside `r.Route("/api/v1", ...)`. Add alongside `r.Get("/aggregate", ...)`:

```go
		r.Get("/inventory", srv.handleInventory)
```

- [ ] **Step 5: Run the handler tests — should pass**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestHandleInventory ./pkg/server/...
```

Expected: PASS (4 tests).

---

### Task 2.2: Sidebar Analytics section + inventory link in `index.html`

**Files:**
- Modify: `pkg/server/ui/dist/index.html`

- [ ] **Step 1: Open `pkg/server/ui/dist/index.html` and locate the existing `<a href="#/trend">` link**

- [ ] **Step 2: Insert the section label + three nav entries (certificates and priority will render empty views until later tasks wire them up — but the links are present from the start)**

Add after the Trend anchor and before the Users anchor:

```html
      <div class="nav-section-label">Analytics</div>
      <a href="#/inventory" class="nav-link" data-view="inventory">
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="3" width="14" height="12" rx="1.5"/>
          <line x1="2" y1="7" x2="16" y2="7"/>
          <line x1="6" y1="7" x2="6" y2="15"/>
        </svg>
        <span>Inventory</span>
      </a>
      <a href="#/certificates" class="nav-link" data-view="certificates">
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="4" width="14" height="10" rx="1"/>
          <line x1="2" y1="8" x2="16" y2="8"/>
          <circle cx="6" cy="11" r="1"/>
          <line x1="9" y1="11" x2="14" y2="11"/>
        </svg>
        <span>Certificates</span>
      </a>
      <a href="#/priority" class="nav-link" data-view="priority">
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M4 14l3-3 3 3 4-8"/>
          <path d="M11 3h3v3"/>
        </svg>
        <span>Priority</span>
      </a>
```

- [ ] **Step 3: Verify by viewing the file**

```bash
grep -n 'nav-section-label\|#/inventory\|#/certificates\|#/priority' pkg/server/ui/dist/index.html
```

Expected: four matches.

---

### Task 2.3: Analytics CSS (shared across all three views)

**Files:**
- Modify: `pkg/server/ui/dist/style.css`

- [ ] **Step 1: Append the new styles**

```css
/* Analytics Phase 1 — shared styles across Inventory, Certificates, Priority. */

.nav-section-label {
  padding: 16px 14px 6px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #64748b;
}

.backfill-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  margin: 0 0 16px;
  border-radius: 8px;
  background: rgba(34, 211, 238, 0.08);
  border: 1px solid rgba(34, 211, 238, 0.2);
  color: #22d3ee;
  font-size: 13px;
}
.backfill-banner svg {
  flex-shrink: 0;
  animation: spin 2s linear infinite;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}

.analytics-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.analytics-table th {
  background: rgba(148, 163, 184, 0.08);
  text-align: left;
  padding: 10px 12px;
  font-weight: 600;
  color: #94a3b8;
}
.analytics-table td {
  padding: 10px 12px;
  border-top: 1px solid rgba(148, 163, 184, 0.08);
}
.analytics-table td.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.analytics-table tr.clickable-row:hover {
  background: rgba(148, 163, 184, 0.04);
  cursor: pointer;
}

.empty-state {
  padding: 40px 24px;
  text-align: center;
  color: #94a3b8;
  background: rgba(148, 163, 184, 0.04);
  border-radius: 8px;
  border: 1px dashed rgba(148, 163, 184, 0.1);
}

.summary-chips {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.summary-chip {
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12px;
  background: rgba(148, 163, 184, 0.08);
  color: #94a3b8;
}
.summary-chip strong { color: #e2e8f0; }
.summary-chip.critical { background: rgba(248, 113, 113, 0.15); color: #f87171; }
.summary-chip.critical strong { color: #f87171; }
.summary-chip.urgent   { background: rgba(251, 146, 60, 0.15); color: #fb923c; }
.summary-chip.urgent strong { color: #fb923c; }
.summary-chip.warning  { background: rgba(251, 191, 36, 0.15); color: #fbbf24; }
.summary-chip.warning strong { color: #fbbf24; }
```

- [ ] **Step 2: Verify CSS is valid by counting braces**

```bash
grep -c '{' pkg/server/ui/dist/style.css
grep -c '}' pkg/server/ui/dist/style.css
```

Expected: counts should be equal.

---

### Task 2.4: `app.js` — router cases, backfill plumbing, renderInventory

**Files:**
- Modify: `pkg/server/ui/dist/app.js`

- [ ] **Step 1: Add the backfill state near the top of the IIFE (after the `auth` object)**

Insert after the existing `auth` definition:

```js
  // Backfill state tracking — updated by api() on analytics responses,
  // read by renderBackfillBanner(). Zero cost when backfill is idle.
  // Analytics Phase 1.
  const backfillState = { inProgress: false };
  const ANALYTICS_PATHS = ['/inventory', '/certificates', '/priority'];
```

- [ ] **Step 2: Extend the `api()` function to read the backfill header on analytics responses**

Find the `api()` function. Inside it, after the `fetch(...)` line returns `resp`, add:

```js
    // Sync backfill state on every analytics response so the banner
    // disappears automatically when the backend stops sending the header.
    if (ANALYTICS_PATHS.some(p => path.startsWith(p))) {
      backfillState.inProgress = resp.headers.get('X-Backfill-In-Progress') === 'true';
    }
```

Place this BEFORE the 401 handling so the state is updated even when the response is a 401.

- [ ] **Step 3: Add the `renderBackfillBanner` helper near the other render helpers**

Place it before the first `render*()` function:

```js
  // Prepends the backfill banner to the given container if a recent
  // analytics response advertised X-Backfill-In-Progress: true.
  function renderBackfillBanner(containerEl) {
    if (!backfillState.inProgress) return;
    const html = `<div class="backfill-banner">
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="7" cy="7" r="5" stroke-dasharray="20 8"/>
      </svg>
      <span>Triton is still populating historical scan data — this view may be incomplete. Refresh in a moment for more.</span>
    </div>`;
    containerEl.insertAdjacentHTML('afterbegin', html);
  }
```

- [ ] **Step 4: Add the inventory case to the router and the `renderInventory` function**

Inside the `route()` switch, add BEFORE `case '': case 'overview':`:

```js
      case 'inventory':    renderInventory(); break;
      case 'certificates': renderCertificates(); break;
      case 'priority':     renderPriority(); break;
```

Then add the three render functions (only `renderInventory` is implemented now; `renderCertificates` and `renderPriority` are stubs until Commits 3 and 4):

```js
  async function renderInventory() {
    content.innerHTML = '<div class="loading">Loading crypto inventory...</div>';
    try {
      const rows = await api('/inventory');
      let html = `<h2>Crypto Inventory</h2>
        <p class="subtitle">Aggregated by algorithm and key size across all machines in your organization (latest scan per host).</p>`;
      if (rows.length === 0) {
        html += `<div class="empty-state">No findings yet — run a scan to see your crypto inventory.</div>`;
      } else {
        html += `<table class="analytics-table">
          <thead><tr>
            <th>Algorithm</th><th>Size</th><th>Status</th>
            <th class="num">Instances</th><th class="num">Machines</th><th class="num">Max Priority</th>
          </tr></thead><tbody>`;
        for (const row of rows) {
          html += `<tr>
            <td>${escapeHtml(row.algorithm)}</td>
            <td>${row.keySize > 0 ? escapeHtml(row.keySize) : '—'}</td>
            <td>${badge(row.pqcStatus)}</td>
            <td class="num">${escapeHtml(row.instances)}</td>
            <td class="num">${escapeHtml(row.machines)}</td>
            <td class="num">${row.maxPriority > 0 ? escapeHtml(row.maxPriority) : '—'}</td>
          </tr>`;
        }
        html += `</tbody></table>`;
      }
      content.innerHTML = html;
      renderBackfillBanner(content);
    } catch (e) {
      content.innerHTML = `<div class="error">Failed to load inventory: ${escapeHtml(e.message)}</div>`;
    }
  }

  // Stubs — implemented in later commits.
  async function renderCertificates() {
    content.innerHTML = `<div class="empty-state">Certificates view coming soon.</div>`;
  }
  async function renderPriority() {
    content.innerHTML = `<div class="empty-state">Priority view coming soon.</div>`;
  }
```

- [ ] **Step 5: Manual smoke-test**

```bash
make container-build && make container-stop && make container-run
```

Then open `http://localhost:8090/ui/#/inventory` (hard refresh with Cmd+Shift+R). You should see either "No findings yet" or a populated table depending on the DB state.

---

### Task 2.5: E2E — inventory Playwright test

**Files:**
- Create: `test/e2e/analytics.spec.js`
- Modify: `test/e2e/global-setup.js` to seed a finding-bearing scan

- [ ] **Step 1: Read the existing global setup pattern**

```bash
grep -n 'POST.*scans\|CryptoAsset\|findings' test/e2e/global-setup.js | head
```

- [ ] **Step 2: Update `test/e2e/global-setup.js` to ensure at least one scan has a `CryptoAsset` so analytics views have data**

Find the existing `POST /api/v1/scans` seed calls and extend one of their findings arrays to include a `cryptoAsset` object:

```js
findings: [
  {
    module: 'key',
    category: 'key',
    filePath: '/etc/pki/test.key',
    lineNumber: 0,
    cryptoAsset: {
      algorithm: 'RSA',
      keySize: 2048,
      pqcStatus: 'DEPRECATED',
      migrationPriority: 80,
    },
  },
  // ... other existing findings ...
],
```

- [ ] **Step 3: Create `test/e2e/analytics.spec.js`**

```js
const { test, expect } = require('@playwright/test');

test.describe('Analytics — Inventory view', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/');
    // Login flow — adapt to existing helper if one exists
    await page.fill('#loginEmail', 'admin@example.com');
    await page.fill('#loginPassword', 'admin-e2e-password');
    await page.click('button[type="submit"]');
    await page.waitForURL(/#\/$/);
  });

  test('sidebar shows Analytics section with three entries', async ({ page }) => {
    const section = page.locator('.nav-section-label', { hasText: 'Analytics' });
    await expect(section).toBeVisible();
    await expect(page.locator('a[href="#/inventory"]')).toBeVisible();
    await expect(page.locator('a[href="#/certificates"]')).toBeVisible();
    await expect(page.locator('a[href="#/priority"]')).toBeVisible();
  });

  test('clicking Inventory loads the crypto inventory view', async ({ page }) => {
    await page.click('a[href="#/inventory"]');
    await expect(page.locator('h2', { hasText: 'Crypto Inventory' })).toBeVisible();
  });

  test('inventory table renders rows from seeded data', async ({ page }) => {
    await page.click('a[href="#/inventory"]');
    const table = page.locator('.analytics-table');
    await expect(table).toBeVisible();
    // global-setup seeds at least one RSA-2048 finding
    const rsaRow = page.locator('.analytics-table tbody tr', { hasText: 'RSA' });
    await expect(rsaRow).toBeVisible();
  });
});
```

**Note:** The login credentials above are assumed from the existing E2E setup. Match whatever `test/e2e/global-setup.js` uses.

- [ ] **Step 4: Run the E2E tests**

```bash
make test-e2e 2>&1 | tail -20
```

Expected: 3 new tests PASS. If login credentials differ, adjust and re-run.

---

### Task 2.6: Commit 2

- [ ] **Step 1: Format and full test pass**

```bash
make fmt
go vet ./...
go test ./...
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./...
```

- [ ] **Step 2: Stage and commit**

```bash
git add \
  pkg/server/handlers_analytics.go \
  pkg/server/handlers_analytics_test.go \
  pkg/server/server.go \
  pkg/server/ui/dist/index.html \
  pkg/server/ui/dist/app.js \
  pkg/server/ui/dist/style.css \
  test/e2e/analytics.spec.js \
  test/e2e/global-setup.js

git commit -m "$(cat <<'EOF'
feat(server): analytics phase 1 — crypto inventory view

First of three analytics dashboard views. Adds the GET /api/v1/inventory
endpoint aggregating findings by (algorithm, key_size) filtered to the
latest scan per hostname, plus the Analytics sidebar section, the
Inventory render function in app.js, shared analytics CSS, and the
X-Backfill-In-Progress header plumbing with inline banner.

Certificates and Priority views land in the next two commits.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Commit group 3 — Certificates view

### Task 3.1: `handleExpiringCertificates` + param tests

**Files:**
- Modify: `pkg/server/handlers_analytics.go` (append)
- Modify: `pkg/server/handlers_analytics_test.go` (append)

- [ ] **Step 1: Append failing tests**

```go
func TestHandleExpiringCerts_DefaultWindow(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	in30 := time.Now().UTC().Add(30 * 24 * time.Hour)
	in200 := time.Now().UTC().Add(200 * 24 * time.Hour)

	scan := testScanResult(testUUID("certs-def-1"), "host-1", "quick")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in30, Subject: "CN=soon"}},
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in200, Subject: "CN=later"}},
	}
	require.NoError(t, db.SaveScanWithFindings(t.Context(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/certificates/expiring", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.ExpiringCertRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 1, "default 90-day window excludes the 200-day cert")
}

func TestHandleExpiringCerts_WithinAll(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	in500 := time.Now().UTC().Add(500 * 24 * time.Hour)
	scan := testScanResult(testUUID("certs-all-1"), "host-1", "quick")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		{Module: "certificate", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in500, Subject: "CN=far"}},
	}
	require.NoError(t, db.SaveScanWithFindings(t.Context(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/certificates/expiring?within=all", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.ExpiringCertRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 1)
}

func TestHandleExpiringCerts_InvalidWithin(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	for _, param := range []string{"abc", "-1", "5000"} {
		t.Run(param, func(t *testing.T) {
			w := authReq(t, srv, http.MethodGet, "/api/v1/certificates/expiring?within="+param, token, nil)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}
```

- [ ] **Step 2: Run — expect 404**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestHandleExpiringCerts ./pkg/server/...
```

- [ ] **Step 3: Append handler to `handlers_analytics.go`**

```go
// GET /api/v1/certificates/expiring?within=<days>|all
//
// within=<N>   certs expiring within N days (plus any already-expired)
// within=all   all future expiries (handler passes 100 years to the store)
// (missing)    default 90 days
func (s *Server) handleExpiringCertificates(w http.ResponseWriter, r *http.Request) {
	if s.backfillInProgress.Load() {
		w.Header().Set("X-Backfill-In-Progress", "true")
	}
	orgID := TenantFromContext(r.Context())

	withinParam := strings.TrimSpace(r.URL.Query().Get("within"))
	var within time.Duration
	switch {
	case withinParam == "":
		within = 90 * 24 * time.Hour
	case withinParam == "all":
		within = 100 * 365 * 24 * time.Hour
	default:
		days, err := strconv.Atoi(withinParam)
		if err != nil || days < 0 || days > 3650 {
			writeError(w, http.StatusBadRequest, "within must be a non-negative integer (days, 0-3650) or 'all'")
			return
		}
		within = time.Duration(days) * 24 * time.Hour
	}

	rows, err := s.store.ListExpiringCertificates(r.Context(), orgID, within)
	if err != nil {
		log.Printf("expiring certs: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.ExpiringCertRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}
```

Make sure `"strconv"`, `"strings"`, and `"time"` are imported at the top of `handlers_analytics.go`.

- [ ] **Step 4: Register the route in `pkg/server/server.go`**

Add alongside `r.Get("/inventory", srv.handleInventory)`:

```go
		r.Get("/certificates/expiring", srv.handleExpiringCertificates)
```

- [ ] **Step 5: Run — expect PASS**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestHandleExpiringCerts ./pkg/server/...
```

Expected: 5 tests PASS.

---

### Task 3.2: `renderCertificates` in `app.js`

**Files:**
- Modify: `pkg/server/ui/dist/app.js`

- [ ] **Step 1: Replace the stub `renderCertificates` from Task 2.4 with the real implementation**

Find and replace:

```js
  async function renderCertificates() {
    content.innerHTML = `<div class="empty-state">Certificates view coming soon.</div>`;
  }
```

with:

```js
  // In-memory state for the certificates view so the filter chips can
  // toggle without a full re-render of the sidebar/chrome.
  let certFilterDays = 90; // 'all' | number

  async function renderCertificates() {
    content.innerHTML = '<div class="loading">Loading certificates...</div>';
    try {
      const param = certFilterDays === 'all' ? 'all' : String(certFilterDays);
      const rows = await api(`/certificates/expiring?within=${param}`);

      // Summary counts across ALL rows we got (which already excludes >window).
      const now = new Date();
      let expired = 0, urgent = 0, warning = 0;
      for (const r of rows) {
        if (r.daysRemaining < 0) expired++;
        else if (r.daysRemaining <= 30) urgent++;
        else if (r.daysRemaining <= 90) warning++;
      }

      let html = `<h2>Expiring Certificates</h2>
        <p class="subtitle">Latest-scan certificates sorted by soonest expiry.</p>
        <div class="summary-chips">
          <div class="summary-chip critical"><strong>${expired}</strong> expired</div>
          <div class="summary-chip urgent"><strong>${urgent}</strong> within 30 days</div>
          <div class="summary-chip warning"><strong>${warning}</strong> within 90 days</div>
          <div class="summary-chip"><strong>${rows.length}</strong> shown</div>
        </div>
        <div class="form-row" style="gap:8px;margin-bottom:12px">
          ${['30','90','180','all'].map(d => {
            const active = String(certFilterDays) === d;
            return `<button class="btn" data-window="${d}" style="opacity:${active?'1':'0.6'}">${d === 'all' ? 'All' : d + ' days'}</button>`;
          }).join('')}
        </div>`;

      if (rows.length === 0) {
        html += `<div class="empty-state">No certificates match this filter.</div>`;
      } else {
        html += `<table class="analytics-table">
          <thead><tr>
            <th>Subject</th><th>Host</th><th>Algorithm</th>
            <th class="num">Expires in</th><th>Status</th>
          </tr></thead><tbody>`;
        for (const row of rows) {
          const days = row.daysRemaining;
          const daysText = days < 0 ? `expired ${-days}d ago` : `${days} days`;
          html += `<tr>
            <td>${escapeHtml(row.subject)}</td>
            <td>${escapeHtml(row.hostname)}</td>
            <td>${escapeHtml(row.algorithm)}${row.keySize ? '-' + escapeHtml(row.keySize) : ''}</td>
            <td class="num">${daysText}</td>
            <td>${badge(row.status)}</td>
          </tr>`;
        }
        html += `</tbody></table>`;
      }

      content.innerHTML = html;
      renderBackfillBanner(content);

      // Wire up filter buttons.
      $$('button[data-window]').forEach(btn => {
        btn.addEventListener('click', () => {
          const v = btn.dataset.window;
          certFilterDays = v === 'all' ? 'all' : parseInt(v, 10);
          renderCertificates();
        });
      });
    } catch (e) {
      content.innerHTML = `<div class="error">Failed to load certificates: ${escapeHtml(e.message)}</div>`;
    }
  }
```

- [ ] **Step 2: Smoke-test in the browser**

Rebuild and navigate to `#/certificates` — expect the chip row and table to render.

---

### Task 3.3: E2E — certificates view

**Files:**
- Modify: `test/e2e/analytics.spec.js` (append)
- Modify: `test/e2e/global-setup.js` (add a cert finding with `notAfter`)

- [ ] **Step 1: Extend `global-setup.js` to seed a cert finding**

Add to the findings array:

```js
{
  module: 'certificate',
  category: 'cert',
  cryptoAsset: {
    algorithm: 'RSA',
    keySize: 2048,
    subject: 'CN=e2e.test',
    notAfter: new Date(Date.now() + 15 * 86400000).toISOString(),
    pqcStatus: 'DEPRECATED',
  },
},
```

- [ ] **Step 2: Append certificate tests to `analytics.spec.js`**

```js
test.describe('Analytics — Certificates view', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/');
    await page.fill('#loginEmail', 'admin@example.com');
    await page.fill('#loginPassword', 'admin-e2e-password');
    await page.click('button[type="submit"]');
    await page.waitForURL(/#\/$/);
  });

  test('clicking Certificates loads the view with filter chips', async ({ page }) => {
    await page.click('a[href="#/certificates"]');
    await expect(page.locator('h2', { hasText: 'Expiring Certificates' })).toBeVisible();
    await expect(page.locator('button[data-window="90"]')).toBeVisible();
    await expect(page.locator('button[data-window="all"]')).toBeVisible();
  });

  test('seeded cert appears in the default view', async ({ page }) => {
    await page.click('a[href="#/certificates"]');
    const row = page.locator('.analytics-table tbody tr', { hasText: 'CN=e2e.test' });
    await expect(row).toBeVisible();
  });

  test('clicking the 30-day filter narrows the table', async ({ page }) => {
    await page.click('a[href="#/certificates"]');
    await page.click('button[data-window="30"]');
    // The seeded cert is 15 days out, so it should still be visible.
    await expect(page.locator('.analytics-table tbody tr', { hasText: 'CN=e2e.test' })).toBeVisible();
  });
});
```

- [ ] **Step 3: Run E2E**

```bash
make test-e2e 2>&1 | tail -20
```

Expected: new tests PASS.

---

### Task 3.4: Commit 3

- [ ] **Step 1: Test pass**

```bash
make fmt
go test ./...
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./...
```

- [ ] **Step 2: Commit**

```bash
git add \
  pkg/server/handlers_analytics.go \
  pkg/server/handlers_analytics_test.go \
  pkg/server/server.go \
  pkg/server/ui/dist/app.js \
  test/e2e/analytics.spec.js \
  test/e2e/global-setup.js

git commit -m "$(cat <<'EOF'
feat(server): analytics phase 1 — expiring certificates view

Second of three analytics views. Adds GET /api/v1/certificates/expiring
with a configurable time window (default 90 days, ?within=N for N days
up to 3650, ?within=all for a 100-year look-ahead). Already-expired
certs are always included regardless of the window so operators can
always see the fires.

UI adds filter chips (30/90/180/all) with inline re-fetching, summary
count chips (expired / urgent / warning / shown), and a sortable table
of subject, host, algorithm, days-remaining, and status badge.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Commit group 4 — Priority view + docs

### Task 4.1: `handlePriorityFindings` + param tests

**Files:**
- Modify: `pkg/server/handlers_analytics.go` (append)
- Modify: `pkg/server/handlers_analytics_test.go` (append)

- [ ] **Step 1: Append failing tests**

```go
func TestHandlePriority_DefaultLimit(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID("prio-def-1"), "host-1", "quick")
	scan.OrgID = org.ID
	for i := 0; i < 25; i++ {
		scan.Findings = append(scan.Findings, model.Finding{
			Module: "key",
			CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i},
		})
	}
	require.NoError(t, db.SaveScanWithFindings(t.Context(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/priority", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.PriorityRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 20, "default limit is 20")
}

func TestHandlePriority_CustomLimit(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID("prio-cust-1"), "host-1", "quick")
	scan.OrgID = org.ID
	for i := 0; i < 10; i++ {
		scan.Findings = append(scan.Findings, model.Finding{
			Module: "key",
			CryptoAsset: &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i},
		})
	}
	require.NoError(t, db.SaveScanWithFindings(t.Context(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/priority?limit=5", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.PriorityRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 5)
}

func TestHandlePriority_InvalidLimit(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	for _, param := range []string{"0", "-1", "1001", "abc"} {
		t.Run(param, func(t *testing.T) {
			w := authReq(t, srv, http.MethodGet, "/api/v1/priority?limit="+param, token, nil)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}
```

- [ ] **Step 2: Run — expect 404**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestHandlePriority ./pkg/server/...
```

- [ ] **Step 3: Append handler to `handlers_analytics.go`**

```go
// GET /api/v1/priority?limit=<N>
//
// Returns the top N findings by migration_priority descending, filtered
// to the latest scan per hostname. Priority-0 findings are excluded.
// limit missing → 20, limit must be 1..1000.
func (s *Server) handlePriorityFindings(w http.ResponseWriter, r *http.Request) {
	if s.backfillInProgress.Load() {
		w.Header().Set("X-Backfill-In-Progress", "true")
	}
	orgID := TenantFromContext(r.Context())

	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 1000")
			return
		}
		limit = n
	}

	rows, err := s.store.ListTopPriorityFindings(r.Context(), orgID, limit)
	if err != nil {
		log.Printf("priority: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.PriorityRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}
```

- [ ] **Step 4: Register route**

Add alongside the other two in `pkg/server/server.go`:

```go
		r.Get("/priority", srv.handlePriorityFindings)
```

- [ ] **Step 5: Run — expect PASS**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration -run TestHandlePriority ./pkg/server/...
```

Expected: 6 tests PASS.

---

### Task 4.2: `renderPriority` in `app.js`

**Files:**
- Modify: `pkg/server/ui/dist/app.js`

- [ ] **Step 1: Replace the stub `renderPriority`**

```js
  async function renderPriority() {
    content.innerHTML = '<div class="loading">Loading priority findings...</div>';
    try {
      const rows = await api('/priority?limit=20');

      // Bucket counts.
      let critical = 0, high = 0, medium = 0;
      for (const r of rows) {
        if (r.priority >= 80) critical++;
        else if (r.priority >= 60) high++;
        else if (r.priority >= 40) medium++;
      }

      let html = `<h2>Migration Priority</h2>
        <p class="subtitle">Top findings to fix first, ranked by migration priority score (latest scan per host).</p>
        <div class="card-grid">
          <div class="card unsafe"><div class="value">${critical}</div><div class="label">Critical (≥80)</div></div>
          <div class="card deprecated"><div class="value">${high}</div><div class="label">High (60–79)</div></div>
          <div class="card transitional"><div class="value">${medium}</div><div class="label">Medium (40–59)</div></div>
          <div class="card info"><div class="value">${rows.length}</div><div class="label">Shown (top 20)</div></div>
        </div>`;

      if (rows.length === 0) {
        html += `<div class="empty-state">No priority findings yet — run a scan.</div>`;
      } else {
        html += `<table class="analytics-table">
          <thead><tr>
            <th class="num">Score</th><th>Algorithm</th><th>Category</th>
            <th>Host</th><th>Location</th><th>Status</th>
          </tr></thead><tbody>`;
        for (const row of rows) {
          const algo = row.algorithm + (row.keySize ? '-' + row.keySize : '');
          const loc = row.filePath
            ? (row.lineNumber ? `${row.filePath}:${row.lineNumber}` : row.filePath)
            : '—';
          html += `<tr>
            <td class="num">${escapeHtml(row.priority)}</td>
            <td>${escapeHtml(algo)}</td>
            <td>${escapeHtml(row.category)}</td>
            <td>${escapeHtml(row.hostname)}</td>
            <td><code>${escapeHtml(loc)}</code></td>
            <td>${badge(row.pqcStatus)}</td>
          </tr>`;
        }
        html += `</tbody></table>`;
      }

      content.innerHTML = html;
      renderBackfillBanner(content);
    } catch (e) {
      content.innerHTML = `<div class="error">Failed to load priority findings: ${escapeHtml(e.message)}</div>`;
    }
  }
```

- [ ] **Step 2: Smoke-test in the browser**

Rebuild, navigate to `#/priority`, verify the card row and table render.

---

### Task 4.3: E2E — priority view

**Files:**
- Modify: `test/e2e/analytics.spec.js` (append)

- [ ] **Step 1: Append priority tests**

```js
test.describe('Analytics — Priority view', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/');
    await page.fill('#loginEmail', 'admin@example.com');
    await page.fill('#loginPassword', 'admin-e2e-password');
    await page.click('button[type="submit"]');
    await page.waitForURL(/#\/$/);
  });

  test('clicking Priority loads the view with summary cards', async ({ page }) => {
    await page.click('a[href="#/priority"]');
    await expect(page.locator('h2', { hasText: 'Migration Priority' })).toBeVisible();
    await expect(page.locator('.card .label', { hasText: 'Critical' })).toBeVisible();
  });

  test('priority table shows rows sorted by score', async ({ page }) => {
    await page.click('a[href="#/priority"]');
    const firstScore = await page.locator('.analytics-table tbody tr:nth-child(1) td.num').first().textContent();
    const secondScore = await page.locator('.analytics-table tbody tr:nth-child(2) td.num').first().textContent();
    if (firstScore && secondScore) {
      expect(Number(firstScore)).toBeGreaterThanOrEqual(Number(secondScore));
    }
  });
});
```

- [ ] **Step 2: Run**

```bash
make test-e2e 2>&1 | tail -20
```

Expected: new tests PASS.

---

### Task 4.4: Documentation updates

**Files:**
- Modify: `docs/DEPLOYMENT_GUIDE.md`
- Modify: `docs/SYSTEM_ARCHITECTURE.md`

- [ ] **Step 1: Add an Analytics section to `docs/DEPLOYMENT_GUIDE.md`**

Append at the end of the existing document (or in the most appropriate existing section):

```markdown
## Analytics Dashboard (Phase 1)

The report server's web UI includes three analytical views under the
"Analytics" sidebar section:

- **Crypto Inventory** (`#/inventory`) — aggregated by algorithm and
  key size across the org (latest scan per host)
- **Expiring Certificates** (`#/certificates`) — certificates sorted
  by soonest expiry, with 30/90/180-day filter chips
- **Migration Priority** (`#/priority`) — top 20 findings by priority
  score, read-only

All three views read from a denormalized `findings` table that is
populated on every scan submit (transactionally alongside the scan
row) and, for historical data, via a first-boot background goroutine
that walks `scans.result_json` and extracts crypto findings. The
goroutine runs once per process start, bounded to 30 minutes, and is
idempotent across restarts via a `findings_extracted_at` marker column.

### Backfill observability

Three Prometheus metrics expose backfill progress via `/api/v1/metrics`:

- `triton_backfill_scans_processed_total` — counter of successfully
  processed scans
- `triton_backfill_scans_failed_total` — counter of scans that failed
  extraction and were marked to skip (check logs for details)
- `triton_backfill_in_progress` — gauge, 1 while the goroutine is
  running, 0 otherwise

While backfill is in progress, analytics API responses include an
`X-Backfill-In-Progress: true` header and the UI shows an inline
cyan banner on the affected views.

### Recovery runbook

The `findings` table is a **read-model** over `scans.result_json`.
Dropping or truncating it loses nothing permanent — it can always be
rebuilt from the scan blobs.

**If the findings table has stale or wrong data:**

```sql
TRUNCATE findings;
UPDATE scans SET findings_extracted_at = NULL;
```

Then restart the report server — the backfill goroutine will re-run
automatically and repopulate the table.

**If the schema itself needs to be rolled back (worst case):**

```sql
DROP TABLE findings;
ALTER TABLE scans DROP COLUMN findings_extracted_at;
```

Redeploy with a schema v6 binary. The report server will work
without analytics views until v7 is re-applied.
```

- [ ] **Step 2: Add a paragraph to `docs/SYSTEM_ARCHITECTURE.md`**

Find the section describing the storage layer (`pkg/store/`) and add:

```markdown
### Findings read-model (Analytics Phase 1)

The `findings` table is a denormalized read-model populated from
`scans.result_json`. Unlike `scans`, which is the source of truth
and is optionally encrypted at rest, `findings` stores one row per
`CryptoAsset` with columns extracted for fast aggregation:
`algorithm`, `key_size`, `pqc_status`, `migration_priority`,
`not_after`, and so on.

Populated via two paths:
1. **Hot-path**: `SaveScanWithFindings` inserts findings atomically
   alongside the scan row inside a single transaction.
2. **Backfill**: a first-boot goroutine walks existing scans with
   `findings_extracted_at IS NULL` and extracts their findings.

All three Phase 1 aggregation queries (`ListInventory`,
`ListExpiringCertificates`, `ListTopPriorityFindings`) filter to the
latest scan per hostname via a shared CTE, so the numbers reflect
"what's currently deployed" rather than the full historical footprint.
```

- [ ] **Step 3: Update `MEMORY.md` with a Phase 1 completion marker**

Find the "Important Files" or similar section and add:

```markdown
## Analytics Phase 1 (completed 2026-04-DD, commit <hash>)
- **New table**: `findings` — denormalized per-finding read-model over `scans.result_json`, populated transactionally on submit and via first-boot backfill goroutine
- **Three views**: Inventory (`#/inventory`), Expiring Certificates (`#/certificates`, default 90 days), Migration Priority (`#/priority`, top 20 read-only)
- **Three endpoints**: `GET /api/v1/inventory`, `/certificates/expiring`, `/priority` — all tenant-scoped, filter to latest scan per hostname
- **Three metrics**: `triton_backfill_scans_processed_total`, `triton_backfill_scans_failed_total`, `triton_backfill_in_progress`
- **Sidebar**: new grouped "Analytics" section (first use of `.nav-section-label`)
- **Rollback**: findings table is a read-model; `TRUNCATE findings; UPDATE scans SET findings_extracted_at = NULL;` rebuilds from source of truth
- **Spec**: `docs/plans/2026-04-09-analytics-phase-1-design.md`
- **Plan**: `docs/plans/2026-04-09-analytics-phase-1-plan.md`
```

Leave `<hash>` as a placeholder until after the final commit.

---

### Task 4.5: Final test pass + commit 4

- [ ] **Step 1: Full test run**

```bash
make fmt
go vet ./...
go test ./...
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./...
make test-e2e
```

Expected: everything green.

- [ ] **Step 2: Stage and commit**

```bash
git add \
  pkg/server/handlers_analytics.go \
  pkg/server/handlers_analytics_test.go \
  pkg/server/server.go \
  pkg/server/ui/dist/app.js \
  test/e2e/analytics.spec.js \
  docs/DEPLOYMENT_GUIDE.md \
  docs/SYSTEM_ARCHITECTURE.md

git commit -m "$(cat <<'EOF'
feat(server): analytics phase 1 — migration priority view + docs

Final analytics view for Phase 1. Adds GET /api/v1/priority returning
the top N findings by migration_priority descending (default 20, range
1-1000). UI renders four summary cards (Critical/High/Medium/Shown)
plus a sortable table with score, algorithm, category, host, location,
and status.

Also updates docs/DEPLOYMENT_GUIDE.md with an Analytics section
covering backfill observability (three Prometheus metrics), the
X-Backfill-In-Progress header semantics, and the recovery runbook
(TRUNCATE findings + UPDATE scans SET findings_extracted_at = NULL).
Adds a read-model paragraph to docs/SYSTEM_ARCHITECTURE.md.

Closes Analytics Phase 1. Phase 2 (Executive Summary) is next.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 3: Push to GitHub and open a PR**

```bash
git push -u origin feat/analytics-phase-1
gh pr create --title "feat(server): analytics phase 1 — inventory, certificates, priority views" --body "$(cat <<'EOF'
## Summary

Ships the first of six planned analytics phases (see `docs/plans/2026-04-09-analytics-phases.md`).

Three new read-only analytical views in the report server web dashboard, backed by a denormalized `findings` read-model:

- **Crypto Inventory** — aggregated by `(algorithm, key_size)` across the org, latest scan per host
- **Expiring Certificates** — default 90-day window, chip filters for 30/90/180/all
- **Migration Priority** — top 20 findings by priority score, read-only

## Architecture

- New `findings` table (schema v7) as a denormalized read-model over `scans.result_json`
- Auto-backfill of historical scans on first boot via a bounded background goroutine (idempotent, resumable)
- Three Prometheus metrics for backfill observability (`triton_backfill_scans_{processed,failed}_total`, `triton_backfill_in_progress`)
- `X-Backfill-In-Progress` response header + inline cyan UI banner during the backfill window
- All queries filter to latest-scan-per-host via a shared CTE so numbers reflect "currently deployed," not historical totals

## Test plan

- [x] Unit tests for `ExtractFindings` pure function
- [x] Integration tests for `ListInventory`, `ListExpiringCertificates`, `ListTopPriorityFindings` against PostgreSQL
- [x] Integration tests for backfill (empty DB, unmarked scans, idempotency, resumability, context cancellation)
- [x] Integration tests for the three handlers (401 gate, tenant isolation, backfill header, param validation)
- [x] Playwright E2E covering all three views, sidebar navigation, and filter chip interaction
- [x] Prometheus metrics scrape test
- [x] `handleDeleteScan` cascade-to-findings test

## Rollback

`findings` is a read-model — dropping it loses nothing permanent. See `docs/DEPLOYMENT_GUIDE.md` for the recovery runbook.

## Spec

Full design rationale, decision log, and query shapes in `docs/plans/2026-04-09-analytics-phase-1-design.md`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Return the PR URL.

---

## Self-review checklist

- **Spec §1 scope** — in scope items: all four (schema + backfill, 3 handlers, 3 views, sidebar section, X-Backfill-In-Progress, Prometheus metrics) are covered by Tasks 1.2, 1.5–1.9, 1.10, 1.11, 1.13, 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 4.1, 4.2 ✓
- **Spec §2 decision log** — all 14 decisions mapped to specific tasks ✓
- **Spec §4 schema** — Task 1.2 contains the verbatim migration ✓
- **Spec §5 backfill** — Tasks 1.9 + 1.10 cover the implementation + wiring ✓
- **Spec §6 store** — Tasks 1.1, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8 cover types, interface, extraction, transactional save, and three queries ✓
- **Spec §7 API** — Tasks 2.1, 3.1, 4.1 cover the three endpoints + param validation ✓
- **Spec §8 UI** — Tasks 2.2, 2.3, 2.4, 3.2, 4.2 cover sidebar, CSS, app.js ✓
- **Spec §9 ops** — Task 1.13 covers metrics; Task 4.4 covers the rollback runbook docs ✓
- **Spec §10 testing** — Every task contains its own failing test step; E2E in Tasks 2.5, 3.3, 4.3 ✓
- **Spec §11 commit plan** — Four commits at Tasks 1.14, 2.6, 3.4, 4.5 ✓
- **No placeholders** — all code blocks are complete; no "TODO", "TBD", "implement later" strings ✓
- **Type consistency** — `Finding`, `InventoryRow`, `ExpiringCertRow`, `PriorityRow`, `SaveScanWithFindings`, `ListInventory`, `ListExpiringCertificates`, `ListTopPriorityFindings` are used identically across all tasks ✓
- **File paths** — every task specifies exact paths (`pkg/store/...`, `pkg/server/...`, `pkg/server/ui/dist/...`, `test/e2e/...`, `docs/...`) ✓
- **Commands** — every test run command includes the `TRITON_TEST_DB_URL` env var override because the project's test DB is on port 5435 (per MEMORY.md) ✓

---

# Appendix A — Plan Corrections (authored during execution)

## Why this exists

When execution began on 2026-04-09, the first implementer subagent discovered that several tasks referenced `pkg/model` and `pkg/store` APIs that didn't exist as specified in the plan. The plan was written assuming field shapes and helper function names without cross-checking them against the actual source. A validation pass was run and the affected tasks are corrected here.

**Affected tasks:** 1.1, 1.2, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.12, 1.13, 2.1, 3.1, 4.1, 4.2.

**Root causes found:**

1. `model.ScanResult.Hostname` doesn't exist — hostname is at `ScanResult.Metadata.Hostname`.
2. `model.ScanResult.Metadata.Profile` doesn't exist — it's `Metadata.ScanProfile`.
3. `model.Finding.FilePath` and `model.Finding.LineNumber` don't exist — file path is at `Finding.Source.Path`; no line-number field exists anywhere in the model.
4. `model.Finding.Category` is a `ModuleCategory int` enum (4 coarse values), not a string — trying to set `Category: "key"` in a struct literal doesn't compile. The scanner **module name** (`Finding.Module`) is the granular drill-down field, and `Category` is deliberately not stored in the findings table.
5. `marshalScanPayload()` and `maybeDecrypt()` helpers referenced by the plan don't exist — the actual pattern in `pkg/store/postgres.go::SaveScan` uses `json.Marshal(result)` followed by `s.loadEncryptor().Encrypt(blob)` (or `Decrypt` on read), both inline.
6. `scan.Summary.TotalCryptoAssets` exists but `SaveScan` uses `scan.Summary.TotalFindings` for the `total_findings` column — match that.
7. `pgx.BeginFunc` works but isn't the codebase's idiom — `s.pool.BeginTx(ctx, pgx.TxOptions{})` + defer Rollback + explicit Commit is (see `pkg/licensestore/postgres.go:325`).
8. `testScanResult` has **two different signatures** depending on package:
   - `pkg/store/store_test.go:55`: `testScanResult(id, hostname, profile string)` — 3 args, does NOT set OrgID
   - `pkg/server/server_test.go:217`: `testScanResult(id, hostname string)` — 2 args, DOES set `OrgID: testOrgID` (the constant `"00000000-0000-0000-0000-000000000abc"`)
9. `testUUID` has **two different signatures**:
   - `pkg/store/store_test.go:24`: `testUUID(name string) string` — deterministic UUIDv5 from name
   - `pkg/server/server_test.go:31`: `testUUID(n int) string` — deterministic from int
10. Downstream consequences of dropping `Category` and `LineNumber` from `Finding`/`PriorityRow`: SQL queries, scan-row targets, UI render functions, and several test assertions all need updating.

## A.1 — Task 1.1 corrected `Finding` and `PriorityRow`

**Status:** ✅ Already applied to `pkg/store/types.go` during validation pass.

The `Finding` struct drops `Category string` and `LineNumber int`. The `PriorityRow` struct drops `Category string` and `LineNumber int`.

Correct `Finding`:

```go
// Finding is the denormalized per-finding row stored in the findings
// table. Populated from model.Finding.CryptoAsset during extraction;
// findings without a crypto asset are skipped.
//
// Field mapping from model.Finding:
//   - Hostname comes from model.ScanResult.Metadata.Hostname
//   - FilePath comes from model.Finding.Source.Path (empty for non-file sources)
//   - Module is the scanner module name ("certificate", "library", "deps", ...)
//     and is the primary drill-down discriminator. model.Finding.Category
//     (a coarse ModuleCategory enum) is intentionally NOT stored — Module
//     carries the granular information Phase 1 views care about.
type Finding struct {
	ID                string
	ScanID            string
	OrgID             string
	Hostname          string
	FindingIndex      int
	Module            string
	FilePath          string
	Algorithm         string
	KeySize           int
	PQCStatus         string
	MigrationPriority int
	NotAfter          *time.Time
	Subject           string
	Issuer            string
	Reachability      string
	CreatedAt         time.Time
}
```

Correct `PriorityRow`:

```go
// PriorityRow is one row in the Migration Priority view.
//
// Module is the scanner module name ("certificate", "library", ...);
// we don't store a separate "category" field — the coarse
// ModuleCategory enum from the model package wasn't useful for
// drill-down, and Module carries the granular information.
type PriorityRow struct {
	FindingID string `json:"findingId"`
	Priority  int    `json:"priority"`
	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"keySize,omitempty"`
	PQCStatus string `json:"pqcStatus"`
	Module    string `json:"module"`
	Hostname  string `json:"hostname"`
	FilePath  string `json:"filePath,omitempty"`
}
```

`InventoryRow` and `ExpiringCertRow` are unchanged from the original Task 1.1.

## A.2 — Task 1.2 corrected migration v7

**Status:** ✅ Already applied to `pkg/store/migrations.go` during validation pass.

Drop `category TEXT NOT NULL` and `line_number INTEGER NOT NULL DEFAULT 0` from the `findings` table definition. The rest of the migration is unchanged.

Correct CREATE TABLE:

```sql
CREATE TABLE IF NOT EXISTS findings (
    id                  UUID PRIMARY KEY,
    scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    org_id              UUID NOT NULL,
    hostname            TEXT NOT NULL,
    finding_index       INTEGER NOT NULL,
    module              TEXT NOT NULL,
    file_path           TEXT NOT NULL DEFAULT '',
    algorithm           TEXT NOT NULL,
    key_size            INTEGER NOT NULL DEFAULT 0,
    pqc_status          TEXT NOT NULL DEFAULT '',
    migration_priority  INTEGER NOT NULL DEFAULT 0,
    not_after           TIMESTAMPTZ,
    subject             TEXT NOT NULL DEFAULT '',
    issuer              TEXT NOT NULL DEFAULT '',
    reachability        TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, finding_index)
);
```

Indexes + `ALTER TABLE scans ADD COLUMN IF NOT EXISTS findings_extracted_at TIMESTAMPTZ;` are unchanged.

## A.4 — Task 1.4 corrected ExtractFindings

**Status:** ✅ Already applied to `pkg/store/extract.go` and `extract_test.go` during validation pass.

Correct `pkg/store/extract.go`:

```go
package store

import (
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// ExtractFindings walks a ScanResult and produces one Finding row per
// model.Finding whose CryptoAsset is non-nil. Pure function — no DB
// access. Used by both the submit path (SaveScanWithFindings) and the
// backfill goroutine (BackfillFindings) so they produce identical rows.
//
// Field mapping from model.Finding / model.ScanResult:
//
//	Hostname ← scan.Metadata.Hostname
//	FilePath ← f.Source.Path
//	Module   ← f.Module
//	(CryptoAsset fields map 1:1 from ca)
//
// model.Finding.Category (a coarse ModuleCategory enum) is NOT stored —
// the scanner module name is the granular drill-down discriminator for
// Phase 1 views.
func ExtractFindings(scan *model.ScanResult) []Finding {
	if scan == nil || len(scan.Findings) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(scan.Findings))
	now := time.Now().UTC()
	for i := range scan.Findings {
		f := &scan.Findings[i]
		if f.CryptoAsset == nil {
			continue
		}
		ca := f.CryptoAsset
		out = append(out, Finding{
			ID:                uuid.Must(uuid.NewV7()).String(),
			ScanID:            scan.ID,
			OrgID:             scan.OrgID,
			Hostname:          scan.Metadata.Hostname,
			FindingIndex:      i,
			Module:            f.Module,
			FilePath:          f.Source.Path,
			Algorithm:         ca.Algorithm,
			KeySize:           ca.KeySize,
			PQCStatus:         ca.PQCStatus,
			MigrationPriority: ca.MigrationPriority,
			NotAfter:          ca.NotAfter,
			Subject:           ca.Subject,
			Issuer:            ca.Issuer,
			Reachability:      ca.Reachability,
			CreatedAt:         now,
		})
	}
	return out
}
```

The test file `pkg/store/extract_test.go` uses helper functions `scanWith`, `cryptoFinding`, and `plainFinding` to keep individual test bodies short. It's been checked into the working tree directly; see the git diff for the exact content.

## A.5 — Task 1.5 corrected SaveScanWithFindings

Major rewrite due to several bugs in the original: `marshalScanPayload` helper doesn't exist, `scan.Hostname`/`scan.Metadata.Profile`/`scan.Summary.TotalCryptoAssets` field references were wrong, column count was 18 instead of 16, and the pgx transaction idiom should match the rest of the codebase.

### Correct `pkg/store/findings.go`

```go
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/amiryahaya/triton/pkg/model"
)

// SaveScanWithFindings atomically creates a scan row and inserts the
// extracted crypto findings into the findings table. Marks the scan
// as backfilled on success so the background goroutine skips it.
//
// Replaces SaveScan on the hot-path write; SaveScan remains for legacy
// call sites. See docs/plans/2026-04-09-analytics-phase-1-design.md §6.
func (s *PostgresStore) SaveScanWithFindings(ctx context.Context, scan *model.ScanResult, findings []Finding) error {
	if scan == nil {
		return fmt.Errorf("cannot save nil scan result")
	}
	if scan.ID == "" {
		return fmt.Errorf("scan result must have an ID")
	}

	// Marshal + encrypt the blob using the same pattern as SaveScan.
	blob, err := json.Marshal(scan)
	if err != nil {
		return fmt.Errorf("marshalling scan result: %w", err)
	}
	if enc := s.loadEncryptor(); enc != nil {
		encrypted, encErr := enc.Encrypt(blob)
		if encErr != nil {
			return fmt.Errorf("encrypting scan result: %w", encErr)
		}
		blob = encrypted
	}

	var orgID *string
	if scan.OrgID != "" {
		orgID = &scan.OrgID
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// (1) Upsert the scan row. Column list matches SaveScan's insert plus
	// the new findings_extracted_at marker (set to NOW() so the backfill
	// goroutine skips this row).
	_, err = tx.Exec(ctx, `
		INSERT INTO scans
		  (id, hostname, timestamp, profile,
		   total_findings, safe, transitional, deprecated, unsafe,
		   result_json, org_id, findings_extracted_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		ON CONFLICT (id) DO UPDATE SET
		  hostname = EXCLUDED.hostname,
		  timestamp = EXCLUDED.timestamp,
		  profile = EXCLUDED.profile,
		  total_findings = EXCLUDED.total_findings,
		  safe = EXCLUDED.safe,
		  transitional = EXCLUDED.transitional,
		  deprecated = EXCLUDED.deprecated,
		  unsafe = EXCLUDED.unsafe,
		  result_json = EXCLUDED.result_json,
		  org_id = EXCLUDED.org_id,
		  findings_extracted_at = EXCLUDED.findings_extracted_at
	`,
		scan.ID,
		scan.Metadata.Hostname,
		scan.Metadata.Timestamp.UTC(),
		scan.Metadata.ScanProfile,
		scan.Summary.TotalFindings,
		scan.Summary.Safe,
		scan.Summary.Transitional,
		scan.Summary.Deprecated,
		scan.Summary.Unsafe,
		blob,
		orgID,
	)
	if err != nil {
		return fmt.Errorf("upsert scan: %w", err)
	}

	// (2) Bulk-insert the findings. Idempotent via ON CONFLICT so retries
	// or re-runs of the backfill are safe.
	if err := insertFindingsInTx(ctx, tx, findings); err != nil {
		return fmt.Errorf("insert findings: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// insertFindingsInTx bulk-inserts findings using chunked VALUES lists
// to avoid the pgx parameter limit (65535). 1000 rows × 16 cols = 16000
// params per chunk keeps us well under the limit.
func insertFindingsInTx(ctx context.Context, tx pgx.Tx, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	const chunkSize = 1000
	for start := 0; start < len(findings); start += chunkSize {
		end := start + chunkSize
		if end > len(findings) {
			end = len(findings)
		}
		if err := insertFindingsChunk(ctx, tx, findings[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// insertFindingsChunk inserts up to 1000 finding rows in a single
// statement. Column count: 16.
func insertFindingsChunk(ctx context.Context, tx pgx.Tx, chunk []Finding) error {
	const cols = 16
	args := make([]any, 0, len(chunk)*cols)
	valueStrs := make([]string, 0, len(chunk))
	for i, f := range chunk {
		base := i * cols
		valueStrs = append(valueStrs, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8,
			base+9, base+10, base+11, base+12, base+13, base+14, base+15, base+16,
		))
		args = append(args,
			f.ID, f.ScanID, f.OrgID, f.Hostname, f.FindingIndex,
			f.Module, f.FilePath,
			f.Algorithm, f.KeySize, f.PQCStatus, f.MigrationPriority,
			f.NotAfter, f.Subject, f.Issuer, f.Reachability, f.CreatedAt,
		)
	}

	sql := `INSERT INTO findings (
		id, scan_id, org_id, hostname, finding_index,
		module, file_path,
		algorithm, key_size, pqc_status, migration_priority,
		not_after, subject, issuer, reachability, created_at
	) VALUES ` + strings.Join(valueStrs, ",") + `
	ON CONFLICT (scan_id, finding_index) DO NOTHING`

	_, err := tx.Exec(ctx, sql, args...)
	return err
}
```

### Correct `pkg/store/findings_test.go` (foundation for Tasks 1.5–1.8)

```go
//go:build integration

package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// saveScan is a shared test helper that creates a scan with the given
// ID/hostname/profile/orgID, runs ExtractFindings, and calls
// SaveScanWithFindings. It replaces the scan's pre-seeded findings
// entirely with the supplied list.
func saveScan(t *testing.T, s *PostgresStore, id, hostname, orgID string, findings ...model.Finding) *model.ScanResult {
	t.Helper()
	scan := testScanResult(id, hostname, "quick")
	scan.OrgID = orgID
	scan.Findings = findings
	require.NoError(t, s.SaveScanWithFindings(context.Background(), scan, ExtractFindings(scan)))
	return scan
}

func cryptoF(module, path string, ca *model.CryptoAsset) model.Finding {
	return model.Finding{
		Module:      module,
		Source:      model.FindingSource{Type: "file", Path: path},
		CryptoAsset: ca,
	}
}

// queryFindingsCount counts findings rows for a scan. Uses the
// package-private pool directly so it's only available to tests in
// the pkg/store package.
func queryFindingsCount(t *testing.T, s *PostgresStore, scanID string) int {
	t.Helper()
	var count int
	err := s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM findings WHERE scan_id = $1`, scanID).Scan(&count)
	require.NoError(t, err)
	return count
}

// queryScanBackfilled returns true if the scan row has findings_extracted_at set.
func queryScanBackfilled(t *testing.T, s *PostgresStore, scanID string) bool {
	t.Helper()
	var markedAt *time.Time
	err := s.pool.QueryRow(context.Background(),
		`SELECT findings_extracted_at FROM scans WHERE id = $1`, scanID).Scan(&markedAt)
	require.NoError(t, err)
	return markedAt != nil
}

// --- SaveScanWithFindings ---

func TestSaveScanWithFindings_StoresScanAndFindings(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("swf-org")

	scan := saveScan(t, s, testUUID("swf-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "AES", KeySize: 256, PQCStatus: "SAFE", MigrationPriority: 10}),
	)

	// Scan row exists
	retrieved, err := s.GetScan(context.Background(), scan.ID, orgID)
	require.NoError(t, err)
	assert.Equal(t, scan.ID, retrieved.ID)

	// Findings rows exist
	assert.Equal(t, 2, queryFindingsCount(t, s, scan.ID))

	// Scan marked backfilled
	assert.True(t, queryScanBackfilled(t, s, scan.ID))
}

func TestSaveScanWithFindings_SkipsNonCryptoFindings(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("swf-org-2")

	scan := saveScan(t, s, testUUID("swf-2"), "host-2", orgID,
		model.Finding{Module: "file", Source: model.FindingSource{Path: "/plain"}}, // non-crypto, skipped
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	)
	assert.Equal(t, 1, queryFindingsCount(t, s, scan.ID))
}

func TestSaveScanWithFindings_OnConflictSkipsDuplicateRows(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("swf-org-3")

	scan := testScanResult(testUUID("swf-3"), "host-3", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	}
	extracted := ExtractFindings(scan)

	// First save
	require.NoError(t, s.SaveScanWithFindings(context.Background(), scan, extracted))
	// Second save with the SAME extracted rows — ON CONFLICT DO NOTHING
	// should absorb the duplicate (same scan_id + finding_index).
	require.NoError(t, s.SaveScanWithFindings(context.Background(), scan, extracted))

	assert.Equal(t, 1, queryFindingsCount(t, s, scan.ID))
}
```

## A.6 — Task 1.6 corrected ListInventory tests

Store-package tests use `testScanResult(id, hostname, profile)` (3-arg, no OrgID set) + `testUUID(name string)` (string arg). They must set `scan.OrgID` manually.

### Append to `pkg/store/findings_test.go`

```go
// --- ListInventory ---

func TestListInventory_EmptyOrg(t *testing.T) {
	s := testStore(t)
	rows, err := s.ListInventory(context.Background(), testUUID("empty-org"))
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListInventory_SingleFinding(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("inv-org")
	scan := saveScan(t, s, testUUID("inv-1"), "host-1", orgID,
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
	)
	_ = scan

	rows, err := s.ListInventory(context.Background(), orgID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "RSA", rows[0].Algorithm)
	assert.Equal(t, 2048, rows[0].KeySize)
	assert.Equal(t, "DEPRECATED", rows[0].PQCStatus)
	assert.Equal(t, 1, rows[0].Instances)
	assert.Equal(t, 1, rows[0].Machines)
	assert.Equal(t, 80, rows[0].MaxPriority)
}

func TestListInventory_GroupsByAlgorithmAndSize(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("inv-grp")
	_ = saveScan(t, s, testUUID("inv-grp-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 75}),
		cryptoF("key", "/c", &model.CryptoAsset{Algorithm: "RSA", KeySize: 4096, PQCStatus: "SAFE", MigrationPriority: 0}),
	)

	rows, err := s.ListInventory(context.Background(), orgID)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	rsa2048 := findInventoryRow(rows, "RSA", 2048)
	require.NotNil(t, rsa2048)
	assert.Equal(t, 2, rsa2048.Instances)
	assert.Equal(t, 1, rsa2048.Machines)
	assert.Equal(t, 80, rsa2048.MaxPriority)

	rsa4096 := findInventoryRow(rows, "RSA", 4096)
	require.NotNil(t, rsa4096)
	assert.Equal(t, "SAFE", rsa4096.PQCStatus)
}

func TestListInventory_TenantIsolation(t *testing.T) {
	s := testStore(t)
	orgA := testUUID("inv-tenant-a")
	orgB := testUUID("inv-tenant-b")

	_ = saveScan(t, s, testUUID("inv-tenant-scan-a"), "host-a", orgA,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED"}),
	)
	_ = saveScan(t, s, testUUID("inv-tenant-scan-b"), "host-b", orgB,
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "AES", KeySize: 256, PQCStatus: "SAFE"}),
	)

	rowsA, err := s.ListInventory(context.Background(), orgA)
	require.NoError(t, err)
	require.Len(t, rowsA, 1)
	assert.Equal(t, "RSA", rowsA[0].Algorithm)

	rowsB, err := s.ListInventory(context.Background(), orgB)
	require.NoError(t, err)
	require.Len(t, rowsB, 1)
	assert.Equal(t, "AES", rowsB[0].Algorithm)
}

func TestListInventory_LatestScanPerHostOnly(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("inv-latest")

	// Old scan: RSA-1024 (stale)
	oldScan := testScanResult(testUUID("inv-latest-old"), "host-1", "quick")
	oldScan.OrgID = orgID
	oldScan.Metadata.Timestamp = time.Now().UTC().Add(-48 * time.Hour)
	oldScan.Findings = []model.Finding{
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 1024, PQCStatus: "UNSAFE"}),
	}
	require.NoError(t, s.SaveScanWithFindings(context.Background(), oldScan, ExtractFindings(oldScan)))

	// New scan: upgraded to RSA-4096
	newScan := testScanResult(testUUID("inv-latest-new"), "host-1", "quick")
	newScan.OrgID = orgID
	newScan.Metadata.Timestamp = time.Now().UTC()
	newScan.Findings = []model.Finding{
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 4096, PQCStatus: "SAFE"}),
	}
	require.NoError(t, s.SaveScanWithFindings(context.Background(), newScan, ExtractFindings(newScan)))

	rows, err := s.ListInventory(context.Background(), orgID)
	require.NoError(t, err)
	require.Len(t, rows, 1, "only the latest scan per host counts")
	assert.Equal(t, 4096, rows[0].KeySize)
}

// findInventoryRow locates a row by (algorithm, keySize).
func findInventoryRow(rows []InventoryRow, algo string, size int) *InventoryRow {
	for i := range rows {
		if rows[i].Algorithm == algo && rows[i].KeySize == size {
			return &rows[i]
		}
	}
	return nil
}
```

The `ListInventory` implementation in `findings.go` (SQL query) is unchanged from the original Task 1.6 — append it per the plan's code block.

## A.7 — Task 1.7 corrected ListExpiringCertificates tests

Same test setup corrections as A.6. Query implementation unchanged.

### Append to `pkg/store/findings_test.go`

```go
// --- ListExpiringCertificates ---

func TestListExpiringCerts_EmptyOrg(t *testing.T) {
	s := testStore(t)
	rows, err := s.ListExpiringCertificates(context.Background(), testUUID("cert-empty"), 90*24*time.Hour)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListExpiringCerts_WithinWindow(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-window")
	in30 := time.Now().UTC().Add(30 * 24 * time.Hour)
	in200 := time.Now().UTC().Add(200 * 24 * time.Hour)

	_ = saveScan(t, s, testUUID("cert-win-1"), "host-1", orgID,
		cryptoF("certificate", "/soon.crt", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &in30, Subject: "CN=soon"}),
		cryptoF("certificate", "/later.crt", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &in200, Subject: "CN=later"}),
	)

	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 90*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 1, "only the 30-day cert is inside the 90-day window")
	assert.Equal(t, "CN=soon", rows[0].Subject)
}

func TestListExpiringCerts_AlreadyExpiredAlwaysIncluded(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-expired")
	expired := time.Now().UTC().Add(-10 * 24 * time.Hour)

	_ = saveScan(t, s, testUUID("cert-expired-1"), "host-1", orgID,
		cryptoF("certificate", "/dead.crt", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &expired, Subject: "CN=dead"}),
	)

	// Even a 1-hour window includes already-expired certs.
	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 1*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "CN=dead", rows[0].Subject)
	assert.True(t, rows[0].DaysRemaining < 0)
	assert.Equal(t, "expired", rows[0].Status)
}

func TestListExpiringCerts_NullNotAfterExcluded(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-null")
	_ = saveScan(t, s, testUUID("cert-null-1"), "host-1", orgID,
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "AES", KeySize: 256}), // no NotAfter
	)

	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 90*24*time.Hour)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListExpiringCerts_SortedAscending(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-sort")
	in15 := time.Now().UTC().Add(15 * 24 * time.Hour)
	in45 := time.Now().UTC().Add(45 * 24 * time.Hour)
	in5 := time.Now().UTC().Add(5 * 24 * time.Hour)

	_ = saveScan(t, s, testUUID("cert-sort-1"), "host-1", orgID,
		cryptoF("certificate", "/15.crt", &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in15, Subject: "CN=fifteen"}),
		cryptoF("certificate", "/45.crt", &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in45, Subject: "CN=forty-five"}),
		cryptoF("certificate", "/5.crt", &model.CryptoAsset{Algorithm: "RSA", NotAfter: &in5, Subject: "CN=five"}),
	)

	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 90*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, "CN=five", rows[0].Subject)
	assert.Equal(t, "CN=fifteen", rows[1].Subject)
	assert.Equal(t, "CN=forty-five", rows[2].Subject)
}

func TestListExpiringCerts_LargeWithinReturnsFuture(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cert-all")
	inYear := time.Now().UTC().Add(400 * 24 * time.Hour)

	_ = saveScan(t, s, testUUID("cert-all-1"), "host-1", orgID,
		cryptoF("certificate", "/far.crt", &model.CryptoAsset{Algorithm: "RSA", NotAfter: &inYear, Subject: "CN=far"}),
	)

	rows, err := s.ListExpiringCertificates(context.Background(), orgID, 100*365*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "CN=far", rows[0].Subject)
}
```

Implementation (append to `findings.go`) — unchanged from the original Task 1.7 code block.

## A.8 — Task 1.8 corrected ListTopPriorityFindings

Drop `f.line_number` from SELECT + scan target. PriorityRow has no `Category` field. Test setup uses `saveScan` helper.

### `ListTopPriorityFindings` implementation (append to `findings.go`)

```go
// ListTopPriorityFindings returns the top N findings by
// migration_priority descending, filtered to the latest scan per
// hostname. limit=0 is treated as limit=20.
func (s *PostgresStore) ListTopPriorityFindings(ctx context.Context, orgID string, limit int) ([]PriorityRow, error) {
	if limit <= 0 {
		limit = 20
	}
	const q = `
WITH latest_scans AS (
    SELECT DISTINCT ON (hostname) id
    FROM scans
    WHERE org_id = $1
    ORDER BY hostname, timestamp DESC
)
SELECT f.id, f.migration_priority, f.algorithm, f.key_size, f.pqc_status,
       f.module, f.hostname, f.file_path
FROM findings f
WHERE f.org_id = $1
  AND f.scan_id IN (SELECT id FROM latest_scans)
  AND f.migration_priority > 0
ORDER BY f.migration_priority DESC
LIMIT $2
`
	rows, err := s.pool.Query(ctx, q, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("ListTopPriorityFindings query: %w", err)
	}
	defer rows.Close()

	out := make([]PriorityRow, 0)
	for rows.Next() {
		var r PriorityRow
		if err := rows.Scan(&r.FindingID, &r.Priority, &r.Algorithm, &r.KeySize, &r.PQCStatus,
			&r.Module, &r.Hostname, &r.FilePath); err != nil {
			return nil, fmt.Errorf("ListTopPriorityFindings scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
```

### Priority tests (append to `findings_test.go`)

```go
// --- ListTopPriorityFindings ---

func TestListPriority_EmptyOrg(t *testing.T) {
	s := testStore(t)
	rows, err := s.ListTopPriorityFindings(context.Background(), testUUID("prio-empty"), 20)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListPriority_SortedDescending(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("prio-sort")
	_ = saveScan(t, s, testUUID("prio-sort-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "MD5", MigrationPriority: 95}),
		cryptoF("key", "/c", &model.CryptoAsset{Algorithm: "SHA-1", MigrationPriority: 80}),
	)

	rows, err := s.ListTopPriorityFindings(context.Background(), orgID, 20)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, 95, rows[0].Priority)
	assert.Equal(t, 80, rows[1].Priority)
	assert.Equal(t, 50, rows[2].Priority)
}

func TestListPriority_LimitRespected(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("prio-limit")
	findings := make([]model.Finding, 0, 30)
	for i := 0; i < 30; i++ {
		findings = append(findings, cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i}))
	}
	_ = saveScan(t, s, testUUID("prio-limit-1"), "host-1", orgID, findings...)

	rows, err := s.ListTopPriorityFindings(context.Background(), orgID, 10)
	require.NoError(t, err)
	assert.Len(t, rows, 10)

	rowsAll, err := s.ListTopPriorityFindings(context.Background(), orgID, 100)
	require.NoError(t, err)
	assert.Len(t, rowsAll, 30)
}

func TestListPriority_ExcludesZeroPriority(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("prio-zero")
	_ = saveScan(t, s, testUUID("prio-zero-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "AES", MigrationPriority: 0}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50}),
	)

	rows, err := s.ListTopPriorityFindings(context.Background(), orgID, 20)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "RSA", rows[0].Algorithm)
}

func TestListPriority_LimitZeroDefaultsTo20(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("prio-default")
	findings := make([]model.Finding, 0, 25)
	for i := 0; i < 25; i++ {
		findings = append(findings, cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i}))
	}
	_ = saveScan(t, s, testUUID("prio-default-1"), "host-1", orgID, findings...)

	rows, err := s.ListTopPriorityFindings(context.Background(), orgID, 0)
	require.NoError(t, err)
	assert.Len(t, rows, 20)
}
```

## A.9 — Task 1.9 corrected BackfillFindings

`maybeDecrypt` doesn't exist — use `s.loadEncryptor().Decrypt(blob)` pattern from existing `GetScan`. Also use `pool.BeginTx` instead of `pgx.BeginFunc`.

### Correct `pkg/store/backfill.go`

```go
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/amiryahaya/triton/pkg/model"
)

// BackfillFindings walks every scan row where findings_extracted_at
// IS NULL, unpacks result_json, extracts crypto findings, inserts them,
// and sets the marker. Safe to call repeatedly. Safe to interrupt mid-
// run — next call resumes from the next unprocessed scan.
//
// Intended to be called once from cmd/server.go after migrations run,
// in a goroutine so it doesn't block the HTTP listener. On per-scan
// failure the scan is MARKED anyway so we don't retry forever on a
// corrupt blob.
//
// See docs/plans/2026-04-09-analytics-phase-1-design.md §5.
func (s *PostgresStore) BackfillFindings(ctx context.Context) error {
	const batchSize = 100
	total := 0
	start := time.Now()

	for {
		if err := ctx.Err(); err != nil {
			log.Printf("backfill: context cancelled after %d scans: %v", total, err)
			return nil
		}

		scans, err := s.selectUnbackfilledScans(ctx, batchSize)
		if err != nil {
			return fmt.Errorf("backfill: select unbackfilled: %w", err)
		}
		if len(scans) == 0 {
			log.Printf("backfill: done — processed %d scans in %s", total, time.Since(start))
			return nil
		}

		for _, scanID := range scans {
			if err := ctx.Err(); err != nil {
				log.Printf("backfill: context cancelled mid-batch after %d scans", total)
				return nil
			}
			if err := s.extractAndInsertOneScan(ctx, scanID); err != nil {
				log.Printf("backfill: scan %s failed: %v — marking as processed anyway", scanID, err)
				s.backfillScansFailed.Add(1)
			} else {
				s.backfillScansTotal.Add(1)
			}
			if err := s.markScanBackfilled(ctx, scanID); err != nil {
				return fmt.Errorf("backfill: mark scan %s: %w", scanID, err)
			}
			total++
		}
		log.Printf("backfill: progress — %d scans processed", total)
	}
}

// selectUnbackfilledScans returns up to `limit` scan IDs whose
// findings_extracted_at is NULL. Ordered by ID for determinism.
func (s *PostgresStore) selectUnbackfilledScans(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM scans
		WHERE findings_extracted_at IS NULL
		ORDER BY id
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// extractAndInsertOneScan fetches a scan, decrypts + unmarshals the
// blob, runs ExtractFindings, and bulk-inserts the result inside a
// transaction.
func (s *PostgresStore) extractAndInsertOneScan(ctx context.Context, scanID string) error {
	// (1) Fetch the raw blob + the row-level org_id/hostname. The
	// latter two are needed because scans persisted via SaveScan may
	// not have them populated inside result_json.
	var (
		blob     []byte
		orgID    string
		hostname string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT result_json, COALESCE(org_id::text, ''), hostname
		FROM scans WHERE id = $1
	`, scanID).Scan(&blob, &orgID, &hostname)
	if err != nil {
		return fmt.Errorf("fetch scan: %w", err)
	}

	// (2) Decrypt if configured. No-op when encryptor is nil.
	if enc := s.loadEncryptor(); enc != nil {
		decrypted, decErr := enc.Decrypt(blob)
		if decErr != nil {
			return fmt.Errorf("decrypt scan: %w", decErr)
		}
		blob = decrypted
	}

	// (3) Unmarshal.
	var scan model.ScanResult
	if err := json.Unmarshal(blob, &scan); err != nil {
		return fmt.Errorf("unmarshal scan: %w", err)
	}

	// (4) Rehydrate row-level fields so ExtractFindings gets the right
	// values — the persisted blob may have empty OrgID/Hostname.
	scan.ID = scanID
	if scan.OrgID == "" {
		scan.OrgID = orgID
	}
	if scan.Metadata.Hostname == "" {
		scan.Metadata.Hostname = hostname
	}

	findings := ExtractFindings(&scan)
	if len(findings) == 0 {
		return nil // scan had no crypto findings, still valid
	}

	// (5) Bulk insert inside a transaction so partial inserts don't
	// leak if any row fails.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertFindingsInTx(ctx, tx, findings); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// markScanBackfilled sets findings_extracted_at = NOW() for the given scan.
func (s *PostgresStore) markScanBackfilled(ctx context.Context, scanID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE scans SET findings_extracted_at = NOW() WHERE id = $1`, scanID)
	return err
}
```

Add the atomic counters to `PostgresStore` in `pkg/store/postgres.go`:

```go
import "sync/atomic"  // add if not already present

type PostgresStore struct {
    // ... existing fields ...

    // Backfill counters — read by the metrics handler, written by
    // BackfillFindings. Lock-free atomics so the metrics scrape path
    // costs nothing. Analytics Phase 1.
    backfillScansTotal  atomic.Uint64
    backfillScansFailed atomic.Uint64
}

// BackfillScansTotal returns the running count of scans successfully
// processed by the findings backfill loop. Analytics Phase 1.
func (s *PostgresStore) BackfillScansTotal() uint64 {
	return s.backfillScansTotal.Load()
}

// BackfillScansFailed returns the running count of scans that failed
// extraction and were marked to skip. Analytics Phase 1.
func (s *PostgresStore) BackfillScansFailed() uint64 {
	return s.backfillScansFailed.Load()
}
```

### Backfill tests (`pkg/store/backfill_test.go`)

```go
//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestBackfillFindings_EmptyDB(t *testing.T) {
	s := testStore(t)
	err := s.BackfillFindings(context.Background())
	assert.NoError(t, err)
}

func TestBackfillFindings_PopulatesUnmarkedScans(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-org")

	scan := testScanResult(testUUID("bf-1"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
	}
	// Save via the LEGACY path so findings_extracted_at stays NULL.
	require.NoError(t, s.SaveScan(context.Background(), scan))
	_, err := s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	require.NoError(t, err)

	require.NoError(t, s.BackfillFindings(context.Background()))

	assert.Equal(t, 1, queryFindingsCount(t, s, scan.ID))
	assert.True(t, queryScanBackfilled(t, s, scan.ID))
}

func TestBackfillFindings_SkipsAlreadyMarked(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-skip-org")

	scan := saveScan(t, s, testUUID("bf-skip"), "host-1", orgID,
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	)
	countBefore := queryFindingsCount(t, s, scan.ID)

	require.NoError(t, s.BackfillFindings(context.Background()))
	countAfter := queryFindingsCount(t, s, scan.ID)
	assert.Equal(t, countBefore, countAfter,
		"backfill must not re-insert findings for already-marked scans")
}

func TestBackfillFindings_Idempotent(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-idem-org")

	scan := testScanResult(testUUID("bf-idem"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	}
	require.NoError(t, s.SaveScan(context.Background(), scan))
	_, _ = s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)

	require.NoError(t, s.BackfillFindings(context.Background()))
	// Clear marker and re-run — ON CONFLICT DO NOTHING keeps it safe.
	_, _ = s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	require.NoError(t, s.BackfillFindings(context.Background()))

	assert.Equal(t, 1, queryFindingsCount(t, s, scan.ID))
}

func TestBackfillFindings_ContextCancellationAllowsResume(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-resume-org")

	for i := 0; i < 3; i++ {
		scan := testScanResult(testUUID("bf-resume-"+string(rune('a'+i))), "host-"+string(rune('a'+i)), "quick")
		scan.OrgID = orgID
		scan.Findings = []model.Finding{
			cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
		}
		require.NoError(t, s.SaveScan(context.Background(), scan))
		_, _ = s.pool.Exec(context.Background(),
			`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)
	}

	// Cancel immediately — zero scans processed, no panic.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_ = s.BackfillFindings(cancelled)

	// Resume — all should be processed.
	require.NoError(t, s.BackfillFindings(context.Background()))

	var unmarked int
	err := s.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM scans WHERE org_id = $1 AND findings_extracted_at IS NULL`,
		orgID).Scan(&unmarked)
	require.NoError(t, err)
	assert.Equal(t, 0, unmarked)
}

func TestBackfillFindings_CountersIncrement(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("bf-count-org")

	scan := testScanResult(testUUID("bf-count"), "host-1", "quick")
	scan.OrgID = orgID
	scan.Findings = []model.Finding{
		cryptoF("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
	}
	require.NoError(t, s.SaveScan(context.Background(), scan))
	_, _ = s.pool.Exec(context.Background(),
		`UPDATE scans SET findings_extracted_at = NULL WHERE id = $1`, scan.ID)

	// Counters are package-level on PostgresStore; reset for the test.
	s.backfillScansTotal.Store(0)
	s.backfillScansFailed.Store(0)

	require.NoError(t, s.BackfillFindings(context.Background()))

	assert.Equal(t, uint64(1), s.backfillScansTotal.Load())
	assert.Equal(t, uint64(0), s.backfillScansFailed.Load())
}
```

## A.12 — Task 1.12 moved to pkg/store

The original Task 1.12 put the cascade test in pkg/server, but it needs the `queryFindingsCount` helper which is package-private in pkg/store. Move the test to `pkg/store/findings_test.go` — the cascade is a DB property, not a handler property, so a store-level test is more direct anyway.

### Append to `pkg/store/findings_test.go`

```go
// --- DeleteScan cascade ---

func TestDeleteScan_CascadesToFindings(t *testing.T) {
	s := testStore(t)
	orgID := testUUID("cascade-org")

	scan := saveScan(t, s, testUUID("cascade-1"), "host-1", orgID,
		cryptoF("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
		cryptoF("key", "/b", &model.CryptoAsset{Algorithm: "AES", KeySize: 256}),
	)
	require.Equal(t, 2, queryFindingsCount(t, s, scan.ID))

	// Use the existing DeleteScan method.
	require.NoError(t, s.DeleteScan(context.Background(), scan.ID, orgID))

	assert.Equal(t, 0, queryFindingsCount(t, s, scan.ID),
		"ON DELETE CASCADE should have removed the findings rows")
}
```

The handler-level `handleDeleteScan` test is dropped — the cascade is fully exercised at the store level and the handler just calls through.

## A.13 — Task 1.13 store import in handlers_metrics.go

The Prometheus metrics snippet uses `s.store.(*store.PostgresStore)` type assertion, which requires the `store` package to be imported in `pkg/server/handlers_metrics.go`. The import is not present today (only `pkg/server/server.go` imports it). Add it:

```go
import (
    // ... existing imports ...
    "github.com/amiryahaya/triton/pkg/store"
)
```

The metrics snippet body is otherwise unchanged from the original Task 1.13.

## A.2.1 — Task 2.1 corrected handleInventory tests

Server-package tests use `testServerWithJWT(t)` + `createOrgUser(t, db, ...)` + `testScanResult(id, hostname)` (2-arg, server-pkg signature) + `testUUID(n int)` (server-pkg signature, int arg). Override `scan.OrgID = org.ID` after calling `testScanResult` so it matches the tenant created by `createOrgUser`.

### Correct `pkg/server/handlers_analytics_test.go` — inventory tests

```go
//go:build integration

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// cryptoFinding is a handler-test helper that builds a file-sourced
// crypto finding. Mirrors the store-pkg helper but lives here so
// handler tests don't depend on store internals.
func cryptoFinding(module, path string, ca *model.CryptoAsset) model.Finding {
	return model.Finding{
		Module:      module,
		Source:      model.FindingSource{Type: "file", Path: path},
		CryptoAsset: ca,
	}
}

func TestHandleInventory_EmptyReturns200(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.InventoryRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Empty(t, rows)
}

func TestHandleInventory_PopulatedReturnsRows(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID(1), "host-1")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		cryptoFinding("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.InventoryRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	require.Len(t, rows, 1)
	assert.Equal(t, "RSA", rows[0].Algorithm)
	assert.Equal(t, 2048, rows[0].KeySize)
}

func TestHandleInventory_NoJWTReturns401(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleInventory_BackfillHeaderWhenInProgress(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	srv.BackfillInProgress().Store(true)
	defer srv.BackfillInProgress().Store(false)

	w := authReq(t, srv, http.MethodGet, "/api/v1/inventory", token, nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true", w.Header().Get("X-Backfill-In-Progress"))
}
```

## A.3.1 — Task 3.1 corrected handleExpiringCertificates tests

Same test-helper corrections as A.2.1. Append to `pkg/server/handlers_analytics_test.go`:

```go
func TestHandleExpiringCerts_DefaultWindow(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	in30 := time.Now().UTC().Add(30 * 24 * time.Hour)
	in200 := time.Now().UTC().Add(200 * 24 * time.Hour)

	scan := testScanResult(testUUID(2), "host-1")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		cryptoFinding("certificate", "/soon.crt", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &in30, Subject: "CN=soon"}),
		cryptoFinding("certificate", "/later.crt", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &in200, Subject: "CN=later"}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/certificates/expiring", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.ExpiringCertRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 1, "default 90-day window excludes the 200-day cert")
}

func TestHandleExpiringCerts_WithinAll(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	in500 := time.Now().UTC().Add(500 * 24 * time.Hour)
	scan := testScanResult(testUUID(3), "host-1")
	scan.OrgID = org.ID
	scan.Findings = []model.Finding{
		cryptoFinding("certificate", "/far.crt", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, NotAfter: &in500, Subject: "CN=far"}),
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/certificates/expiring?within=all", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.ExpiringCertRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 1)
}

func TestHandleExpiringCerts_InvalidWithin(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	for _, param := range []string{"abc", "-1", "5000"} {
		t.Run(param, func(t *testing.T) {
			w := authReq(t, srv, http.MethodGet, "/api/v1/certificates/expiring?within="+param, token, nil)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}
```

Add `"time"` to the imports at the top of `handlers_analytics_test.go`.

## A.4.1 — Task 4.1 corrected handlePriority tests

Same helper corrections. PriorityRow has no Category/LineNumber — test assertions must not reference them. Append to `pkg/server/handlers_analytics_test.go`:

```go
func TestHandlePriority_DefaultLimit(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID(4), "host-1")
	scan.OrgID = org.ID
	scan.Findings = nil
	for i := 0; i < 25; i++ {
		scan.Findings = append(scan.Findings,
			cryptoFinding("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i}))
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/priority", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.PriorityRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 20)
}

func TestHandlePriority_CustomLimit(t *testing.T) {
	srv, db := testServerWithJWT(t)
	org, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	scan := testScanResult(testUUID(5), "host-1")
	scan.OrgID = org.ID
	scan.Findings = nil
	for i := 0; i < 10; i++ {
		scan.Findings = append(scan.Findings,
			cryptoFinding("key", "/k", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, MigrationPriority: 50 + i}))
	}
	require.NoError(t, db.SaveScanWithFindings(context.Background(), scan, store.ExtractFindings(scan)))

	w := authReq(t, srv, http.MethodGet, "/api/v1/priority?limit=5", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var rows []store.PriorityRow
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rows))
	assert.Len(t, rows, 5)
}

func TestHandlePriority_InvalidLimit(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)
	token := loginAndExtractToken(t, srv, user.Email, "correct-horse-battery")

	for _, param := range []string{"0", "-1", "1001", "abc"} {
		t.Run(param, func(t *testing.T) {
			w := authReq(t, srv, http.MethodGet, "/api/v1/priority?limit="+param, token, nil)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}
```

## A.4.2 — Task 4.2 corrected renderPriority UI

The original JS referenced `row.category` and `row.lineNumber` which are no longer on PriorityRow. Drop the Category column from the table, simplify Location to just `row.filePath`.

### Correct `renderPriority` function (replaces the version in Task 4.2)

```js
  async function renderPriority() {
    content.innerHTML = '<div class="loading">Loading priority findings...</div>';
    try {
      const rows = await api('/priority?limit=20');

      let critical = 0, high = 0, medium = 0;
      for (const r of rows) {
        if (r.priority >= 80) critical++;
        else if (r.priority >= 60) high++;
        else if (r.priority >= 40) medium++;
      }

      let html = `<h2>Migration Priority</h2>
        <p class="subtitle">Top findings to fix first, ranked by migration priority score (latest scan per host).</p>
        <div class="card-grid">
          <div class="card unsafe"><div class="value">${critical}</div><div class="label">Critical (≥80)</div></div>
          <div class="card deprecated"><div class="value">${high}</div><div class="label">High (60–79)</div></div>
          <div class="card transitional"><div class="value">${medium}</div><div class="label">Medium (40–59)</div></div>
          <div class="card info"><div class="value">${rows.length}</div><div class="label">Shown (top 20)</div></div>
        </div>`;

      if (rows.length === 0) {
        html += `<div class="empty-state">No priority findings yet — run a scan.</div>`;
      } else {
        html += `<table class="analytics-table">
          <thead><tr>
            <th class="num">Score</th><th>Algorithm</th><th>Module</th>
            <th>Host</th><th>Location</th><th>Status</th>
          </tr></thead><tbody>`;
        for (const row of rows) {
          const algo = row.algorithm + (row.keySize ? '-' + row.keySize : '');
          const loc = row.filePath || '—';
          html += `<tr>
            <td class="num">${escapeHtml(row.priority)}</td>
            <td>${escapeHtml(algo)}</td>
            <td>${escapeHtml(row.module)}</td>
            <td>${escapeHtml(row.hostname)}</td>
            <td><code>${escapeHtml(loc)}</code></td>
            <td>${badge(row.pqcStatus)}</td>
          </tr>`;
        }
        html += `</tbody></table>`;
      }

      content.innerHTML = html;
      renderBackfillBanner(content);
    } catch (e) {
      content.innerHTML = `<div class="error">Failed to load priority findings: ${escapeHtml(e.message)}</div>`;
    }
  }
```

Key differences from Task 4.2's original:
- Column header `Category` → `Module`
- Drop the `row.lineNumber` concatenation — just show `row.filePath`
- `row.category` removed everywhere

---

**End of Appendix A.** Back to the original plan body above for Tasks 1.10, 1.11, 1.14, 2.2–2.6, 3.2–3.4, 4.3–4.5 — those remain unchanged.

