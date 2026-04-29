# NACSA Arahan 9 Analytics — Report Portal Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a tenant-scoped NACSA Arahan 9 compliance dashboard to the Report Portal with 5-tab drill-down navigation (Summary · Inventory · CBOM · Risk · Migration) from Manage Servers → Hosts → Scan Modules → Results.

**Architecture:** Backend adds `manage_server_id` / `manage_server_name` to the scan/finding pipeline (model → manage gateway → store → DB migration), then exposes 6 new `/api/v1/nacsa/*` endpoints. Frontend replaces the stub `NacsaArahan9.vue` with a full 5-tab layout backed by a Pinia store.

**Tech Stack:** Go 1.25, pgx/v5, chi router, Vue 3 + Pinia + TypeScript, `@triton/ui` component library, `@triton/api-client` package.

**Spec:** `docs/superpowers/specs/2026-04-29-nacsa-arahan9-analytics-design.md`

---

## File Map

**New files:**
- `pkg/store/nacsa.go` — NACSA query helpers + response types
- `pkg/store/nacsa_test.go` — integration tests for NACSA queries
- `pkg/server/handlers_nacsa.go` — 6 HTTP handlers for `/api/v1/nacsa/*`
- `pkg/server/handlers_nacsa_test.go` — unit tests for handlers
- `web/apps/report-portal/src/stores/nacsa.ts` — Pinia store for NACSA data

**Modified files:**
- `pkg/model/types.go` — add `ManageServerID`, `ManageServerName` to `ScanMetadata`
- `pkg/manageserver/agents/handlers_gateway.go` — add `InstanceInfo` + `SetInstanceInfo`, stamp on `IngestScan`
- `pkg/manageserver/server.go` — call `SetInstanceInfo` from `startScannerPipeline`
- `pkg/store/migrations.go` — version 29: manage_server columns + nacsa_migration_phases table
- `pkg/store/types.go` — add `ManageServerID` to `Finding` struct
- `pkg/store/findings.go` — persist `manage_server_id` in both INSERT paths + `insertFindingsChunk`
- `pkg/store/store.go` — add NACSA methods to `Store` interface
- `pkg/server/server.go` — mount `/api/v1/nacsa/*` routes
- `web/packages/api-client/src/reportServer.ts` — NACSA response types + 6 api methods
- `web/apps/report-portal/src/views/NacsaArahan9.vue` — full 5-tab dashboard

---

## Task 1: Add ManageServerID/Name to ScanMetadata

**Files:**
- Modify: `pkg/model/types.go`

- [ ] **Step 1: Add fields to ScanMetadata**

In `pkg/model/types.go`, add two fields at the end of `ScanMetadata` (after `Source ScanSource`):

```go
// ManageServerID is the UUID of the Manage Server instance that
// relayed this scan to the Report Server. Empty when submitted
// directly by a standalone agent.
ManageServerID   string `json:"manageServerID,omitempty"`
ManageServerName string `json:"manageServerName,omitempty"`
```

- [ ] **Step 2: Verify existing tests still compile**

```bash
go build ./pkg/model/...
go test ./pkg/model/... -v
```

Expected: PASS (no tests broken — struct addition is backward compatible).

- [ ] **Step 3: Commit**

```bash
git add pkg/model/types.go
git commit -m "feat(model): add ManageServerID/Name to ScanMetadata"
```

---

## Task 2: Stamp manage server identity in the gateway

**Files:**
- Modify: `pkg/manageserver/agents/handlers_gateway.go`
- Modify: `pkg/manageserver/server.go`

- [ ] **Step 1: Write failing test**

Add to `pkg/manageserver/agents/handlers_gateway_test.go` (create if absent — look for existing test file first):

```go
func TestIngestScan_StampsInstanceInfo(t *testing.T) {
    // Build a gateway with known InstanceInfo
    gw := &GatewayHandlers{
        CAStore:      &fakeCAStore{},
        AgentStore:   &fakeAgentStore{markActiveOK: true},
        ResultsStore: &fakeEnqueuer{},
    }
    gw.SetInstanceInfo("test-uuid-123", "test-manage")

    scan := model.ScanResult{
        ID: uuid.NewString(),
        Metadata: model.ScanMetadata{Hostname: "host1"},
    }
    body, _ := json.Marshal(scan)
    req := httptest.NewRequest(http.MethodPost, "/agents/scans", bytes.NewReader(body))
    req = req.WithContext(withCN(req.Context(), "agent:"+uuid.NewString()))
    rec := httptest.NewRecorder()
    gw.IngestScan(rec, req)

    require.Equal(t, http.StatusAccepted, rec.Code)
    enq := gw.ResultsStore.(*fakeEnqueuer)
    require.NotNil(t, enq.lastScan)
    assert.Equal(t, "test-uuid-123", enq.lastScan.Metadata.ManageServerID)
    assert.Equal(t, "test-manage", enq.lastScan.Metadata.ManageServerName)
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
go test ./pkg/manageserver/agents/... -run TestIngestScan_StampsInstanceInfo -v
```

Expected: FAIL (compile error — `SetInstanceInfo` not defined yet).

- [ ] **Step 3: Add InstanceInfo and SetInstanceInfo to GatewayHandlers**

In `pkg/manageserver/agents/handlers_gateway.go`, add to the `GatewayHandlers` struct and a new method:

```go
// GatewayHandlers serves the :8443 mTLS endpoints an agent dials.
type GatewayHandlers struct {
    CAStore      ca.Store
    AgentStore   Store
    ResultsStore ResultEnqueuer

    // instanceID and instanceName identify this Manage Server deployment.
    // Set via SetInstanceInfo once instance_id is resolved from setup state.
    // Empty before setup completes — IngestScan still works but won't stamp metadata.
    instanceID   string
    instanceName string
}

// SetInstanceInfo records the Manage Server's stable UUID and display
// name. Call once from startScannerPipeline after instance_id is resolved.
func (h *GatewayHandlers) SetInstanceInfo(id, name string) {
    h.instanceID = id
    h.instanceName = name
}
```

- [ ] **Step 4: Stamp metadata in IngestScan**

In the `IngestScan` method, after `json.Unmarshal(body, &scan)` succeeds, add:

```go
if h.instanceID != "" {
    scan.Metadata.ManageServerID   = h.instanceID
    scan.Metadata.ManageServerName = h.instanceName
}
```

- [ ] **Step 5: Wire SetInstanceInfo from server.go**

In `pkg/manageserver/server.go`, inside `startScannerPipeline`, after `instanceID, err := uuid.Parse(state.InstanceID)` succeeds (around line 511), add:

```go
// Stamp manage server identity onto all gateway-relayed scans.
hostname, _ := os.Hostname()
if hostname == "" {
    hostname = state.InstanceID
}
s.agentsGateway.SetInstanceInfo(state.InstanceID, hostname)
```

Add `"os"` to imports if not already present.

- [ ] **Step 6: Run test to confirm it passes**

```bash
go test ./pkg/manageserver/agents/... -run TestIngestScan_StampsInstanceInfo -v
go test ./pkg/manageserver/... -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/manageserver/agents/handlers_gateway.go pkg/manageserver/server.go
git commit -m "feat(manageserver): stamp ManageServerID/Name on relayed scans"
```

---

## Task 3: Schema migration v29

**Files:**
- Modify: `pkg/store/migrations.go`

- [ ] **Step 1: Write failing test**

In `pkg/store/migrations_test.go` (or create a new test adjacent to it — check for existing pattern):

```go
//go:build integration
func TestMigration_V29_ManageServerColumns(t *testing.T) {
    db := newTestDB(t)
    // v29 should already be applied by newTestDB which runs Migrate.
    // Verify columns exist.
    _, err := db.pool.Exec(context.Background(),
        `SELECT manage_server_id, manage_server_name FROM scans LIMIT 0`)
    require.NoError(t, err, "scans.manage_server_id / manage_server_name missing")

    _, err = db.pool.Exec(context.Background(),
        `SELECT manage_server_id FROM findings LIMIT 0`)
    require.NoError(t, err, "findings.manage_server_id missing")

    _, err = db.pool.Exec(context.Background(),
        `SELECT org_id, phase, name, status, progress_pct FROM nacsa_migration_phases LIMIT 0`)
    require.NoError(t, err, "nacsa_migration_phases table missing")

    _, err = db.pool.Exec(context.Background(),
        `SELECT id, org_id, phase, name, status, budget_rm FROM nacsa_migration_activities LIMIT 0`)
    require.NoError(t, err, "nacsa_migration_activities table missing")
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
go test -tags integration -run TestMigration_V29_ManageServerColumns ./pkg/store/... -v
```

Expected: FAIL (`manage_server_id` column does not exist).

- [ ] **Step 3: Add v29 migration**

Append to the `migrations` slice in `pkg/store/migrations.go`:

```go
// Version 29: NACSA Arahan 9 analytics — manage server identity on
// scans/findings + migration-phase admin tables.
`ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS manage_server_id   TEXT,
    ADD COLUMN IF NOT EXISTS manage_server_name TEXT;

CREATE INDEX IF NOT EXISTS idx_scans_manage_server
    ON scans (org_id, manage_server_id)
    WHERE manage_server_id IS NOT NULL;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS manage_server_id TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_manage_server
    ON findings (org_id, manage_server_id)
    WHERE manage_server_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS nacsa_migration_phases (
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    phase        INT  NOT NULL CHECK (phase IN (1, 2, 3)),
    name         TEXT NOT NULL DEFAULT '',
    period       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'not_started'
                 CHECK (status IN ('not_started', 'in_progress', 'complete')),
    progress_pct INT  NOT NULL DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
    PRIMARY KEY (org_id, phase)
);

CREATE TABLE IF NOT EXISTS nacsa_migration_activities (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL,
    phase      INT  NOT NULL,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending', 'active', 'done')),
    budget_rm  BIGINT NOT NULL DEFAULT 0,
    sort_order INT    NOT NULL DEFAULT 0,
    FOREIGN KEY (org_id, phase)
        REFERENCES nacsa_migration_phases(org_id, phase) ON DELETE CASCADE
);`,
```

- [ ] **Step 4: Run to confirm migration test passes**

```bash
go test -tags integration -run TestMigration_V29_ManageServerColumns ./pkg/store/... -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/store/migrations.go
git commit -m "feat(store): v29 migration — manage_server_id + nacsa_migration tables"
```

---

## Task 4: Persist manage_server_id through the findings pipeline

**Files:**
- Modify: `pkg/store/types.go`
- Modify: `pkg/store/findings.go`

- [ ] **Step 1: Add ManageServerID to Finding struct**

In `pkg/store/types.go`, add to the `Finding` struct after `ImageDigest`:

```go
ManageServerID string
```

- [ ] **Step 2: Write failing test**

In `pkg/store/findings_test.go` (integration, look for existing test helpers):

```go
//go:build integration
func TestSaveWithFindings_PersistsManageServerID(t *testing.T) {
    db := newTestDB(t)
    orgID := createTestOrg(t, db)

    scan := makeMinimalScan(orgID)
    scan.Metadata.ManageServerID   = "manage-001"
    scan.Metadata.ManageServerName = "HQ Server"
    scan.Findings = []model.Finding{makeMinimalFinding()}

    findings := store.ExtractFindings(&scan)
    err := db.SaveScanWithFindings(context.Background(), &scan, findings)
    require.NoError(t, err)

    // Verify scans row
    var gotID, gotName string
    err = db.pool.QueryRow(context.Background(),
        `SELECT manage_server_id, manage_server_name FROM scans WHERE id = $1`, scan.ID,
    ).Scan(&gotID, &gotName)
    require.NoError(t, err)
    assert.Equal(t, "manage-001", gotID)
    assert.Equal(t, "HQ Server", gotName)

    // Verify findings row
    var gotFindingMSID string
    err = db.pool.QueryRow(context.Background(),
        `SELECT manage_server_id FROM findings WHERE scan_id = $1 LIMIT 1`, scan.ID,
    ).Scan(&gotFindingMSID)
    require.NoError(t, err)
    assert.Equal(t, "manage-001", gotFindingMSID)
}
```

- [ ] **Step 3: Run to confirm it fails**

```bash
go test -tags integration -run TestSaveWithFindings_PersistsManageServerID ./pkg/store/... -v
```

Expected: FAIL.

- [ ] **Step 4: Update insertFindingsChunk**

In `pkg/store/findings.go`, the `insertFindingsChunk` function currently has `const cols = 18`. Change it to 19 and add `manage_server_id`:

```go
func insertFindingsChunk(ctx context.Context, tx pgx.Tx, chunk []Finding) error {
    const cols = 19
    args := make([]any, 0, len(chunk)*cols)
    valueStrs := make([]string, 0, len(chunk))
    for i := range chunk {
        f := &chunk[i]
        base := i * cols
        valueStrs = append(valueStrs, fmt.Sprintf(
            "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
            base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8,
            base+9, base+10, base+11, base+12, base+13, base+14, base+15, base+16,
            base+17, base+18, base+19,
        ))
        args = append(args,
            f.ID, f.ScanID, f.OrgID, f.Hostname, f.FindingIndex,
            f.Module, f.FilePath,
            f.Algorithm, f.KeySize, f.PQCStatus, f.MigrationPriority,
            f.NotAfter, f.Subject, f.Issuer, f.Reachability, f.CreatedAt,
            f.ImageRef, f.ImageDigest, f.ManageServerID,
        )
    }

    sql := `INSERT INTO findings (
        id, scan_id, org_id, hostname, finding_index,
        module, file_path,
        algorithm, key_size, pqc_status, migration_priority,
        not_after, subject, issuer, reachability, created_at,
        image_ref, image_digest, manage_server_id
    ) VALUES ` + strings.Join(valueStrs, ",") + `
    ON CONFLICT (scan_id, finding_index) DO NOTHING`

    _, err := tx.Exec(ctx, sql, args...)
    return err
}
```

- [ ] **Step 5: Update ExtractFindings to copy ManageServerID**

In `pkg/store/extract.go`, inside the finding-extraction loop, add to the `Finding` struct literal (after `ImageDigest`):

```go
ManageServerID: scan.Metadata.ManageServerID,
```

Check `pkg/store/extract.go` for the exact struct literal location.

- [ ] **Step 6: Update SaveScanWithFindings scans INSERT**

In `pkg/store/findings.go`, in the `SaveScanWithFindings` function, update the `INSERT INTO scans` statement:

```go
_, err = tx.Exec(ctx, `
    INSERT INTO scans
      (id, hostname, timestamp, profile,
       total_findings, safe, transitional, deprecated, unsafe,
       result_json, org_id, findings_extracted_at, scan_source,
       manage_server_id, manage_server_name)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), $12, $13, $14)
    ON CONFLICT (id) DO UPDATE SET
      hostname             = EXCLUDED.hostname,
      timestamp            = EXCLUDED.timestamp,
      profile              = EXCLUDED.profile,
      total_findings       = EXCLUDED.total_findings,
      safe                 = EXCLUDED.safe,
      transitional         = EXCLUDED.transitional,
      deprecated           = EXCLUDED.deprecated,
      unsafe               = EXCLUDED.unsafe,
      result_json          = EXCLUDED.result_json,
      org_id               = EXCLUDED.org_id,
      findings_extracted_at = EXCLUDED.findings_extracted_at,
      scan_source          = EXCLUDED.scan_source,
      manage_server_id     = EXCLUDED.manage_server_id,
      manage_server_name   = EXCLUDED.manage_server_name
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
    string(scan.Metadata.Source),
    nullableStr(scan.Metadata.ManageServerID),
    nullableStr(scan.Metadata.ManageServerName),
)
```

Add a helper at the bottom of `findings.go` if not already present:

```go
// nullableStr returns nil for empty string so PostgreSQL stores NULL
// instead of an empty string for optional TEXT columns.
func nullableStr(s string) any {
    if s == "" {
        return nil
    }
    return s
}
```

- [ ] **Step 7: Also update SaveScanWithJobContext scans INSERT**

In the same file, `SaveScanWithJobContext` has its own INSERT. Add `manage_server_id, manage_server_name` columns and `$15, $16` parameters (currently ends at `$14` for `scan_source`):

```go
_, err = tx.Exec(ctx, `
    INSERT INTO scans
      (id, hostname, timestamp, profile,
       total_findings, safe, transitional, deprecated, unsafe,
       result_json, org_id, findings_extracted_at,
       engine_id, scan_job_id, scan_source,
       manage_server_id, manage_server_name)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), $12, $13, $14, $15, $16)
    ON CONFLICT (id) DO UPDATE SET
      hostname              = EXCLUDED.hostname,
      timestamp             = EXCLUDED.timestamp,
      profile               = EXCLUDED.profile,
      total_findings        = EXCLUDED.total_findings,
      safe                  = EXCLUDED.safe,
      transitional          = EXCLUDED.transitional,
      deprecated            = EXCLUDED.deprecated,
      unsafe                = EXCLUDED.unsafe,
      result_json           = EXCLUDED.result_json,
      org_id                = EXCLUDED.org_id,
      findings_extracted_at = EXCLUDED.findings_extracted_at,
      engine_id             = EXCLUDED.engine_id,
      scan_job_id           = EXCLUDED.scan_job_id,
      scan_source           = EXCLUDED.scan_source,
      manage_server_id      = EXCLUDED.manage_server_id,
      manage_server_name    = EXCLUDED.manage_server_name
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
    engineID,
    scanJobID,
    string(scan.Metadata.Source),
    nullableStr(scan.Metadata.ManageServerID),
    nullableStr(scan.Metadata.ManageServerName),
)
```

- [ ] **Step 8: Run tests**

```bash
go test -tags integration -run TestSaveWithFindings_PersistsManageServerID ./pkg/store/... -v
go test -tags integration ./pkg/store/... -count=1
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add pkg/store/types.go pkg/store/findings.go pkg/store/extract.go
git commit -m "feat(store): persist manage_server_id in scans and findings"
```

---

## Task 5: NACSA store — response types and Summary query

**Files:**
- Create: `pkg/store/nacsa.go`
- Create: `pkg/store/nacsa_test.go`
- Modify: `pkg/store/store.go`

- [ ] **Step 1: Create pkg/store/nacsa.go with types and NacsaSummary**

```go
package store

import (
    "context"
    "fmt"
    "time"
)

// NacsaSummary is the response for GET /api/v1/nacsa/summary.
type NacsaSummary struct {
    ReadinessPct    float64       `json:"readiness_pct"`
    TargetPct       float64       `json:"target_pct"`
    TargetYear      int           `json:"target_year"`
    Compliant       int64         `json:"compliant"`
    Transitional    int64         `json:"transitional"`
    NonCompliant    int64         `json:"non_compliant"`
    Safe            int64         `json:"safe"`
    TotalAssets     int64         `json:"total_assets"`
    TopBlockers     []NacsaBlocker `json:"top_blockers"`
    MigrationPhases []NacsaPhase  `json:"migration_phases"`
}

// NacsaBlocker is one top-blocker entry in NacsaSummary.
type NacsaBlocker struct {
    Algorithm  string `json:"algorithm"`
    Hostname   string `json:"hostname"`
    Severity   string `json:"severity"`
    AssetCount int64  `json:"asset_count"`
}

// NacsaPhase is migration-phase progress in NacsaSummary.
type NacsaPhase struct {
    Phase       int    `json:"phase"`
    Name        string `json:"name"`
    Status      string `json:"status"`
    ProgressPct int    `json:"progress_pct"`
}

// NacsaServerRow is one row for GET /api/v1/nacsa/servers.
type NacsaServerRow struct {
    ID           string     `json:"id"`
    Name         string     `json:"name"`
    HostCount    int64      `json:"host_count"`
    ReadinessPct float64    `json:"readiness_pct"`
    LastScanAt   *time.Time `json:"last_scan_at,omitempty"`
}

// NacsaHostRow is one row for GET /api/v1/nacsa/servers/{id}/hosts.
type NacsaHostRow struct {
    Hostname     string     `json:"hostname"`
    ScanProfile  string     `json:"scan_profile,omitempty"`
    ReadinessPct float64    `json:"readiness_pct"`
    LastScanAt   *time.Time `json:"last_scan_at,omitempty"`
    ModuleCount  int64      `json:"module_count"`
}

// NacsaCBOMRow is one algorithm row for GET /api/v1/nacsa/hosts/{hostname}/cbom.
type NacsaCBOMRow struct {
    Algorithm  string `json:"algorithm"`
    KeySize    int    `json:"key_size,omitempty"`
    PQCStatus  string `json:"pqc_status"`
    AssetCount int64  `json:"asset_count"`
    Module     string `json:"module"`
}

// NacsaRiskRow is one risk entry for GET /api/v1/nacsa/hosts/{hostname}/risk.
type NacsaRiskRow struct {
    Algorithm  string `json:"algorithm"`
    Hostname   string `json:"hostname"`
    Impact     int    `json:"impact"`
    Likelihood int    `json:"likelihood"`
    Score      int    `json:"score"`
    RiskBand   string `json:"risk_band"`
    AssetCount int64  `json:"asset_count"`
}

// NacsaMigResponse is the response for GET /api/v1/nacsa/migration.
type NacsaMigResponse struct {
    Phases []NacsaMigPhase `json:"phases"`
}

// NacsaMigPhase is one migration phase in NacsaMigResponse.
type NacsaMigPhase struct {
    Phase         int                `json:"phase"`
    Name          string             `json:"name"`
    Status        string             `json:"status"`
    ProgressPct   int                `json:"progress_pct"`
    Period        string             `json:"period"`
    Activities    []NacsaMigActivity `json:"activities"`
    BudgetTotalRM int64              `json:"budget_total_rm"`
    BudgetSpentRM int64              `json:"budget_spent_rm"`
}

// NacsaMigActivity is one activity row in NacsaMigPhase.
type NacsaMigActivity struct {
    Name     string `json:"name"`
    Status   string `json:"status"`
    BudgetRM int64  `json:"budget_rm"`
}

// NacsaScopeFilter restricts NACSA queries to a specific manage server
// and/or hostname. Zero values mean "show all".
type NacsaScopeFilter struct {
    ManageServerID string
    Hostname       string
}

// nacsaReadinessPct computes NACSA readiness % from safe/total.
// Returns 0 when total is 0 (avoid division by zero).
func nacsaReadinessPct(safe, total int64) float64 {
    if total == 0 {
        return 0
    }
    return float64(safe) / float64(total) * 100
}

// nacsaRiskBand converts a score to a risk band label.
func nacsaRiskBand(score int) string {
    switch {
    case score >= 20:
        return "CRITICAL"
    case score >= 10:
        return "HIGH"
    case score >= 5:
        return "MEDIUM"
    default:
        return "LOW"
    }
}

// nacsaImpactLikelihood returns default impact and likelihood for a pqc_status.
// Higher priority overrides likelihood (max 5).
func nacsaImpactLikelihood(pqcStatus string, migrationPriority int) (impact, likelihood int) {
    switch pqcStatus {
    case "UNSAFE":
        impact, likelihood = 5, 4
    case "DEPRECATED":
        impact, likelihood = 4, 2
    case "TRANSITIONAL":
        impact, likelihood = 3, 3
    default:
        impact, likelihood = 1, 1
    }
    if migrationPriority > 0 && migrationPriority < 5 {
        likelihood = migrationPriority
    }
    return
}

// latestScansCTE returns a WITH clause fragment filtering to latest scan
// per hostname within the given org (and optionally manage_server_id).
// The returned string is ready to embed: "latest_scans AS (...)"
func latestScansCTE(orgID string, scope NacsaScopeFilter) (cte string, args []any) {
    args = []any{orgID}
    where := "WHERE org_id = $1"
    if scope.ManageServerID != "" {
        args = append(args, scope.ManageServerID)
        where += fmt.Sprintf(" AND manage_server_id = $%d", len(args))
    }
    if scope.Hostname != "" {
        args = append(args, scope.Hostname)
        where += fmt.Sprintf(" AND hostname = $%d", len(args))
    }
    cte = fmt.Sprintf(`latest_scans AS (
        SELECT DISTINCT ON (hostname) id, org_id, manage_server_id, manage_server_name
        FROM scans
        %s
        ORDER BY hostname, timestamp DESC
    )`, where)
    return cte, args
}

// GetNacsaSummary returns the tenant-level NACSA summary.
func (s *PostgresStore) GetNacsaSummary(ctx context.Context, orgID string, scope NacsaScopeFilter) (NacsaSummary, error) {
    cte, args := latestScansCTE(orgID, scope)

    nextArg := len(args) + 1
    _ = nextArg // args are already built; findings query reuses same args

    // Aggregate pqc_status counts from findings joined to latest scans.
    q := fmt.Sprintf(`
WITH %s
SELECT
    SUM(CASE WHEN f.pqc_status = 'SAFE'         THEN 1 ELSE 0 END) AS safe_count,
    SUM(CASE WHEN f.pqc_status = 'TRANSITIONAL' THEN 1 ELSE 0 END) AS trans_count,
    SUM(CASE WHEN f.pqc_status IN ('DEPRECATED','UNSAFE') THEN 1 ELSE 0 END) AS noncompliant_count,
    COUNT(*) AS total_count
FROM findings f
JOIN latest_scans ls ON f.scan_id = ls.id
WHERE f.org_id = $1`, cte)

    var safe, trans, noncompliant, total int64
    err := s.pool.QueryRow(ctx, q, args...).Scan(&safe, &trans, &noncompliant, &total)
    if err != nil {
        return NacsaSummary{}, fmt.Errorf("nacsa summary counts: %w", err)
    }

    // Top blockers: UNSAFE findings grouped by algorithm+hostname.
    cte2, args2 := latestScansCTE(orgID, scope)
    bq := fmt.Sprintf(`
WITH %s
SELECT f.algorithm, f.hostname, COUNT(*) AS cnt
FROM findings f
JOIN latest_scans ls ON f.scan_id = ls.id
WHERE f.org_id = $1 AND f.pqc_status = 'UNSAFE'
GROUP BY f.algorithm, f.hostname
ORDER BY cnt DESC
LIMIT 5`, cte2)

    rows, err := s.pool.Query(ctx, bq, args2...)
    if err != nil {
        return NacsaSummary{}, fmt.Errorf("nacsa top blockers: %w", err)
    }
    defer rows.Close()
    var blockers []NacsaBlocker
    for rows.Next() {
        var b NacsaBlocker
        if err := rows.Scan(&b.Algorithm, &b.Hostname, &b.AssetCount); err != nil {
            return NacsaSummary{}, err
        }
        b.Severity = "CRITICAL"
        blockers = append(blockers, b)
    }
    if err := rows.Err(); err != nil {
        return NacsaSummary{}, err
    }

    // Migration phases from nacsa_migration_phases.
    phases, err := s.listNacsaPhasesSummary(ctx, orgID)
    if err != nil {
        return NacsaSummary{}, err
    }

    return NacsaSummary{
        ReadinessPct:    nacsaReadinessPct(safe, total),
        TargetPct:       80,
        TargetYear:      2030,
        Compliant:       safe,
        Transitional:    trans,
        NonCompliant:    noncompliant,
        Safe:            safe,
        TotalAssets:     total,
        TopBlockers:     blockers,
        MigrationPhases: phases,
    }, nil
}

// listNacsaPhasesSummary returns the 3 migration phases for a summary card.
// Returns empty-name placeholder rows when no data has been inserted.
func (s *PostgresStore) listNacsaPhasesSummary(ctx context.Context, orgID string) ([]NacsaPhase, error) {
    rows, err := s.pool.Query(ctx, `
        SELECT phase, name, status, progress_pct
        FROM nacsa_migration_phases
        WHERE org_id = $1
        ORDER BY phase`, orgID)
    if err != nil {
        return nil, fmt.Errorf("nacsa phases: %w", err)
    }
    defer rows.Close()
    var phases []NacsaPhase
    for rows.Next() {
        var p NacsaPhase
        if err := rows.Scan(&p.Phase, &p.Name, &p.Status, &p.ProgressPct); err != nil {
            return nil, err
        }
        phases = append(phases, p)
    }
    return phases, rows.Err()
}
```

- [ ] **Step 2: Write failing test**

In `pkg/store/nacsa_test.go`:

```go
//go:build integration

package store_test

import (
    "context"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestGetNacsaSummary_Empty(t *testing.T) {
    db := newTestDB(t)
    orgID := createTestOrg(t, db)

    summary, err := db.GetNacsaSummary(context.Background(), orgID, NacsaScopeFilter{})
    require.NoError(t, err)
    assert.Equal(t, float64(0), summary.ReadinessPct)
    assert.Equal(t, int64(0), summary.TotalAssets)
    assert.Empty(t, summary.TopBlockers)
    assert.Equal(t, float64(80), summary.TargetPct)
    assert.Equal(t, 2030, summary.TargetYear)
}
```

- [ ] **Step 3: Run to confirm it fails**

```bash
go test -tags integration -run TestGetNacsaSummary_Empty ./pkg/store/... -v
```

Expected: FAIL (compile error — `GetNacsaSummary` not on `Store` interface yet).

- [ ] **Step 4: Add NACSA methods to Store interface**

In `pkg/store/store.go`, add to the `Store` interface (after `GetOrgSnapshot`):

```go
// --- NACSA Arahan 9 Analytics ---

// GetNacsaSummary returns tenant-level readiness stats, top blockers,
// and migration phase summary. scope filters to a specific manage server
// and/or hostname when set.
GetNacsaSummary(ctx context.Context, orgID string, scope NacsaScopeFilter) (NacsaSummary, error)

// ListNacsaServers returns manage servers for the tenant with per-server
// readiness % and host count.
ListNacsaServers(ctx context.Context, orgID string) ([]NacsaServerRow, error)

// ListNacsaHosts returns hosts under a specific manage server.
ListNacsaHosts(ctx context.Context, orgID, manageServerID string) ([]NacsaHostRow, error)

// ListNacsaCBOM returns crypto asset inventory for a hostname, filtered
// by PQC statuses (empty slice = all statuses).
ListNacsaCBOM(ctx context.Context, orgID, hostname string, statuses []string) ([]NacsaCBOMRow, error)

// ListNacsaRisk returns risk register rows for a hostname, sorted by
// score descending. sortBy accepted values: "score" (default), "impact", "hostname".
ListNacsaRisk(ctx context.Context, orgID, hostname, sortBy string) ([]NacsaRiskRow, error)

// GetNacsaMigration returns full migration phase data with activities
// and budget for the tenant.
GetNacsaMigration(ctx context.Context, orgID string) (NacsaMigResponse, error)
```

- [ ] **Step 5: Run test to confirm it passes**

```bash
go test -tags integration -run TestGetNacsaSummary_Empty ./pkg/store/... -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/store/nacsa.go pkg/store/nacsa_test.go pkg/store/store.go
git commit -m "feat(store): NACSA summary query + response types"
```

---

## Task 6: NACSA store — Servers, Hosts, CBOM, Risk, Migration queries

**Files:**
- Modify: `pkg/store/nacsa.go`
- Modify: `pkg/store/nacsa_test.go`

- [ ] **Step 1: Implement ListNacsaServers**

Append to `pkg/store/nacsa.go`:

```go
// ListNacsaServers groups scans by manage_server_id and returns readiness per server.
func (s *PostgresStore) ListNacsaServers(ctx context.Context, orgID string) ([]NacsaServerRow, error) {
    rows, err := s.pool.Query(ctx, `
WITH latest AS (
    SELECT DISTINCT ON (hostname)
        manage_server_id, manage_server_name, timestamp,
        safe, unsafe, deprecated, transitional,
        (safe + unsafe + deprecated + transitional) AS total
    FROM scans
    WHERE org_id = $1 AND manage_server_id IS NOT NULL
    ORDER BY hostname, timestamp DESC
)
SELECT
    manage_server_id,
    MAX(manage_server_name)   AS name,
    COUNT(*)                  AS host_count,
    CASE WHEN SUM(total) = 0 THEN 0
         ELSE ROUND(SUM(safe)::numeric / SUM(total)::numeric * 100, 1)
    END                       AS readiness_pct,
    MAX(timestamp)            AS last_scan_at
FROM latest
GROUP BY manage_server_id
ORDER BY readiness_pct DESC`, orgID)
    if err != nil {
        return nil, fmt.Errorf("nacsa servers: %w", err)
    }
    defer rows.Close()
    var result []NacsaServerRow
    for rows.Next() {
        var r NacsaServerRow
        if err := rows.Scan(&r.ID, &r.Name, &r.HostCount, &r.ReadinessPct, &r.LastScanAt); err != nil {
            return nil, err
        }
        result = append(result, r)
    }
    if result == nil {
        result = []NacsaServerRow{}
    }
    return result, rows.Err()
}

// ListNacsaHosts returns hosts for a specific manage server.
func (s *PostgresStore) ListNacsaHosts(ctx context.Context, orgID, manageServerID string) ([]NacsaHostRow, error) {
    rows, err := s.pool.Query(ctx, `
SELECT DISTINCT ON (hostname)
    hostname,
    profile,
    CASE WHEN (safe + unsafe + deprecated + transitional) = 0 THEN 0
         ELSE ROUND(safe::numeric / (safe + unsafe + deprecated + transitional)::numeric * 100, 1)
    END AS readiness_pct,
    timestamp,
    0 AS module_count
FROM scans
WHERE org_id = $1 AND manage_server_id = $2
ORDER BY hostname, timestamp DESC`, orgID, manageServerID)
    if err != nil {
        return nil, fmt.Errorf("nacsa hosts: %w", err)
    }
    defer rows.Close()
    var result []NacsaHostRow
    for rows.Next() {
        var r NacsaHostRow
        if err := rows.Scan(&r.Hostname, &r.ScanProfile, &r.ReadinessPct, &r.LastScanAt, &r.ModuleCount); err != nil {
            return nil, err
        }
        result = append(result, r)
    }
    if result == nil {
        result = []NacsaHostRow{}
    }
    return result, rows.Err()
}

// ListNacsaCBOM returns crypto algorithm inventory for a hostname.
func (s *PostgresStore) ListNacsaCBOM(ctx context.Context, orgID, hostname string, statuses []string) ([]NacsaCBOMRow, error) {
    q := `
WITH latest AS (
    SELECT DISTINCT ON (hostname) id
    FROM scans
    WHERE org_id = $1 AND hostname = $2
    ORDER BY hostname, timestamp DESC
)
SELECT f.algorithm, f.key_size, f.pqc_status, COUNT(*) AS cnt, f.module
FROM findings f
JOIN latest l ON f.scan_id = l.id
WHERE f.org_id = $1`

    args := []any{orgID, hostname}
    if len(statuses) > 0 {
        placeholders := make([]string, len(statuses))
        for i, s := range statuses {
            args = append(args, s)
            placeholders[i] = fmt.Sprintf("$%d", len(args))
        }
        q += fmt.Sprintf(" AND f.pqc_status IN (%s)", strings.Join(placeholders, ","))
    }
    q += `
GROUP BY f.algorithm, f.key_size, f.pqc_status, f.module
ORDER BY
    CASE f.pqc_status WHEN 'UNSAFE' THEN 1 WHEN 'DEPRECATED' THEN 2 WHEN 'TRANSITIONAL' THEN 3 ELSE 4 END,
    cnt DESC`

    rows, err := s.pool.Query(ctx, q, args...)
    if err != nil {
        return nil, fmt.Errorf("nacsa cbom: %w", err)
    }
    defer rows.Close()
    var result []NacsaCBOMRow
    for rows.Next() {
        var r NacsaCBOMRow
        if err := rows.Scan(&r.Algorithm, &r.KeySize, &r.PQCStatus, &r.AssetCount, &r.Module); err != nil {
            return nil, err
        }
        result = append(result, r)
    }
    if result == nil {
        result = []NacsaCBOMRow{}
    }
    return result, rows.Err()
}

// ListNacsaRisk returns risk register rows derived from findings.
func (s *PostgresStore) ListNacsaRisk(ctx context.Context, orgID, hostname, sortBy string) ([]NacsaRiskRow, error) {
    orderCol := "score DESC"
    switch sortBy {
    case "impact":
        orderCol = "impact DESC, score DESC"
    case "hostname":
        orderCol = "f.hostname ASC, score DESC"
    }

    whereExtra := ""
    args := []any{orgID}
    if hostname != "" {
        args = append(args, hostname)
        whereExtra = fmt.Sprintf(" AND f.hostname = $%d", len(args))
    }

    q := fmt.Sprintf(`
WITH latest AS (
    SELECT DISTINCT ON (hostname) id
    FROM scans
    WHERE org_id = $1
    ORDER BY hostname, timestamp DESC
)
SELECT
    f.algorithm,
    f.hostname,
    f.pqc_status,
    COALESCE(f.migration_priority, 0) AS max_priority,
    COUNT(*) AS asset_count
FROM findings f
JOIN latest l ON f.scan_id = l.id
WHERE f.org_id = $1
  AND f.pqc_status IN ('UNSAFE','DEPRECATED','TRANSITIONAL')
  %s
GROUP BY f.algorithm, f.hostname, f.pqc_status, f.migration_priority
`, whereExtra)

    rows, err := s.pool.Query(ctx, q, args...)
    if err != nil {
        return nil, fmt.Errorf("nacsa risk: %w", err)
    }
    defer rows.Close()
    var result []NacsaRiskRow
    for rows.Next() {
        var algo, host, status string
        var maxPriority int
        var cnt int64
        if err := rows.Scan(&algo, &host, &status, &maxPriority, &cnt); err != nil {
            return nil, err
        }
        impact, likelihood := nacsaImpactLikelihood(status, maxPriority)
        score := impact * likelihood
        result = append(result, NacsaRiskRow{
            Algorithm:  algo,
            Hostname:   host,
            Impact:     impact,
            Likelihood: likelihood,
            Score:      score,
            RiskBand:   nacsaRiskBand(score),
            AssetCount: cnt,
        })
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    // Sort in Go since the ordering involves computed columns.
    sort.Slice(result, func(i, j int) bool {
        switch sortBy {
        case "impact":
            if result[i].Impact != result[j].Impact {
                return result[i].Impact > result[j].Impact
            }
            return result[i].Score > result[j].Score
        case "hostname":
            if result[i].Hostname != result[j].Hostname {
                return result[i].Hostname < result[j].Hostname
            }
            return result[i].Score > result[j].Score
        default:
            return result[i].Score > result[j].Score
        }
    })
    if result == nil {
        result = []NacsaRiskRow{}
    }
    return result, nil
}

// GetNacsaMigration returns phase + activity data. Empty phases slice when
// no data has been inserted (admin has not configured migration yet).
func (s *PostgresStore) GetNacsaMigration(ctx context.Context, orgID string) (NacsaMigResponse, error) {
    rows, err := s.pool.Query(ctx, `
        SELECT phase, name, period, status, progress_pct
        FROM nacsa_migration_phases
        WHERE org_id = $1
        ORDER BY phase`, orgID)
    if err != nil {
        return NacsaMigResponse{}, fmt.Errorf("nacsa migration phases: %w", err)
    }
    defer rows.Close()
    phaseMap := map[int]*NacsaMigPhase{}
    var phases []NacsaMigPhase
    for rows.Next() {
        var p NacsaMigPhase
        if err := rows.Scan(&p.Phase, &p.Name, &p.Period, &p.Status, &p.ProgressPct); err != nil {
            return NacsaMigResponse{}, err
        }
        phases = append(phases, p)
        phaseMap[p.Phase] = &phases[len(phases)-1]
    }
    if err := rows.Err(); err != nil {
        return NacsaMigResponse{}, err
    }

    // Fetch activities for each phase.
    aRows, err := s.pool.Query(ctx, `
        SELECT phase, name, status, budget_rm
        FROM nacsa_migration_activities
        WHERE org_id = $1
        ORDER BY phase, sort_order`, orgID)
    if err != nil {
        return NacsaMigResponse{}, fmt.Errorf("nacsa migration activities: %w", err)
    }
    defer aRows.Close()
    for aRows.Next() {
        var phaseNum int
        var a NacsaMigActivity
        if err := aRows.Scan(&phaseNum, &a.Name, &a.Status, &a.BudgetRM); err != nil {
            return NacsaMigResponse{}, err
        }
        if p, ok := phaseMap[phaseNum]; ok {
            p.Activities = append(p.Activities, a)
            p.BudgetTotalRM += a.BudgetRM
            if a.Status == "done" {
                p.BudgetSpentRM += a.BudgetRM
            }
        }
    }
    if err := aRows.Err(); err != nil {
        return NacsaMigResponse{}, err
    }

    return NacsaMigResponse{Phases: phases}, nil
}
```

Add `"sort"` and `"strings"` to the imports at the top of `nacsa.go`.

- [ ] **Step 2: Write and run integration tests**

Add to `pkg/store/nacsa_test.go`:

```go
func TestListNacsaServers_Empty(t *testing.T) {
    db := newTestDB(t)
    orgID := createTestOrg(t, db)
    servers, err := db.ListNacsaServers(context.Background(), orgID)
    require.NoError(t, err)
    assert.Empty(t, servers)
}

func TestListNacsaCBOM_FiltersStatus(t *testing.T) {
    db := newTestDB(t)
    orgID := createTestOrg(t, db)
    // Insert a scan with findings
    scan := makeMinimalScan(orgID)
    scan.Metadata.Hostname = "host-cbom"
    scan.Metadata.ManageServerID = "srv-1"
    scan.Findings = []model.Finding{
        makeUnsafeFinding("RSA-1024"),
        makeSafeFinding("SHA-256"),
    }
    findings := store.ExtractFindings(&scan)
    require.NoError(t, db.SaveScanWithFindings(context.Background(), &scan, findings))

    rows, err := db.ListNacsaCBOM(context.Background(), orgID, "host-cbom", []string{"UNSAFE"})
    require.NoError(t, err)
    assert.Equal(t, 1, len(rows))
    assert.Equal(t, "RSA-1024", rows[0].Algorithm)
}

func TestGetNacsaMigration_Empty(t *testing.T) {
    db := newTestDB(t)
    orgID := createTestOrg(t, db)
    resp, err := db.GetNacsaMigration(context.Background(), orgID)
    require.NoError(t, err)
    assert.Empty(t, resp.Phases)
}
```

```bash
go test -tags integration -run "TestListNacsaServers_Empty|TestListNacsaCBOM_FiltersStatus|TestGetNacsaMigration_Empty" ./pkg/store/... -v
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add pkg/store/nacsa.go pkg/store/nacsa_test.go
git commit -m "feat(store): NACSA server/host/CBOM/risk/migration queries"
```

---

## Task 7: NACSA HTTP handlers + route mounting

**Files:**
- Create: `pkg/server/handlers_nacsa.go`
- Modify: `pkg/server/server.go`

- [ ] **Step 1: Create handlers_nacsa.go**

```go
package server

import (
    "log"
    "net/http"
    "strings"

    "github.com/go-chi/chi/v5"

    "github.com/amiryahaya/triton/pkg/store"
)

// GET /api/v1/nacsa/summary
func (s *Server) handleNacsaSummary(w http.ResponseWriter, r *http.Request) {
    orgID := TenantFromContext(r.Context())
    scope := store.NacsaScopeFilter{
        ManageServerID: r.URL.Query().Get("manage_server_id"),
        Hostname:       r.URL.Query().Get("hostname"),
    }
    summary, err := s.store.GetNacsaSummary(r.Context(), orgID, scope)
    if err != nil {
        log.Printf("nacsa summary: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    writeJSON(w, http.StatusOK, summary)
}

// GET /api/v1/nacsa/servers
func (s *Server) handleNacsaServers(w http.ResponseWriter, r *http.Request) {
    orgID := TenantFromContext(r.Context())
    rows, err := s.store.ListNacsaServers(r.Context(), orgID)
    if err != nil {
        log.Printf("nacsa servers: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/nacsa/servers/{serverID}/hosts
func (s *Server) handleNacsaHosts(w http.ResponseWriter, r *http.Request) {
    orgID := TenantFromContext(r.Context())
    serverID := chi.URLParam(r, "serverID")
    rows, err := s.store.ListNacsaHosts(r.Context(), orgID, serverID)
    if err != nil {
        log.Printf("nacsa hosts: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/nacsa/hosts/{hostname}/cbom
func (s *Server) handleNacsaCBOM(w http.ResponseWriter, r *http.Request) {
    orgID := TenantFromContext(r.Context())
    hostname := chi.URLParam(r, "hostname")
    statusParam := r.URL.Query().Get("status")
    var statuses []string
    if statusParam != "" {
        statuses = strings.Split(statusParam, ",")
    }
    rows, err := s.store.ListNacsaCBOM(r.Context(), orgID, hostname, statuses)
    if err != nil {
        log.Printf("nacsa cbom: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/nacsa/hosts/{hostname}/risk
func (s *Server) handleNacsaRisk(w http.ResponseWriter, r *http.Request) {
    orgID := TenantFromContext(r.Context())
    hostname := chi.URLParam(r, "hostname")
    sortBy := r.URL.Query().Get("sort")
    rows, err := s.store.ListNacsaRisk(r.Context(), orgID, hostname, sortBy)
    if err != nil {
        log.Printf("nacsa risk: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/nacsa/migration
func (s *Server) handleNacsaMigration(w http.ResponseWriter, r *http.Request) {
    orgID := TenantFromContext(r.Context())
    resp, err := s.store.GetNacsaMigration(r.Context(), orgID)
    if err != nil {
        log.Printf("nacsa migration: %v", err)
        writeError(w, http.StatusInternalServerError, "internal server error")
        return
    }
    writeJSON(w, http.StatusOK, resp)
}
```

- [ ] **Step 2: Mount routes in server.go**

In `pkg/server/server.go`, inside the authenticated `r.Group(...)` block where other analytics routes are mounted (near the `r.Get("/inventory", ...)` lines), add:

```go
// NACSA Arahan 9 dashboard
r.Route("/nacsa", func(r chi.Router) {
    r.Get("/summary", s.handleNacsaSummary)
    r.Get("/servers", s.handleNacsaServers)
    r.Get("/servers/{serverID}/hosts", s.handleNacsaHosts)
    r.Get("/hosts/{hostname}/cbom", s.handleNacsaCBOM)
    r.Get("/hosts/{hostname}/risk", s.handleNacsaRisk)
    r.Get("/migration", s.handleNacsaMigration)
})
```

- [ ] **Step 3: Write handler tests**

Create `pkg/server/handlers_nacsa_test.go`:

```go
package server_test

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestHandleNacsaSummary_ReturnsOK(t *testing.T) {
    srv := newTestServer(t) // uses the existing test server helper
    req := httptest.NewRequest(http.MethodGet, "/api/v1/nacsa/summary", nil)
    req = withTestTenant(req, testOrgID) // helper that injects tenant context
    rec := httptest.NewRecorder()
    srv.ServeHTTP(rec, req)

    require.Equal(t, http.StatusOK, rec.Code)
    var body map[string]any
    require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
    assert.Contains(t, body, "readiness_pct")
    assert.Contains(t, body, "target_pct")
    assert.Equal(t, float64(80), body["target_pct"])
}

func TestHandleNacsaServers_ReturnsArray(t *testing.T) {
    srv := newTestServer(t)
    req := httptest.NewRequest(http.MethodGet, "/api/v1/nacsa/servers", nil)
    req = withTestTenant(req, testOrgID)
    rec := httptest.NewRecorder()
    srv.ServeHTTP(rec, req)

    require.Equal(t, http.StatusOK, rec.Code)
    var rows []map[string]any
    require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rows))
    // empty org returns empty array, not null
    assert.NotNil(t, rows)
}

func TestHandleNacsaMigration_EmptyPhasesArray(t *testing.T) {
    srv := newTestServer(t)
    req := httptest.NewRequest(http.MethodGet, "/api/v1/nacsa/migration", nil)
    req = withTestTenant(req, testOrgID)
    rec := httptest.NewRecorder()
    srv.ServeHTTP(rec, req)

    require.Equal(t, http.StatusOK, rec.Code)
    var body map[string]any
    require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
    phases, ok := body["phases"].([]any)
    assert.True(t, ok)
    assert.Empty(t, phases)
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/server/... -run "TestHandleNacsa" -v
go build ./...
```

Expected: PASS. The `go build ./...` confirms no compile errors.

- [ ] **Step 5: Commit**

```bash
git add pkg/server/handlers_nacsa.go pkg/server/handlers_nacsa_test.go pkg/server/server.go
git commit -m "feat(server): NACSA Arahan 9 API handlers + routes"
```

---

## Task 8: API client types and methods

**Files:**
- Modify: `web/packages/api-client/src/reportServer.ts`

- [ ] **Step 1: Add NACSA types to reportServer.ts**

Add after the existing `PriorityRow` interface:

```typescript
// ===== NACSA Arahan 9 =====

export interface NacsaBlocker {
  algorithm: string;
  hostname: string;
  severity: string;
  asset_count: number;
}

export interface NacsaPhase {
  phase: number;
  name: string;
  status: 'not_started' | 'in_progress' | 'complete';
  progress_pct: number;
}

export interface NacsaSummary {
  readiness_pct: number;
  target_pct: number;
  target_year: number;
  compliant: number;
  transitional: number;
  non_compliant: number;
  safe: number;
  total_assets: number;
  top_blockers: NacsaBlocker[];
  migration_phases: NacsaPhase[];
}

export interface NacsaServerRow {
  id: string;
  name: string;
  host_count: number;
  readiness_pct: number;
  last_scan_at?: string;
}

export interface NacsaHostRow {
  hostname: string;
  scan_profile?: string;
  readiness_pct: number;
  last_scan_at?: string;
  module_count: number;
}

export interface NacsaCBOMRow {
  algorithm: string;
  key_size?: number;
  pqc_status: PqcStatus;
  asset_count: number;
  module: string;
}

export interface NacsaRiskRow {
  algorithm: string;
  hostname: string;
  impact: number;
  likelihood: number;
  score: number;
  risk_band: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  asset_count: number;
}

export interface NacsaMigActivity {
  name: string;
  status: 'pending' | 'active' | 'done';
  budget_rm: number;
}

export interface NacsaMigPhase {
  phase: number;
  name: string;
  status: 'not_started' | 'in_progress' | 'complete';
  progress_pct: number;
  period: string;
  activities: NacsaMigActivity[];
  budget_total_rm: number;
  budget_spent_rm: number;
}

export interface NacsaMigResponse {
  phases: NacsaMigPhase[];
}
```

- [ ] **Step 2: Add NACSA methods to createReportApi**

Inside `createReportApi`, add after the existing analytics methods:

```typescript
// NACSA Arahan 9 (Phase 3)
nacsaSummary: (p?: { manage_server_id?: string; hostname?: string }) =>
  http.get<NacsaSummary>(`/v1/nacsa/summary${buildQS(p)}`),
nacsaServers: () =>
  http.get<NacsaServerRow[]>('/v1/nacsa/servers'),
nacsaHosts: (serverID: string) =>
  http.get<NacsaHostRow[]>(`/v1/nacsa/servers/${encodeURIComponent(serverID)}/hosts`),
nacsaCBOM: (hostname: string, p?: { status?: string }) =>
  http.get<NacsaCBOMRow[]>(`/v1/nacsa/hosts/${encodeURIComponent(hostname)}/cbom${buildQS(p)}`),
nacsaRisk: (hostname: string, p?: { sort?: string }) =>
  http.get<NacsaRiskRow[]>(`/v1/nacsa/hosts/${encodeURIComponent(hostname)}/risk${buildQS(p)}`),
nacsaMigration: () =>
  http.get<NacsaMigResponse>('/v1/nacsa/migration'),
```

- [ ] **Step 3: Verify TypeScript compiles**

```bash
cd /path/to/triton/web && pnpm --filter @triton/api-client build
```

Expected: Build succeeds with no type errors.

- [ ] **Step 4: Commit**

```bash
git add web/packages/api-client/src/reportServer.ts
git commit -m "feat(api-client): NACSA Arahan 9 types + report server methods"
```

---

## Task 9: Pinia store for NACSA data

**Files:**
- Create: `web/apps/report-portal/src/stores/nacsa.ts`

- [ ] **Step 1: Create nacsa.ts**

```typescript
import { defineStore } from 'pinia';
import { ref, reactive } from 'vue';
import type {
  NacsaSummary, NacsaServerRow, NacsaHostRow,
  NacsaCBOMRow, NacsaRiskRow, NacsaMigResponse,
} from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export interface NacsaDrillScope {
  manageServerId: string;
  manageServerName: string;
  hostname: string;
}

export const useNacsaStore = defineStore('nacsa', () => {
  // Drill scope — shared breadcrumb state
  const scope = reactive<NacsaDrillScope>({
    manageServerId: '',
    manageServerName: '',
    hostname: '',
  });

  // Data refs
  const summary    = ref<NacsaSummary | null>(null);
  const servers    = ref<NacsaServerRow[]>([]);
  const hosts      = ref<NacsaHostRow[]>([]);
  const cbom       = ref<NacsaCBOMRow[]>([]);
  const risk       = ref<NacsaRiskRow[]>([]);
  const migration  = ref<NacsaMigResponse | null>(null);

  const loading = ref(false);

  function drillToServer(id: string, name: string) {
    scope.manageServerId = id;
    scope.manageServerName = name;
    scope.hostname = '';
  }

  function drillToHost(hostname: string) {
    scope.hostname = hostname;
  }

  function clearDrill() {
    scope.manageServerId = '';
    scope.manageServerName = '';
    scope.hostname = '';
  }

  async function fetchSummary() {
    const api = useApiClient().get();
    loading.value = true;
    try {
      summary.value = await api.nacsaSummary({
        manage_server_id: scope.manageServerId || undefined,
        hostname:         scope.hostname || undefined,
      });
    } catch (e) {
      useToast().error({ title: 'Failed to load NACSA summary', description: String(e) });
    } finally {
      loading.value = false;
    }
  }

  async function fetchServers() {
    const api = useApiClient().get();
    loading.value = true;
    try {
      servers.value = await api.nacsaServers();
    } catch (e) {
      useToast().error({ title: 'Failed to load servers', description: String(e) });
    } finally {
      loading.value = false;
    }
  }

  async function fetchHosts() {
    if (!scope.manageServerId) { hosts.value = []; return; }
    const api = useApiClient().get();
    loading.value = true;
    try {
      hosts.value = await api.nacsaHosts(scope.manageServerId);
    } catch (e) {
      useToast().error({ title: 'Failed to load hosts', description: String(e) });
    } finally {
      loading.value = false;
    }
  }

  async function fetchCBOM(statusFilter?: string) {
    if (!scope.hostname) { cbom.value = []; return; }
    const api = useApiClient().get();
    loading.value = true;
    try {
      cbom.value = await api.nacsaCBOM(scope.hostname, { status: statusFilter });
    } catch (e) {
      useToast().error({ title: 'Failed to load CBOM', description: String(e) });
    } finally {
      loading.value = false;
    }
  }

  async function fetchRisk(sortBy?: string) {
    const api = useApiClient().get();
    loading.value = true;
    try {
      risk.value = await api.nacsaRisk(scope.hostname, { sort: sortBy });
    } catch (e) {
      useToast().error({ title: 'Failed to load risk', description: String(e) });
    } finally {
      loading.value = false;
    }
  }

  async function fetchMigration() {
    const api = useApiClient().get();
    loading.value = true;
    try {
      migration.value = await api.nacsaMigration();
    } catch (e) {
      useToast().error({ title: 'Failed to load migration', description: String(e) });
    } finally {
      loading.value = false;
    }
  }

  return {
    scope, summary, servers, hosts, cbom, risk, migration, loading,
    drillToServer, drillToHost, clearDrill,
    fetchSummary, fetchServers, fetchHosts, fetchCBOM, fetchRisk, fetchMigration,
  };
});
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd /path/to/triton/web && pnpm --filter report-portal build 2>&1 | head -40
```

Expected: Build succeeds (or only fails on the stub NacsaArahan9.vue — that's fine).

- [ ] **Step 3: Commit**

```bash
git add web/apps/report-portal/src/stores/nacsa.ts
git commit -m "feat(report-portal): NACSA Pinia store with drill scope"
```

---

## Task 10: NacsaArahan9.vue — full 5-tab dashboard

**Files:**
- Modify: `web/apps/report-portal/src/views/NacsaArahan9.vue`

- [ ] **Step 1: Replace stub with full implementation**

Replace the entire contents of `web/apps/report-portal/src/views/NacsaArahan9.vue` with:

```vue
<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { TCrumbBar, TStatCard, TPill, TDataTable } from '@triton/ui';
import type { Column } from '@triton/ui';
import type { NacsaServerRow, NacsaHostRow, NacsaCBOMRow, NacsaRiskRow, NacsaMigPhase } from '@triton/api-client';
import { useNacsaStore } from '../stores/nacsa';

const nacsa = useNacsaStore();

// ── Tabs ──────────────────────────────────────────────────────────────────────
type TabId = 'summary' | 'inventory' | 'cbom' | 'risk' | 'migration';
const activeTab = ref<TabId>('summary');
const TABS: { id: TabId; label: string }[] = [
  { id: 'summary',   label: 'Summary' },
  { id: 'inventory', label: 'Inventory' },
  { id: 'cbom',      label: 'CBOM' },
  { id: 'risk',      label: 'Risk' },
  { id: 'migration', label: 'Migration' },
];

// ── Breadcrumb ────────────────────────────────────────────────────────────────
const crumbs = computed(() => {
  const items = [{ label: 'All Servers' }];
  if (nacsa.scope.manageServerId) {
    items[0] = { label: 'All Servers', href: '#/nacsa' };
    items.push({ label: nacsa.scope.manageServerName || nacsa.scope.manageServerId });
  }
  if (nacsa.scope.hostname) {
    items[items.length - 1] = {
      label: nacsa.scope.manageServerName || nacsa.scope.manageServerId,
      href: '#/nacsa',
    };
    items.push({ label: nacsa.scope.hostname });
  }
  return items;
});

function resetDrill() {
  nacsa.clearDrill();
  activeTab.value = 'summary';
}

// ── Summary tab ───────────────────────────────────────────────────────────────
const readinessPct = computed(() => nacsa.summary?.readiness_pct ?? 0);
const readinessBar = computed(() => Math.min(readinessPct.value, 100));

// ── Inventory tab ─────────────────────────────────────────────────────────────
const serverCols: Column<NacsaServerRow>[] = [
  { key: 'name',          label: 'Server',       width: '2fr' },
  { key: 'host_count',    label: 'Hosts',        width: '80px', numeric: true },
  { key: 'readiness_pct', label: 'Readiness %',  width: '120px', numeric: true },
  { key: 'last_scan_at',  label: 'Last Scan',    width: '160px' },
];
const hostCols: Column<NacsaHostRow>[] = [
  { key: 'hostname',      label: 'Hostname',     width: '2fr' },
  { key: 'scan_profile',  label: 'Profile',      width: '100px' },
  { key: 'readiness_pct', label: 'Readiness %',  width: '120px', numeric: true },
  { key: 'last_scan_at',  label: 'Last Scan',    width: '160px' },
];

function onServerClick(row: NacsaServerRow) {
  nacsa.drillToServer(row.id, row.name);
  activeTab.value = 'inventory';
  void nacsa.fetchHosts();
}

function onHostClick(row: NacsaHostRow) {
  nacsa.drillToHost(row.hostname);
  activeTab.value = 'cbom';
  void nacsa.fetchCBOM();
  void nacsa.fetchRisk();
}

// ── CBOM tab ──────────────────────────────────────────────────────────────────
const cbomStatusFilters = ref<string[]>([]);
const CBOM_STATUSES = ['UNSAFE', 'DEPRECATED', 'TRANSITIONAL', 'SAFE'];

function toggleCBOMStatus(s: string) {
  const idx = cbomStatusFilters.value.indexOf(s);
  if (idx === -1) cbomStatusFilters.value.push(s);
  else cbomStatusFilters.value.splice(idx, 1);
  void nacsa.fetchCBOM(cbomStatusFilters.value.join(',') || undefined);
}

function cbomStatusClass(status: string): string {
  switch (status) {
    case 'UNSAFE':       return 'status-unsafe';
    case 'DEPRECATED':   return 'status-deprecated';
    case 'TRANSITIONAL': return 'status-transitional';
    default:             return 'status-safe';
  }
}

// ── Risk tab ──────────────────────────────────────────────────────────────────
const riskSort = ref<'score' | 'impact' | 'hostname'>('score');
const expandedRiskRow = ref<string | null>(null);

function setRiskSort(s: typeof riskSort.value) {
  riskSort.value = s;
  void nacsa.fetchRisk(s);
}

function toggleRiskRow(key: string) {
  expandedRiskRow.value = expandedRiskRow.value === key ? null : key;
}

function riskBandClass(band: string): string {
  switch (band) {
    case 'CRITICAL': return 'risk-critical';
    case 'HIGH':     return 'risk-high';
    case 'MEDIUM':   return 'risk-medium';
    default:         return 'risk-low';
  }
}

// ── Migration tab ─────────────────────────────────────────────────────────────
const activeMigPhase = ref<number | null>(null);

function setActivePhase(phase: number) {
  activeMigPhase.value = activeMigPhase.value === phase ? null : phase;
}

function phaseClass(status: NacsaMigPhase['status']): string {
  switch (status) {
    case 'complete':    return 'phase-complete';
    case 'in_progress': return 'phase-active';
    default:            return 'phase-pending';
  }
}

function activityIcon(status: NacsaMigActivity['status']): string {
  if (status === 'done')   return '✓';
  if (status === 'active') return '→';
  return '○';
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────
onMounted(() => {
  void nacsa.fetchSummary();
  void nacsa.fetchServers();
  void nacsa.fetchMigration();
});

watch(activeTab, (tab) => {
  if (tab === 'cbom')      void nacsa.fetchCBOM(cbomStatusFilters.value.join(',') || undefined);
  if (tab === 'risk')      void nacsa.fetchRisk(riskSort.value);
  if (tab === 'migration') void nacsa.fetchMigration();
});

// Shorthand for migration phases
import type { NacsaMigActivity } from '@triton/api-client';
</script>

<template>
  <section class="nacsa-view">
    <!-- Breadcrumb -->
    <TCrumbBar :crumbs="crumbs" @click.prevent="resetDrill" />

    <!-- Tab strip -->
    <nav class="tab-strip">
      <button
        v-for="t in TABS"
        :key="t.id"
        class="tab-btn"
        :class="{ 'is-active': activeTab === t.id }"
        @click="activeTab = t.id"
      >
        {{ t.label }}
      </button>
    </nav>

    <!-- ── SUMMARY TAB ── -->
    <div v-if="activeTab === 'summary'" class="tab-content">
      <!-- Hero readiness bar -->
      <div class="hero-bar panel">
        <div class="hero-left">
          <span class="hero-pct">{{ readinessPct.toFixed(1) }}%</span>
          <span class="hero-label">NACSA Arahan 9 Readiness</span>
        </div>
        <div class="hero-progress">
          <div class="progress-track">
            <div class="progress-fill" :style="{ width: readinessBar + '%' }"></div>
          </div>
          <div class="progress-labels">
            <span>0%</span>
            <span>Target: {{ nacsa.summary?.target_pct ?? 80 }}% by {{ nacsa.summary?.target_year ?? 2030 }}</span>
            <span>100%</span>
          </div>
        </div>
      </div>

      <!-- Stat cards -->
      <div class="stat-row">
        <TStatCard label="Compliant"      :value="nacsa.summary?.compliant    ?? 0" />
        <TStatCard label="Transitional"   :value="nacsa.summary?.transitional  ?? 0" />
        <TStatCard label="Non-Compliant"  :value="nacsa.summary?.non_compliant ?? 0" />
        <TStatCard label="Total Assets"   :value="nacsa.summary?.total_assets  ?? 0" />
      </div>

      <!-- Top blockers -->
      <div class="panel">
        <h2>Top Blockers</h2>
        <div v-if="!nacsa.summary?.top_blockers?.length" class="empty">No unsafe assets found.</div>
        <ul v-else class="blockers">
          <li v-for="b in nacsa.summary.top_blockers" :key="`${b.hostname}|${b.algorithm}`">
            <span class="b-host">{{ b.hostname }}</span>
            <span class="b-algo">{{ b.algorithm }}</span>
            <TPill variant="unsafe">{{ b.severity }}</TPill>
            <span class="b-count">{{ b.asset_count }} assets</span>
          </li>
        </ul>
      </div>

      <!-- Migration mini progress -->
      <div v-if="nacsa.summary?.migration_phases?.length" class="panel">
        <h2>Migration Progress</h2>
        <div class="migration-mini">
          <div
            v-for="p in nacsa.summary.migration_phases"
            :key="p.phase"
            class="mig-row"
          >
            <span class="mig-label" :class="phaseClass(p.status)">Fasa {{ p.phase }}</span>
            <div class="mig-track">
              <div class="mig-fill" :class="phaseClass(p.status)" :style="{ width: p.progress_pct + '%' }"></div>
            </div>
            <span class="mig-pct" :class="phaseClass(p.status)">
              {{ p.status === 'complete' ? '✓' : p.progress_pct + '%' }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- ── INVENTORY TAB ── -->
    <div v-else-if="activeTab === 'inventory'" class="tab-content">
      <!-- Show hosts when drilled into a server -->
      <template v-if="nacsa.scope.manageServerId">
        <h2>Hosts — {{ nacsa.scope.manageServerName || nacsa.scope.manageServerId }}</h2>
        <TDataTable
          :columns="hostCols"
          :rows="nacsa.hosts"
          row-key="hostname"
          empty-text="No hosts found for this server."
          @row-click="onHostClick"
        />
      </template>
      <!-- Show servers otherwise -->
      <template v-else>
        <h2>Manage Servers</h2>
        <TDataTable
          :columns="serverCols"
          :rows="nacsa.servers"
          row-key="id"
          empty-text="No manage servers found. Scans must be relayed via a Manage Server."
          @row-click="onServerClick"
        />
      </template>
    </div>

    <!-- ── CBOM TAB ── -->
    <div v-else-if="activeTab === 'cbom'" class="tab-content">
      <div class="cbom-filters">
        <button
          v-for="s in CBOM_STATUSES"
          :key="s"
          class="filter-chip"
          :class="[cbomStatusClass(s), { 'is-active': cbomStatusFilters.includes(s) }]"
          @click="toggleCBOMStatus(s)"
        >
          {{ s }}
        </button>
      </div>
      <table class="data-table cbom-table">
        <thead>
          <tr>
            <th>Algorithm</th><th>Key Length</th><th>Status</th><th>Assets</th><th>Module</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in nacsa.cbom"
            :key="`${row.algorithm}|${row.pqc_status}|${row.module}`"
            :class="cbomStatusClass(row.pqc_status)"
          >
            <td>{{ row.algorithm }}</td>
            <td>{{ row.key_size ? row.key_size + '-bit' : '—' }}</td>
            <td><span class="status-badge" :class="cbomStatusClass(row.pqc_status)">{{ row.pqc_status }}</span></td>
            <td class="numeric">{{ row.asset_count }}</td>
            <td>{{ row.module }}</td>
          </tr>
          <tr v-if="!nacsa.cbom.length">
            <td colspan="5" class="empty">No crypto assets found for this scope.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ── RISK TAB ── -->
    <div v-else-if="activeTab === 'risk'" class="tab-content">
      <div class="sort-bar">
        <span>Sort:</span>
        <button v-for="s in (['score','impact','hostname'] as const)" :key="s"
          class="sort-btn" :class="{ 'is-active': riskSort === s }"
          @click="setRiskSort(s)"
        >{{ s }} {{ riskSort === s ? '↓' : '' }}</button>
      </div>
      <table class="data-table risk-table">
        <thead>
          <tr>
            <th>Algorithm</th><th>System</th><th>Impact</th><th>Likelihood</th><th>Score</th><th>Band</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="row in nacsa.risk" :key="`${row.algorithm}|${row.hostname}`">
            <tr
              :class="riskBandClass(row.risk_band)"
              style="cursor:pointer"
              @click="toggleRiskRow(`${row.algorithm}|${row.hostname}`)"
            >
              <td>{{ row.algorithm }}</td>
              <td>{{ row.hostname }}</td>
              <td class="numeric">{{ row.impact }}</td>
              <td class="numeric">{{ row.likelihood }}</td>
              <td class="numeric score-cell">{{ row.score }}</td>
              <td><span class="risk-badge" :class="riskBandClass(row.risk_band)">{{ row.risk_band }}</span></td>
            </tr>
            <tr v-if="expandedRiskRow === `${row.algorithm}|${row.hostname}`" class="expand-row">
              <td colspan="6">
                <div class="expand-detail">
                  <strong>Assets:</strong> {{ row.asset_count }}&emsp;
                  <strong>Score:</strong> Impact ({{ row.impact }}) × Likelihood ({{ row.likelihood }}) = {{ row.score }}
                </div>
              </td>
            </tr>
          </template>
          <tr v-if="!nacsa.risk.length">
            <td colspan="6" class="empty">No risk items in this scope.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ── MIGRATION TAB ── -->
    <div v-else-if="activeTab === 'migration'" class="tab-content">
      <div v-if="!nacsa.migration?.phases.length" class="empty panel">
        No migration data configured. An admin can add phase data via the API.
      </div>
      <template v-else>
        <!-- Gantt bars -->
        <div class="gantt">
          <div
            v-for="p in nacsa.migration.phases"
            :key="p.phase"
            class="gantt-row"
            :class="{ 'is-active': activeMigPhase === p.phase }"
            @click="setActivePhase(p.phase)"
          >
            <span class="gantt-label" :class="phaseClass(p.status)">Fasa {{ p.phase }}</span>
            <div class="gantt-track">
              <div class="gantt-fill" :class="phaseClass(p.status)" :style="{ width: p.progress_pct + '%' }"></div>
            </div>
            <span class="gantt-pct" :class="phaseClass(p.status)">
              {{ p.status === 'complete' ? '✓ 100%' : p.progress_pct + '%' }}
            </span>
          </div>
        </div>

        <!-- Active phase detail -->
        <div
          v-for="p in nacsa.migration.phases"
          v-show="activeMigPhase === p.phase"
          :key="`detail-${p.phase}`"
          class="phase-detail panel"
        >
          <div class="phase-detail-head">
            <span class="phase-detail-title" :class="phaseClass(p.status)">
              Fasa {{ p.phase }} — {{ p.name }}
            </span>
            <span class="phase-detail-period">{{ p.period }}</span>
          </div>
          <ul class="activity-list">
            <li v-for="a in p.activities" :key="a.name" class="activity-row">
              <span class="act-icon" :class="a.status">{{ activityIcon(a.status) }}</span>
              <span class="act-name">{{ a.name }}</span>
              <span class="act-budget">RM {{ (a.budget_rm / 1_000_000).toFixed(1) }}M</span>
            </li>
          </ul>
          <div v-if="p.budget_total_rm > 0" class="budget-chips">
            <div class="budget-chip">
              <span class="chip-val">RM {{ (p.budget_total_rm / 1_000_000).toFixed(1) }}M</span>
              <span class="chip-lbl">Budget</span>
            </div>
            <div class="budget-chip spent">
              <span class="chip-val">RM {{ (p.budget_spent_rm / 1_000_000).toFixed(1) }}M</span>
              <span class="chip-lbl">Spent</span>
            </div>
            <div class="budget-chip remaining">
              <span class="chip-val">RM {{ ((p.budget_total_rm - p.budget_spent_rm) / 1_000_000).toFixed(1) }}M</span>
              <span class="chip-lbl">Remaining</span>
            </div>
          </div>
        </div>
      </template>
    </div>
  </section>
</template>

<style scoped>
.nacsa-view { display: flex; flex-direction: column; gap: var(--space-4); padding: var(--space-4); }

/* Tab strip */
.tab-strip { display: flex; gap: 2px; border-bottom: 1px solid var(--border); }
.tab-btn {
  padding: var(--space-2) var(--space-4);
  background: none; border: none; border-bottom: 2px solid transparent;
  color: var(--text-muted); cursor: pointer; font-size: 0.85rem;
  transition: color 0.15s, border-color 0.15s;
}
.tab-btn.is-active { color: var(--accent-strong); border-bottom-color: var(--accent-strong); }
.tab-btn:hover:not(.is-active) { color: var(--text-secondary); }

.tab-content { display: flex; flex-direction: column; gap: var(--space-4); }

/* Panel */
.panel {
  background: var(--bg-surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: var(--space-4);
}
.panel h2 { font-size: 0.9rem; font-weight: 500; margin: 0 0 var(--space-3); }
.empty { color: var(--text-muted); font-size: 0.8rem; text-align: center; padding: var(--space-4); }

/* Hero bar */
.hero-bar { display: flex; align-items: center; gap: var(--space-6); }
.hero-left { display: flex; flex-direction: column; align-items: center; min-width: 80px; }
.hero-pct { font-family: var(--font-display); font-size: 2.2rem; font-weight: 700; color: var(--color-safe, #4ade80); }
.hero-label { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-subtle); margin-top: 2px; }
.hero-progress { flex: 1; }
.progress-track { background: var(--bg-elevated); border-radius: 4px; height: 10px; margin-bottom: var(--space-1); }
.progress-fill { background: linear-gradient(90deg, #4ade80, #22c55e); height: 100%; border-radius: 4px; transition: width 0.4s; }
.progress-labels { display: flex; justify-content: space-between; font-size: 0.65rem; color: var(--text-subtle); }

/* Stat row */
.stat-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-3); }

/* Blockers */
.blockers { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: var(--space-2); }
.blockers li { display: flex; align-items: center; gap: var(--space-3); padding: var(--space-2); background: var(--bg-elevated); border-radius: var(--radius-sm); font-size: 0.78rem; }
.b-host { font-weight: 500; flex: 1; }
.b-algo { color: var(--text-secondary); }
.b-count { color: var(--text-muted); font-size: 0.72rem; }

/* Migration mini */
.migration-mini { display: flex; flex-direction: column; gap: var(--space-2); }
.mig-row { display: flex; align-items: center; gap: var(--space-3); }
.mig-label { font-size: 0.78rem; width: 48px; }
.mig-track { flex: 1; background: var(--bg-elevated); border-radius: 3px; height: 8px; }
.mig-fill { height: 100%; border-radius: 3px; transition: width 0.4s; }
.mig-pct { font-size: 0.72rem; width: 40px; text-align: right; }

/* Phase colours */
.phase-complete { color: var(--color-safe, #4ade80); }
.phase-active   { color: var(--color-transitional, #f97316); }
.phase-pending  { color: var(--text-muted); }
.mig-fill.phase-complete { background: #4ade80; }
.mig-fill.phase-active   { background: #f97316; }
.mig-fill.phase-pending  { background: var(--bg-elevated); }

/* CBOM filters */
.cbom-filters { display: flex; gap: var(--space-2); flex-wrap: wrap; }
.filter-chip {
  padding: var(--space-1) var(--space-3); border-radius: var(--radius); font-size: 0.75rem;
  border: 1px solid currentColor; cursor: pointer; opacity: 0.5; transition: opacity 0.15s;
  background: none;
}
.filter-chip.is-active { opacity: 1; }
.status-unsafe       { color: var(--color-unsafe, #ef4444); }
.status-deprecated   { color: var(--color-deprecated, #a78bfa); }
.status-transitional { color: var(--color-transitional, #f97316); }
.status-safe         { color: var(--color-safe, #4ade80); }

/* Tables */
.data-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
.data-table th { text-align: left; padding: var(--space-2) var(--space-3); color: var(--text-subtle); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
.data-table td { padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--border-subtle, var(--border)); }
.data-table tr:hover td { background: var(--bg-elevated); }
.numeric { text-align: right; font-variant-numeric: tabular-nums; }
.status-badge, .risk-badge {
  display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.68rem; font-weight: 600;
}

/* CBOM row borders */
.cbom-table tr.status-unsafe   td:first-child { border-left: 3px solid #ef4444; }
.cbom-table tr.status-deprecated td:first-child { border-left: 3px solid #a78bfa; }
.cbom-table tr.status-transitional td:first-child { border-left: 3px solid #f97316; }
.cbom-table tr.status-safe td:first-child { border-left: 3px solid #4ade80; }

/* Risk */
.sort-bar { display: flex; align-items: center; gap: var(--space-2); }
.sort-bar span { font-size: 0.75rem; color: var(--text-muted); }
.sort-btn {
  padding: var(--space-1) var(--space-3); font-size: 0.75rem; border-radius: var(--radius);
  border: 1px solid var(--border); background: none; cursor: pointer; color: var(--text-secondary);
}
.sort-btn.is-active { background: var(--accent-strong); color: #fff; border-color: var(--accent-strong); }
.risk-critical { color: #ef4444; } .risk-high { color: #f97316; } .risk-medium { color: #60a5fa; } .risk-low { color: #4ade80; }
.risk-table tr.risk-critical td:first-child { border-left: 3px solid #ef4444; }
.risk-table tr.risk-high td:first-child { border-left: 3px solid #f97316; }
.risk-table tr.risk-medium td:first-child { border-left: 3px solid #60a5fa; }
.risk-table tr.risk-low td:first-child { border-left: 3px solid #4ade80; }
.score-cell { font-weight: 700; }
.expand-row td { background: var(--bg-elevated); }
.expand-detail { font-size: 0.78rem; color: var(--text-secondary); padding: var(--space-2) 0; }

/* Gantt */
.gantt { display: flex; flex-direction: column; gap: var(--space-3); padding: var(--space-4); background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius); }
.gantt-row { display: flex; align-items: center; gap: var(--space-4); cursor: pointer; }
.gantt-row.is-active { font-weight: 600; }
.gantt-label { font-size: 0.8rem; width: 52px; }
.gantt-track { flex: 1; background: var(--bg-elevated); border-radius: 3px; height: 10px; }
.gantt-fill { height: 100%; border-radius: 3px; transition: width 0.4s; }
.gantt-fill.phase-complete { background: #4ade80; }
.gantt-fill.phase-active   { background: #f97316; }
.gantt-pct { font-size: 0.75rem; width: 56px; text-align: right; }

/* Phase detail */
.phase-detail-head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: var(--space-3); }
.phase-detail-title { font-size: 0.9rem; font-weight: 600; }
.phase-detail-period { font-size: 0.75rem; color: var(--text-muted); }
.activity-list { list-style: none; padding: 0; margin: 0 0 var(--space-4); display: flex; flex-direction: column; gap: var(--space-2); }
.activity-row { display: flex; align-items: center; gap: var(--space-3); font-size: 0.8rem; }
.act-icon { width: 16px; font-weight: 700; }
.act-icon.done   { color: #4ade80; }
.act-icon.active { color: #f97316; }
.act-icon.pending { color: var(--text-muted); }
.act-name { flex: 1; }
.act-budget { color: var(--text-subtle); font-size: 0.75rem; }
.budget-chips { display: flex; gap: var(--space-3); }
.budget-chip { text-align: center; }
.chip-val { display: block; font-family: var(--font-display); font-weight: 600; font-size: 1rem; color: var(--text-primary); }
.chip-lbl { display: block; font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); }
.budget-chip.spent .chip-val     { color: #4ade80; }
.budget-chip.remaining .chip-val { color: #f97316; }
</style>
```

- [ ] **Step 2: Build and check for TypeScript errors**

```bash
cd /path/to/triton/web && pnpm --filter report-portal build 2>&1 | head -60
```

Expected: Build succeeds. Fix any type errors by adjusting the import for `NacsaMigActivity` — it should already be exported from `@triton/api-client` after Task 8.

- [ ] **Step 3: Run unit tests**

```bash
cd /path/to/triton/web && pnpm test 2>&1 | tail -20
```

Expected: PASS (existing tests unaffected; no new tests for the view since it's UI-only).

- [ ] **Step 4: Rebuild and embed dist**

```bash
cd /path/to/triton/web && pnpm build
```

Then verify the dist output is updated:

```bash
ls /path/to/triton/pkg/server/ui/dist/ -la
```

Expected: `index.html`, `assets/` present with recent timestamps.

- [ ] **Step 5: Build the Go server to confirm embed compiles**

```bash
cd /path/to/triton && go build ./cmd/triton-server/... 2>/dev/null || go build ./... 2>&1 | grep -v "^#" | head -20
```

Expected: No compile errors.

- [ ] **Step 6: Commit**

```bash
git add web/apps/report-portal/src/views/NacsaArahan9.vue \
        web/apps/report-portal/src/stores/nacsa.ts \
        pkg/server/ui/dist/
git commit -m "feat(report-portal): NACSA Arahan 9 5-tab dashboard"
```

---

## Post-Implementation Checklist

- [ ] Run the full unit test suite: `make test`
- [ ] Run integration tests: `make test-integration`
- [ ] Manually test: start server with `make run`, log in, navigate to `#/nacsa`, verify the page loads without console errors
- [ ] Verify Inventory tab shows "No manage servers found" when no relay has pushed scans
- [ ] Verify CBOM and Risk tabs show "No data" states when hostname is not drilled into
- [ ] Verify Migration tab shows "No migration data configured" when no phases exist
