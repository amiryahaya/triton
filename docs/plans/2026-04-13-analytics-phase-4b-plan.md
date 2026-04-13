# Analytics Phase 4B: Remediation & Exception Management — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add finding lifecycle tracking (open → in-progress → resolved → accepted-risk) with audit trail, auto-reopen on reappearance, and a remediation tracker UI — so management can track migration progress and readiness % reflects what's actually been fixed.

**Architecture:** An append-only `finding_status` table keyed by `finding_key` (SHA256 of org+host+algo+keysize+module) tracks status changes across scans. The T2 pipeline transform LEFT JOINs this table to exclude resolved/accepted findings from readiness counts. Auto-reopen inserts a new "open" row when a resolved finding reappears in a new scan. New API handlers expose status mutations (org_admin only) and reads. A remediation tracker UI view provides action dropdowns and an accept-risk modal.

**Tech Stack:** Go 1.25, pgx/v5, crypto/sha256, vanilla JS, testify

**Spec:** `docs/plans/2026-04-13-analytics-phase-4b-design.md`

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `pkg/store/migrations.go` | Modify | v13: finding_status table; v14: host_summary + org_snapshot gain resolved/accepted counts |
| `pkg/store/types.go` | Modify | FindingStatusEntry, RemediationRow, RemediationSummary types |
| `pkg/store/store.go` | Modify | Add remediation methods to Store interface |
| `pkg/store/remediation.go` | Create | ComputeFindingKey, SetFindingStatus, GetFindingHistory, GetRemediationSummary, ListRemediationFindings |
| `pkg/store/remediation_test.go` | Create | Unit test for ComputeFindingKey |
| `pkg/store/host_summary.go` | Modify | T2: LEFT JOIN finding_status, auto-reopen, resolved/accepted counts |
| `pkg/server/handlers_remediation.go` | Create | All remediation HTTP handlers |
| `pkg/server/server.go` | Modify | Wire remediation routes |
| `pkg/server/ui/dist/views/remediation.js` | Create | Remediation tracker view |
| `pkg/server/ui/dist/index.html` | Modify | Nav link + script tag |
| `pkg/server/ui/dist/style.css` | Modify | Status badges, action dropdown, modal |

---

### Task 1: Database migrations — finding_status table + host_summary columns

**Files:**
- Modify: `pkg/store/migrations.go`

- [ ] **Step 1: Add migration v13 (finding_status table)**

Append to the `migrations` slice in `pkg/store/migrations.go`:

```go
	// Version 13: Remediation tracking — append-only finding_status table.
	// Current status = latest row per finding_key by changed_at DESC.
	// finding_key = SHA256(org_id || hostname || algorithm || key_size || module).
	// Analytics Phase 4B.
	`CREATE TABLE IF NOT EXISTS finding_status (
		id          BIGSERIAL PRIMARY KEY,
		finding_key TEXT NOT NULL,
		org_id      UUID NOT NULL,
		status      TEXT NOT NULL CHECK (status IN ('open','in_progress','resolved','accepted')),
		reason      TEXT NOT NULL DEFAULT '',
		changed_by  TEXT NOT NULL,
		changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at  TIMESTAMPTZ
	);

	CREATE INDEX IF NOT EXISTS idx_finding_status_key ON finding_status(finding_key, changed_at DESC);
	CREATE INDEX IF NOT EXISTS idx_finding_status_org ON finding_status(org_id);`,
```

- [ ] **Step 2: Add migration v14 (resolved/accepted counts on host_summary + org_snapshot)**

Append another entry:

```go
	// Version 14: Add resolved_count and accepted_count to host_summary
	// and org_snapshot so the UI can show remediation progress without
	// re-querying the finding_status table. Analytics Phase 4B.
	`ALTER TABLE host_summary ADD COLUMN IF NOT EXISTS resolved_count INT NOT NULL DEFAULT 0;
	ALTER TABLE host_summary ADD COLUMN IF NOT EXISTS accepted_count INT NOT NULL DEFAULT 0;
	ALTER TABLE org_snapshot ADD COLUMN IF NOT EXISTS resolved_count INT NOT NULL DEFAULT 0;
	ALTER TABLE org_snapshot ADD COLUMN IF NOT EXISTS accepted_count INT NOT NULL DEFAULT 0;`,
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./pkg/store/...`

- [ ] **Step 4: Commit**

```bash
git add pkg/store/migrations.go
git commit -m "feat(store): add finding_status table + remediation count columns (v13-v14)

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Types — FindingStatusEntry, RemediationRow, RemediationSummary

**Files:**
- Modify: `pkg/store/types.go`

- [ ] **Step 1: Add types**

Append to `pkg/store/types.go`:

```go
// FindingStatusEntry is one row from the finding_status table.
// Analytics Phase 4B.
type FindingStatusEntry struct {
	ID         int64      `json:"id"`
	FindingKey string     `json:"findingKey"`
	OrgID      string     `json:"orgId"`
	Status     string     `json:"status"`
	Reason     string     `json:"reason"`
	ChangedBy  string     `json:"changedBy"`
	ChangedAt  time.Time  `json:"changedAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

// RemediationRow is one finding enriched with its current remediation
// status, returned by GET /api/v1/remediation. Analytics Phase 4B.
type RemediationRow struct {
	FindingID  string     `json:"findingId"`
	Hostname   string     `json:"hostname"`
	Algorithm  string     `json:"algorithm"`
	KeySize    int        `json:"keySize,omitempty"`
	PQCStatus  string     `json:"pqcStatus"`
	Module     string     `json:"module"`
	Priority   int        `json:"priority"`
	Status     string     `json:"status"`     // open|in_progress|resolved|accepted
	ChangedAt  *time.Time `json:"changedAt"`  // nil if never changed (default open)
	ChangedBy  string     `json:"changedBy"`
	FindingKey string     `json:"findingKey"`
}

// RemediationSummary is the response for GET /api/v1/remediation/summary.
// Analytics Phase 4B.
type RemediationSummary struct {
	Open       int `json:"open"`
	InProgress int `json:"inProgress"`
	Resolved   int `json:"resolved"`
	Accepted   int `json:"accepted"`
	Total      int `json:"total"`
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./pkg/store/...`

- [ ] **Step 3: Commit**

```bash
git add pkg/store/types.go
git commit -m "feat(store): add FindingStatusEntry, RemediationRow, RemediationSummary types

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Store interface + ComputeFindingKey + remediation store methods

**Files:**
- Modify: `pkg/store/store.go`
- Create: `pkg/store/remediation.go`
- Create: `pkg/store/remediation_test.go`

- [ ] **Step 1: Add methods to Store interface**

In `pkg/store/store.go`, add after the Analytics Pipeline section:

```go
	// --- Remediation (Phase 4B) ---

	// SetFindingStatus inserts a new status row for the given finding_key.
	SetFindingStatus(ctx context.Context, entry *FindingStatusEntry) error

	// GetFindingHistory returns all status changes for a finding_key,
	// sorted by changed_at DESC (newest first).
	GetFindingHistory(ctx context.Context, findingKey string) ([]FindingStatusEntry, error)

	// GetRemediationSummary returns counts by status for the given org,
	// based on the latest status per finding_key.
	GetRemediationSummary(ctx context.Context, orgID string) (*RemediationSummary, error)

	// ListRemediationFindings returns findings from the latest scan per
	// host, enriched with their current remediation status. Filterable
	// by status, hostname, and pqc_status.
	ListRemediationFindings(ctx context.Context, orgID string, statusFilter, hostnameFilter, pqcFilter string) ([]RemediationRow, error)

	// GetFindingByID returns a single finding by its ID, scoped to org.
	GetFindingByID(ctx context.Context, findingID, orgID string) (*Finding, error)
```

- [ ] **Step 2: Write unit test for ComputeFindingKey**

Create `pkg/store/remediation_test.go`:

```go
package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeFindingKey_Deterministic(t *testing.T) {
	key1 := ComputeFindingKey("org-1", "web-srv1", "RSA", 2048, "certificate")
	key2 := ComputeFindingKey("org-1", "web-srv1", "RSA", 2048, "certificate")
	assert.Equal(t, key1, key2, "same inputs must produce same key")
	assert.Len(t, key1, 64, "SHA-256 hex = 64 chars")
}

func TestComputeFindingKey_DifferentInputs(t *testing.T) {
	key1 := ComputeFindingKey("org-1", "web-srv1", "RSA", 2048, "certificate")
	key2 := ComputeFindingKey("org-1", "web-srv1", "RSA", 4096, "certificate")
	key3 := ComputeFindingKey("org-1", "db-main", "RSA", 2048, "certificate")
	assert.NotEqual(t, key1, key2, "different key_size must produce different key")
	assert.NotEqual(t, key1, key3, "different hostname must produce different key")
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test -v -run TestComputeFindingKey ./pkg/store/`
Expected: FAIL — ComputeFindingKey not defined

- [ ] **Step 4: Create remediation.go with ComputeFindingKey + stubs**

Create `pkg/store/remediation.go`:

```go
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// ComputeFindingKey produces a stable identifier for a crypto finding
// across scans. The key is a hex-encoded SHA-256 hash of the
// concatenation of org_id, hostname, algorithm, key_size, and module.
// Analytics Phase 4B.
func ComputeFindingKey(orgID, hostname, algorithm string, keySize int, module string) string {
	data := orgID + hostname + algorithm + strconv.Itoa(keySize) + module
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func (s *PostgresStore) SetFindingStatus(ctx context.Context, entry *FindingStatusEntry) error {
	return fmt.Errorf("not implemented")
}

func (s *PostgresStore) GetFindingHistory(ctx context.Context, findingKey string) ([]FindingStatusEntry, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *PostgresStore) GetRemediationSummary(ctx context.Context, orgID string) (*RemediationSummary, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *PostgresStore) ListRemediationFindings(ctx context.Context, orgID string, statusFilter, hostnameFilter, pqcFilter string) ([]RemediationRow, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *PostgresStore) GetFindingByID(ctx context.Context, findingID, orgID string) (*Finding, error) {
	return nil, fmt.Errorf("not implemented")
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -v -run TestComputeFindingKey ./pkg/store/`
Expected: PASS

Run: `go build ./...`
Expected: PASS (stubs satisfy the interface)

- [ ] **Step 6: Commit**

```bash
git add pkg/store/store.go pkg/store/remediation.go pkg/store/remediation_test.go
git commit -m "feat(store): add remediation Store methods + ComputeFindingKey

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Implement remediation store methods

**Files:**
- Modify: `pkg/store/remediation.go`

- [ ] **Step 1: Implement SetFindingStatus**

Replace the stub. INSERT a new row into finding_status:

```go
func (s *PostgresStore) SetFindingStatus(ctx context.Context, entry *FindingStatusEntry) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO finding_status (finding_key, org_id, status, reason, changed_by, changed_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.FindingKey, entry.OrgID, entry.Status, entry.Reason, entry.ChangedBy, entry.ChangedAt, entry.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("SetFindingStatus: %w", err)
	}
	return nil
}
```

- [ ] **Step 2: Implement GetFindingHistory**

```go
func (s *PostgresStore) GetFindingHistory(ctx context.Context, findingKey string) ([]FindingStatusEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, finding_key, org_id, status, reason, changed_by, changed_at, expires_at
		 FROM finding_status
		 WHERE finding_key = $1
		 ORDER BY changed_at DESC`,
		findingKey,
	)
	if err != nil {
		return nil, fmt.Errorf("GetFindingHistory: %w", err)
	}
	defer rows.Close()

	result := []FindingStatusEntry{}
	for rows.Next() {
		var e FindingStatusEntry
		if err := rows.Scan(&e.ID, &e.FindingKey, &e.OrgID, &e.Status, &e.Reason, &e.ChangedBy, &e.ChangedAt, &e.ExpiresAt); err != nil {
			return nil, fmt.Errorf("GetFindingHistory scan: %w", err)
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
```

- [ ] **Step 3: Implement GetRemediationSummary**

Uses a CTE to get the latest status per finding_key, then counts by status:

```go
func (s *PostgresStore) GetRemediationSummary(ctx context.Context, orgID string) (*RemediationSummary, error) {
	// Latest scan per host, then get all findings from those scans,
	// LEFT JOIN latest status per finding_key.
	var summary RemediationSummary
	err := s.pool.QueryRow(ctx,
		`WITH latest_scans AS (
			SELECT DISTINCT ON (hostname) id FROM scans
			WHERE org_id = $1 ORDER BY hostname, timestamp DESC
		),
		current_findings AS (
			SELECT f.org_id, f.hostname, f.algorithm, f.key_size, f.module
			FROM findings f
			JOIN latest_scans ls ON f.scan_id = ls.id
		),
		latest_status AS (
			SELECT DISTINCT ON (finding_key) finding_key, status, expires_at
			FROM finding_status WHERE org_id = $1
			ORDER BY finding_key, changed_at DESC
		)
		SELECT
			COUNT(*) FILTER (WHERE COALESCE(ls.status, 'open') = 'open'
				OR (ls.status = 'accepted' AND ls.expires_at IS NOT NULL AND ls.expires_at < NOW())) AS open_count,
			COUNT(*) FILTER (WHERE ls.status = 'in_progress') AS in_progress,
			COUNT(*) FILTER (WHERE ls.status = 'resolved') AS resolved,
			COUNT(*) FILTER (WHERE ls.status = 'accepted'
				AND (ls.expires_at IS NULL OR ls.expires_at >= NOW())) AS accepted,
			COUNT(*) AS total
		FROM current_findings cf
		LEFT JOIN latest_status ls ON ls.finding_key =
			encode(sha256((cf.org_id::text || cf.hostname || cf.algorithm || cf.key_size::text || cf.module)::bytea), 'hex')`,
		orgID,
	).Scan(&summary.Open, &summary.InProgress, &summary.Resolved, &summary.Accepted, &summary.Total)
	if err != nil {
		return nil, fmt.Errorf("GetRemediationSummary: %w", err)
	}
	return &summary, nil
}
```

- [ ] **Step 4: Implement ListRemediationFindings**

Returns findings from latest scan per host, enriched with current status. Apply optional filters.

```go
func (s *PostgresStore) ListRemediationFindings(ctx context.Context, orgID string, statusFilter, hostnameFilter, pqcFilter string) ([]RemediationRow, error) {
	query := `WITH latest_scans AS (
		SELECT DISTINCT ON (hostname) id FROM scans
		WHERE org_id = $1 ORDER BY hostname, timestamp DESC
	),
	latest_status AS (
		SELECT DISTINCT ON (finding_key) finding_key, status, changed_at, changed_by, expires_at
		FROM finding_status WHERE org_id = $1
		ORDER BY finding_key, changed_at DESC
	)
	SELECT f.id, f.hostname, f.algorithm, f.key_size, f.pqc_status, f.module,
		f.migration_priority,
		COALESCE(ls.status, 'open') AS current_status,
		ls.changed_at, COALESCE(ls.changed_by, ''),
		COALESCE(encode(sha256((f.org_id::text || f.hostname || f.algorithm || f.key_size::text || f.module)::bytea), 'hex'), '') AS finding_key
	FROM findings f
	JOIN latest_scans lsc ON f.scan_id = lsc.id
	LEFT JOIN latest_status ls ON ls.finding_key =
		encode(sha256((f.org_id::text || f.hostname || f.algorithm || f.key_size::text || f.module)::bytea), 'hex')
	WHERE 1=1`

	args := []any{orgID}
	argIdx := 2

	if statusFilter != "" {
		if statusFilter == "open" {
			query += fmt.Sprintf(` AND (COALESCE(ls.status, 'open') = 'open' OR (ls.status = 'accepted' AND ls.expires_at IS NOT NULL AND ls.expires_at < NOW()))`)
		} else {
			query += fmt.Sprintf(` AND ls.status = $%d`, argIdx)
			args = append(args, statusFilter)
			argIdx++
		}
	}
	if hostnameFilter != "" {
		query += fmt.Sprintf(` AND f.hostname = $%d`, argIdx)
		args = append(args, hostnameFilter)
		argIdx++
	}
	if pqcFilter != "" {
		query += fmt.Sprintf(` AND f.pqc_status = $%d`, argIdx)
		args = append(args, pqcFilter)
		argIdx++
	}

	query += ` ORDER BY f.migration_priority DESC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ListRemediationFindings: %w", err)
	}
	defer rows.Close()

	result := []RemediationRow{}
	for rows.Next() {
		var r RemediationRow
		if err := rows.Scan(&r.FindingID, &r.Hostname, &r.Algorithm, &r.KeySize,
			&r.PQCStatus, &r.Module, &r.Priority, &r.Status,
			&r.ChangedAt, &r.ChangedBy, &r.FindingKey); err != nil {
			return nil, fmt.Errorf("ListRemediationFindings scan: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
```

- [ ] **Step 5: Implement GetFindingByID**

```go
func (s *PostgresStore) GetFindingByID(ctx context.Context, findingID, orgID string) (*Finding, error) {
	var f Finding
	err := s.pool.QueryRow(ctx,
		`SELECT id, scan_id, org_id, hostname, finding_index, module, file_path,
			algorithm, key_size, pqc_status, migration_priority, not_after,
			subject, issuer, reachability, created_at, image_ref, image_digest
		 FROM findings
		 WHERE id = $1 AND org_id = $2`,
		findingID, orgID,
	).Scan(&f.ID, &f.ScanID, &f.OrgID, &f.Hostname, &f.FindingIndex, &f.Module, &f.FilePath,
		&f.Algorithm, &f.KeySize, &f.PQCStatus, &f.MigrationPriority, &f.NotAfter,
		&f.Subject, &f.Issuer, &f.Reachability, &f.CreatedAt, &f.ImageRef, &f.ImageDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "finding", ID: findingID}
	}
	if err != nil {
		return nil, fmt.Errorf("GetFindingByID: %w", err)
	}
	return &f, nil
}
```

Add `"errors"` and `"github.com/jackc/pgx/v5"` to the imports at the top of `remediation.go`.

- [ ] **Step 6: Verify compilation**

Run: `go build ./...`

- [ ] **Step 7: Commit**

```bash
git add pkg/store/remediation.go
git commit -m "feat(store): implement remediation store methods (SetFindingStatus, history, summary, list)

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Modify T2 (RefreshHostSummary) for remediation

**Files:**
- Modify: `pkg/store/host_summary.go`

- [ ] **Step 1: Modify the findings-count query (Step 2 in RefreshHostSummary)**

Replace the simple `SELECT pqc_status, COUNT(*)` query with the remediation-aware version that LEFT JOINs `finding_status`:

```go
	// Step 2: count findings by pqc_status, excluding resolved/accepted.
	// LEFT JOIN the latest status per finding_key to determine which
	// findings are active (count toward readiness).
	counts := map[string]int{}
	rows, err := tx.Query(ctx,
		`WITH latest_status AS (
			SELECT DISTINCT ON (finding_key) finding_key, status, expires_at
			FROM finding_status
			WHERE org_id = $1
			ORDER BY finding_key, changed_at DESC
		)
		SELECT f.pqc_status, COUNT(*)
		FROM findings f
		LEFT JOIN latest_status ls ON ls.finding_key =
			encode(sha256(
				(f.org_id::text || f.hostname || f.algorithm || f.key_size::text || f.module)::bytea
			), 'hex')
		WHERE f.scan_id = $2
			AND (ls.status IS NULL
				OR ls.status IN ('open', 'in_progress')
				OR (ls.status = 'accepted' AND ls.expires_at IS NOT NULL AND ls.expires_at < NOW()))
		GROUP BY f.pqc_status`,
		orgID, scanID,
	)
```

- [ ] **Step 2: Add resolved/accepted count queries**

After the status counts, add queries to count resolved and accepted findings for the host_summary columns:

```go
	// Count resolved and accepted findings for this host.
	var resolvedCount, acceptedCount int
	err = tx.QueryRow(ctx,
		`WITH latest_status AS (
			SELECT DISTINCT ON (finding_key) finding_key, status, expires_at
			FROM finding_status
			WHERE org_id = $1
			ORDER BY finding_key, changed_at DESC
		)
		SELECT
			COUNT(*) FILTER (WHERE ls.status = 'resolved'),
			COUNT(*) FILTER (WHERE ls.status = 'accepted'
				AND (ls.expires_at IS NULL OR ls.expires_at >= NOW()))
		FROM findings f
		JOIN latest_status ls ON ls.finding_key =
			encode(sha256(
				(f.org_id::text || f.hostname || f.algorithm || f.key_size::text || f.module)::bytea
			), 'hex')
		WHERE f.scan_id = $2`,
		orgID, scanID,
	).Scan(&resolvedCount, &acceptedCount)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary remediation counts: %w", err)
	}
```

- [ ] **Step 3: Add auto-reopen logic**

After the counts and before the UPSERT, add auto-reopen for resolved findings that reappeared:

```go
	// Auto-reopen: resolved findings that reappeared in the latest scan
	// get reverted to 'open'. Accepted findings are NOT reopened.
	_, err = tx.Exec(ctx,
		`WITH scan_keys AS (
			SELECT DISTINCT encode(sha256(
				(f.org_id::text || f.hostname || f.algorithm || f.key_size::text || f.module)::bytea
			), 'hex') AS fkey
			FROM findings f WHERE f.scan_id = $1
		),
		resolved_keys AS (
			SELECT DISTINCT ON (finding_key) finding_key, status
			FROM finding_status WHERE org_id = $2
			ORDER BY finding_key, changed_at DESC
		)
		INSERT INTO finding_status (finding_key, org_id, status, reason, changed_by, changed_at)
		SELECT rk.finding_key, $2, 'open', 'finding reappeared in scan', 'system', NOW()
		FROM resolved_keys rk
		JOIN scan_keys sk ON rk.finding_key = sk.fkey
		WHERE rk.status = 'resolved'`,
		scanID, orgID,
	)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary auto-reopen: %w", err)
	}
```

- [ ] **Step 4: Update the UPSERT to include resolved_count and accepted_count**

Find the existing `INSERT INTO host_summary` UPSERT and add `resolved_count` and `accepted_count` to both the INSERT column list and the ON CONFLICT UPDATE SET clause. Add the Go variables `resolvedCount` and `acceptedCount` to the parameter list.

- [ ] **Step 5: Update the sparkline query**

The sparkline query (building monthly readiness) should also exclude resolved/accepted findings. Apply the same LEFT JOIN + WHERE filter pattern to the sparkline CTE.

- [ ] **Step 6: Verify compilation**

Run: `go build ./...`

- [ ] **Step 7: Commit**

```bash
git add pkg/store/host_summary.go
git commit -m "feat(store): T2 remediation integration — exclude resolved/accepted from readiness, auto-reopen

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Update T3 (RefreshOrgSnapshot) for remediation counts

**Files:**
- Modify: `pkg/store/org_snapshot.go`

- [ ] **Step 1: Read resolved_count and accepted_count from host_summary**

In RefreshOrgSnapshot, add `resolved_count` and `accepted_count` to the host_summary SELECT query (Step 1).

- [ ] **Step 2: Sum remediation counts in the aggregation loop**

Add `resolvedTotal` and `acceptedTotal` variables, sum them across all hosts alongside the existing totals.

- [ ] **Step 3: Add to the UPSERT**

Add `resolved_count` and `accepted_count` to the org_snapshot UPSERT (both INSERT and ON CONFLICT SET).

- [ ] **Step 4: Verify compilation**

Run: `go build ./...`

- [ ] **Step 5: Commit**

```bash
git add pkg/store/org_snapshot.go
git commit -m "feat(store): T3 aggregates resolved_count + accepted_count from host_summary

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: API handlers — remediation endpoints

**Files:**
- Create: `pkg/server/handlers_remediation.go`
- Modify: `pkg/server/server.go`

- [ ] **Step 1: Create handlers_remediation.go**

```go
package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/store"
)

// POST /api/v1/findings/{id}/status
func (s *Server) handleSetFindingStatus(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	orgID := TenantFromContext(r.Context())
	userID := UserIDFromContext(r.Context())

	var req struct {
		Status    string  `json:"status"`
		Reason    string  `json:"reason"`
		ExpiresAt *string `json:"expiresAt,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	validStatuses := map[string]bool{"in_progress": true, "resolved": true, "accepted": true}
	if !validStatuses[req.Status] {
		writeError(w, http.StatusBadRequest, "status must be in_progress, resolved, or accepted")
		return
	}

	// Look up the finding (scoped to org)
	finding, err := s.store.GetFindingByID(r.Context(), findingID, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		log.Printf("remediation: get finding: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	findingKey := store.ComputeFindingKey(finding.OrgID, finding.Hostname, finding.Algorithm, finding.KeySize, finding.Module)

	entry := &store.FindingStatusEntry{
		FindingKey: findingKey,
		OrgID:      orgID,
		Status:     req.Status,
		Reason:     req.Reason,
		ChangedBy:  userID,
		ChangedAt:  time.Now().UTC(),
	}

	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expiresAt must be RFC3339 format")
			return
		}
		entry.ExpiresAt = &t
	}

	if err := s.store.SetFindingStatus(r.Context(), entry); err != nil {
		log.Printf("remediation: set status: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Audit
	s.writeAudit(r, "finding.status_change", findingID, map[string]any{
		"findingKey": findingKey, "status": req.Status, "reason": req.Reason,
	})

	// Trigger pipeline refresh for this host
	s.EnqueuePipelineJob(orgID, finding.Hostname, "")

	writeJSON(w, http.StatusOK, map[string]any{
		"findingKey": findingKey,
		"status":     req.Status,
		"changedAt":  entry.ChangedAt,
	})
}

// POST /api/v1/findings/{id}/revert
func (s *Server) handleRevertFinding(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	orgID := TenantFromContext(r.Context())
	userID := UserIDFromContext(r.Context())

	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)

	finding, err := s.store.GetFindingByID(r.Context(), findingID, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		log.Printf("remediation: get finding: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	findingKey := store.ComputeFindingKey(finding.OrgID, finding.Hostname, finding.Algorithm, finding.KeySize, finding.Module)

	entry := &store.FindingStatusEntry{
		FindingKey: findingKey,
		OrgID:      orgID,
		Status:     "open",
		Reason:     req.Reason,
		ChangedBy:  userID,
		ChangedAt:  time.Now().UTC(),
	}

	if err := s.store.SetFindingStatus(r.Context(), entry); err != nil {
		log.Printf("remediation: revert: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.writeAudit(r, "finding.revert", findingID, map[string]any{
		"findingKey": findingKey, "reason": req.Reason,
	})
	s.EnqueuePipelineJob(orgID, finding.Hostname, "")

	writeJSON(w, http.StatusOK, map[string]any{
		"findingKey": findingKey,
		"status":     "open",
		"changedAt":  entry.ChangedAt,
	})
}

// GET /api/v1/findings/{id}/history
func (s *Server) handleFindingHistory(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	orgID := TenantFromContext(r.Context())

	finding, err := s.store.GetFindingByID(r.Context(), findingID, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		log.Printf("remediation: get finding: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	findingKey := store.ComputeFindingKey(finding.OrgID, finding.Hostname, finding.Algorithm, finding.KeySize, finding.Module)

	history, err := s.store.GetFindingHistory(r.Context(), findingKey)
	if err != nil {
		log.Printf("remediation: history: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if history == nil {
		history = []store.FindingStatusEntry{}
	}
	writeJSON(w, http.StatusOK, history)
}

// GET /api/v1/remediation/summary
func (s *Server) handleRemediationSummary(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	summary, err := s.store.GetRemediationSummary(r.Context(), orgID)
	if err != nil {
		log.Printf("remediation: summary: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// GET /api/v1/remediation
func (s *Server) handleListRemediation(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	statusFilter := r.URL.Query().Get("status")
	hostnameFilter := r.URL.Query().Get("hostname")
	pqcFilter := r.URL.Query().Get("pqc_status")

	rows, err := s.store.ListRemediationFindings(r.Context(), orgID, statusFilter, hostnameFilter, pqcFilter)
	if err != nil {
		log.Printf("remediation: list: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.RemediationRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": rows,
	})
}
```

- [ ] **Step 2: Wire routes in server.go**

In `pkg/server/server.go`, add routes. Read routes go under RequireTenant; mutation routes go under RequireScanAdmin.

In the RequireTenant section (near the analytics routes):

```go
r.Get("/remediation", s.handleListRemediation)
r.Get("/remediation/summary", s.handleRemediationSummary)
r.Get("/findings/{id}/history", s.handleFindingHistory)
```

In the RequireScanAdmin section (near DELETE /scans/{id}):

```go
r.Post("/findings/{id}/status", s.handleSetFindingStatus)
r.Post("/findings/{id}/revert", s.handleRevertFinding)
```

- [ ] **Step 3: Add UserIDFromContext helper if not present**

Check if `UserIDFromContext` exists in the auth middleware. If not, add a simple helper that reads the user ID from the JWT claims in the request context. If the request is from an agent (no user), return the org_id or "agent" as the actor.

- [ ] **Step 4: Verify compilation**

Run: `go build ./...`

- [ ] **Step 5: Commit**

```bash
git add pkg/server/handlers_remediation.go pkg/server/server.go
git commit -m "feat(server): add remediation API endpoints (status, revert, history, summary, list)

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Remediation tracker UI view

**Files:**
- Create: `pkg/server/ui/dist/views/remediation.js`
- Modify: `pkg/server/ui/dist/index.html`
- Modify: `pkg/server/ui/dist/style.css`
- Modify: `pkg/server/ui/dist/app.js`

- [ ] **Step 1: Create remediation.js**

Implement the full remediation tracker view:
- Fetch `GET /api/v1/remediation/summary` for the status cards
- Fetch `GET /api/v1/remediation` for the table
- Status summary cards at top (clickable to filter)
- Table with columns: Hostname, Algorithm, Status badge, Priority, Changed, Action
- Action dropdown for open/in-progress rows: In Progress / Resolved / Accept Risk
- Revert button for resolved/accepted rows
- Accept Risk modal: reason textarea (required) + expiry date input (optional)
- On status change: POST to `/findings/{id}/status` or `/findings/{id}/revert`, then refresh table
- Click hostname → `#/inventory?hostname=X`
- org_admin check: hide action column when `auth.isAdmin()` returns false
- Use `renderStalenessBar` from staleness.js
- Use `escapeHtml` for all user-provided strings (reason, hostname)

- [ ] **Step 2: Add nav link in index.html**

In the Analytics section:

```html
<a href="#/remediation" class="nav-link" data-view="remediation">
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 1v16"/><path d="M1 9h16"/><circle cx="9" cy="9" r="7"/></svg>
  <span>Remediation</span>
</a>
```

Add script tag:

```html
<script src="/ui/views/remediation.js"></script>
```

- [ ] **Step 3: Add router case in app.js**

```js
case 'remediation': if (window.renderRemediation) window.renderRemediation(); break;
```

- [ ] **Step 4: Add CSS styles**

Append to `style.css`:

```css
/* Remediation — Phase 4B */
.remediation-summary { display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
.remediation-card { padding: 1rem 1.5rem; border-radius: 8px; background: var(--bg-surface); border: 1px solid var(--border); cursor: pointer; text-align: center; min-width: 100px; transition: border-color 0.2s; }
.remediation-card:hover { border-color: var(--accent); }
.remediation-card.active { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(59,130,246,0.2); }
.remediation-card .count { font-size: 1.5rem; font-weight: 700; color: var(--text-primary); }
.remediation-card .label { font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem; }
.status-open { color: #f87171; }
.status-in_progress { color: #facc15; }
.status-resolved { color: #4ade80; }
.status-accepted { color: #60a5fa; }
.action-dropdown { padding: 0.25rem 0.5rem; border-radius: 4px; background: var(--bg-surface); color: var(--text-primary); border: 1px solid var(--border); cursor: pointer; font-size: 0.8rem; }
.action-btn { padding: 0.25rem 0.75rem; border-radius: 4px; background: transparent; color: var(--text-secondary); border: 1px solid var(--border); cursor: pointer; font-size: 0.8rem; }
.action-btn:hover { border-color: var(--accent); color: var(--text-primary); }
.modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.modal-content { background: var(--bg-primary); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; width: 90%; max-width: 480px; }
.modal-content h3 { margin-top: 0; color: var(--text-primary); }
.modal-content textarea { width: 100%; min-height: 80px; margin: 0.5rem 0; padding: 0.5rem; background: var(--bg-surface); color: var(--text-primary); border: 1px solid var(--border); border-radius: 4px; font-family: inherit; resize: vertical; }
.modal-content input[type="date"] { padding: 0.5rem; background: var(--bg-surface); color: var(--text-primary); border: 1px solid var(--border); border-radius: 4px; }
.modal-actions { display: flex; gap: 0.75rem; justify-content: flex-end; margin-top: 1rem; }
.modal-actions button { padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.9rem; }
.btn-primary { background: var(--accent); color: #fff; border: none; }
.btn-cancel { background: transparent; color: var(--text-secondary); border: 1px solid var(--border); }
```

- [ ] **Step 5: Verify build**

Run: `go build ./...`

- [ ] **Step 6: Commit**

```bash
git add pkg/server/ui/dist/views/remediation.js pkg/server/ui/dist/index.html pkg/server/ui/dist/style.css pkg/server/ui/dist/app.js
git commit -m "feat(ui): add Remediation Tracker view with action dropdowns + accept-risk modal

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Full verification + cleanup

**Files:**
- All modified files

- [ ] **Step 1: Run unit tests**

Run: `make test`
Expected: All PASS

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: 0 issues

- [ ] **Step 3: Build**

Run: `make build`
Expected: Clean

- [ ] **Step 4: Run integration tests** (if PostgreSQL available)

Run: `make test-integration`

- [ ] **Step 5: Final commit if fixups needed**

```bash
git add -A
git commit -m "fix: address lint/test issues from Phase 4B implementation

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Review Checkpoint

After Task 9, pause for code review. Key areas:

1. **finding_key consistency:** Go `ComputeFindingKey` produces the same hash as the SQL `encode(sha256(...), 'hex')` expression
2. **T2 auto-reopen:** Only resolved findings are reopened, not accepted
3. **T2 readiness exclusion:** Resolved and non-expired accepted are excluded; expired accepted are included
4. **Permissions:** Mutations require RequireScanAdmin; reads require RequireTenant
5. **Audit trail:** Every status change writes an audit event
6. **Pipeline trigger:** Every status mutation enqueues a pipeline job to refresh summaries
7. **UI security:** All user-provided strings (reason, hostname) are escaped before rendering
8. **Rollback:** TRUNCATE finding_status reverts all findings to open; T2 handles empty finding_status gracefully
