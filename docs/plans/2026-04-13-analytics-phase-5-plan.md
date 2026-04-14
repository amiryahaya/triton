# Analytics Phase 5: Export — PDF Board Report + Excel Analytics — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate downloadable PDF board reports and Excel analytics workbooks from pre-computed summary tables, triggered via API endpoints and UI buttons.

**Architecture:** Two new report generators (`analytics_pdf.go` using maroto v2, `analytics_excel.go` using excelize) read from `org_snapshot` and `host_summary` tables. Two HTTP handlers stream the generated files with Content-Disposition headers. UI buttons on the overview page trigger browser downloads. One new store method (`ListFindingStatusLog`) provides the remediation log for the Excel sheet.

**Tech Stack:** Go 1.25, maroto v2 (pure Go PDF), excelize v2 (existing), vanilla JS

**Spec:** `docs/plans/2026-04-13-analytics-phase-5-design.md`

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `go.mod` | Modify | Add maroto v2 dependency |
| `pkg/report/analytics_types.go` | Create | AnalyticsReportData, AnalyticsExcelData structs |
| `pkg/report/analytics_pdf.go` | Create | GenerateAnalyticsPDF via maroto v2 |
| `pkg/report/analytics_pdf_test.go` | Create | PDF generation unit test |
| `pkg/report/analytics_excel.go` | Create | GenerateAnalyticsExcel via excelize |
| `pkg/report/analytics_excel_test.go` | Create | Excel generation unit test |
| `pkg/store/store.go` | Modify | Add ListFindingStatusLog to Store interface |
| `pkg/store/remediation.go` | Modify | Implement ListFindingStatusLog |
| `pkg/server/handlers_export.go` | Create | handleExportPDF, handleExportExcel |
| `pkg/server/server.go` | Modify | Wire export routes |
| `pkg/server/ui/dist/app.js` | Modify | Export buttons on overview |
| `pkg/server/ui/dist/style.css` | Modify | Export button styles |

---

### Task 1: Add maroto v2 dependency

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add the dependency**

```bash
go get github.com/johnfercher/maroto/v2@latest
```

- [ ] **Step 2: Tidy**

```bash
go mod tidy
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add maroto v2 for pure-Go PDF generation

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Shared types + ListFindingStatusLog store method

**Files:**
- Create: `pkg/report/analytics_types.go`
- Modify: `pkg/store/store.go`
- Modify: `pkg/store/remediation.go`
- Modify: `pkg/store/pipeline_test.go` (mock)

- [ ] **Step 1: Create analytics_types.go**

```go
package report

import (
	"time"

	"github.com/amiryahaya/triton/pkg/store"
)

// AnalyticsReportData holds all data needed to generate a PDF
// analytics report. Populated by the export handler from pre-computed
// summary tables. Analytics Phase 5.
type AnalyticsReportData struct {
	OrgName     string
	Snapshot    *store.OrgSnapshot
	Hosts       []store.HostSummary
	Remediation *store.RemediationSummary
	GeneratedAt time.Time
}

// AnalyticsExcelData holds all data needed to generate an Excel
// analytics workbook. Extends AnalyticsReportData with detail-level
// data for the additional sheets. Analytics Phase 5.
type AnalyticsExcelData struct {
	OrgName     string
	Snapshot    *store.OrgSnapshot
	Hosts       []store.HostSummary
	Remediation *store.RemediationSummary
	Blockers    []store.PriorityRow
	Certs       []store.ExpiringCertRow
	StatusLog   []store.FindingStatusEntry
	GeneratedAt time.Time
}
```

- [ ] **Step 2: Add ListFindingStatusLog to Store interface**

In `pkg/store/store.go`, add in the Remediation section:

```go
	// ListFindingStatusLog returns finding_status entries for the org,
	// ordered by changed_at DESC. Limited by the limit parameter.
	// Used by the Excel Remediation Log sheet. Phase 5.
	ListFindingStatusLog(ctx context.Context, orgID string, limit int) ([]FindingStatusEntry, error)
```

- [ ] **Step 3: Implement ListFindingStatusLog**

In `pkg/store/remediation.go`, add:

```go
func (s *PostgresStore) ListFindingStatusLog(ctx context.Context, orgID string, limit int) ([]FindingStatusEntry, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, finding_key, org_id, status, reason, changed_by, changed_at, expires_at
		 FROM finding_status
		 WHERE org_id = $1
		 ORDER BY changed_at DESC
		 LIMIT $2`,
		orgID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("ListFindingStatusLog: %w", err)
	}
	defer rows.Close()
	result := []FindingStatusEntry{}
	for rows.Next() {
		var e FindingStatusEntry
		if err := rows.Scan(&e.ID, &e.FindingKey, &e.OrgID, &e.Status, &e.Reason, &e.ChangedBy, &e.ChangedAt, &e.ExpiresAt); err != nil {
			return nil, fmt.Errorf("ListFindingStatusLog scan: %w", err)
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
```

- [ ] **Step 4: Add mock stub to pipeline_test.go**

Add to `pipelineMockStore` in `pkg/store/pipeline_test.go`:

```go
func (m *pipelineMockStore) ListFindingStatusLog(_ context.Context, _ string, _ int) ([]FindingStatusEntry, error) {
	panic("not implemented")
}
```

- [ ] **Step 5: Verify build**

Run: `go build ./...`

- [ ] **Step 6: Commit**

```bash
git add pkg/report/analytics_types.go pkg/store/store.go pkg/store/remediation.go pkg/store/pipeline_test.go
git commit -m "feat(store): add ListFindingStatusLog + analytics export types

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: PDF generator — GenerateAnalyticsPDF

**Files:**
- Create: `pkg/report/analytics_pdf.go`
- Create: `pkg/report/analytics_pdf_test.go`

- [ ] **Step 1: Write the unit test**

Create `pkg/report/analytics_pdf_test.go`:

```go
package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

func TestGenerateAnalyticsPDF_ProducesValidFile(t *testing.T) {
	data := &AnalyticsReportData{
		OrgName: "Test Organization",
		Snapshot: &store.OrgSnapshot{
			ReadinessPct:   73.2,
			TotalFindings:  184,
			SafeFindings:   135,
			MachinesTotal:  50,
			MachinesRed:    4,
			MachinesYellow: 15,
			MachinesGreen:  31,
			TrendDirection: "improving",
			TrendDeltaPct:  3.1,
			ProjectionStatus: "on-track",
			ProjectedYear:   2029,
			TargetPct:       80.0,
			DeadlineYear:    2030,
			PolicyVerdicts: []store.PolicyVerdictSummary{
				{PolicyName: "nacsa-2030", PolicyLabel: "NACSA-2030", Verdict: "WARN", ViolationCount: 12, FindingsChecked: 184},
				{PolicyName: "cnsa-2.0", PolicyLabel: "CNSA 2.0", Verdict: "FAIL", ViolationCount: 28, FindingsChecked: 184},
			},
			TopBlockers: []store.PriorityRow{
				{FindingID: "f1", Priority: 92, Algorithm: "RSA-1024", PQCStatus: "UNSAFE", Hostname: "web-srv1"},
				{FindingID: "f2", Priority: 90, Algorithm: "DES", PQCStatus: "UNSAFE", Hostname: "legacy-1"},
			},
			CertsExpiring30d: 7,
			CertsExpiring90d: 15,
			CertsExpired:     3,
		},
		Hosts: []store.HostSummary{
			{Hostname: "legacy-1", ReadinessPct: 12.0, UnsafeFindings: 4, DeprecatedFindings: 12, TrendDirection: "declining"},
			{Hostname: "web-srv1", ReadinessPct: 45.0, UnsafeFindings: 0, DeprecatedFindings: 8, TrendDirection: "improving"},
		},
		Remediation: &store.RemediationSummary{
			Open: 142, InProgress: 8, Resolved: 23, Accepted: 11, Total: 184,
		},
		GeneratedAt: time.Date(2026, 4, 13, 14, 32, 0, 0, time.UTC),
	}

	outputPath := filepath.Join(t.TempDir(), "test-report.pdf")
	err := GenerateAnalyticsPDF(data, outputPath)
	require.NoError(t, err)

	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0), "PDF must not be empty")

	// Check PDF magic bytes
	f, err := os.Open(outputPath)
	require.NoError(t, err)
	defer f.Close()
	magic := make([]byte, 4)
	_, err = f.Read(magic)
	require.NoError(t, err)
	assert.Equal(t, "%PDF", string(magic), "file must start with PDF magic bytes")
}

func TestGenerateAnalyticsPDF_EmptySnapshot(t *testing.T) {
	data := &AnalyticsReportData{
		OrgName:     "Empty Org",
		Snapshot:    nil,
		Hosts:       nil,
		Remediation: nil,
		GeneratedAt: time.Now(),
	}

	outputPath := filepath.Join(t.TempDir(), "empty-report.pdf")
	err := GenerateAnalyticsPDF(data, outputPath)
	require.NoError(t, err)

	info, err := os.Stat(outputPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0), "even empty report must produce a valid PDF")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestGenerateAnalyticsPDF ./pkg/report/`
Expected: FAIL — GenerateAnalyticsPDF not defined

- [ ] **Step 3: Implement GenerateAnalyticsPDF**

Create `pkg/report/analytics_pdf.go`. Use maroto v2 to build the PDF:

```go
package report

import (
	"fmt"
	"os"
	"time"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"
)
```

The implementation should:
1. Create a maroto document with A4 page size
2. Add header: org name, report title, generation timestamp, data-as-of
3. Section 1 — Executive Summary: key-value rows for readiness, trend, projection, systems, policy verdicts
4. Section 2 — Remediation Progress: single row with counts
5. Section 3 — Certificate Urgency: single row with counts
6. Section 4 — Systems Health table: hostname, readiness %, unsafe, deprecated, resolved, trend
7. Section 5 — Top Blockers table: hostname, algorithm, priority, PQC status
8. Footer: page numbers + "Triton PQC Scanner"
9. Handle nil snapshot gracefully (show "No data available")
10. Write to outputPath via `document.Generate()` → `os.WriteFile()`

Read the maroto v2 documentation for the exact API. The key types are:
- `maroto.New(cfg)` → returns a `core.Maroto`
- `m.AddRow(height, components...)` for content
- `text.New("...", props.Text{...})` for text
- `m.GetStructure()` → then save

NOTE: maroto v2 API may vary. The implementer should read the maroto v2 README and examples to get the exact constructor/method names. The key pattern is: build document → add rows with text/table → generate bytes → write file.

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestGenerateAnalyticsPDF ./pkg/report/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/report/analytics_pdf.go pkg/report/analytics_pdf_test.go
git commit -m "feat(report): add GenerateAnalyticsPDF via maroto v2

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Excel generator — GenerateAnalyticsExcel

**Files:**
- Create: `pkg/report/analytics_excel.go`
- Create: `pkg/report/analytics_excel_test.go`

- [ ] **Step 1: Write the unit test**

Create `pkg/report/analytics_excel_test.go`:

```go
package report

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xuri/excelize/v2"

	"github.com/amiryahaya/triton/pkg/store"
)

func TestGenerateAnalyticsExcel_ProducesValidFile(t *testing.T) {
	data := &AnalyticsExcelData{
		OrgName: "Test Organization",
		Snapshot: &store.OrgSnapshot{
			ReadinessPct:     73.2,
			TotalFindings:    184,
			SafeFindings:     135,
			MachinesTotal:    50,
			MachinesRed:      4,
			MachinesYellow:   15,
			MachinesGreen:    31,
			TrendDirection:   "improving",
			TrendDeltaPct:    3.1,
			ProjectionStatus: "on-track",
			ProjectedYear:    2029,
			TargetPct:        80.0,
			DeadlineYear:     2030,
			CertsExpiring30d: 7,
			CertsExpiring90d: 15,
			CertsExpired:     3,
		},
		Hosts: []store.HostSummary{
			{Hostname: "legacy-1", ReadinessPct: 12.0, TotalFindings: 20, SafeFindings: 2, UnsafeFindings: 4, DeprecatedFindings: 12, TrendDirection: "declining", ScannedAt: time.Now()},
		},
		Remediation: &store.RemediationSummary{Open: 142, InProgress: 8, Resolved: 23, Accepted: 11, Total: 184},
		Blockers:    []store.PriorityRow{{FindingID: "f1", Priority: 92, Algorithm: "RSA-1024", PQCStatus: "UNSAFE", Hostname: "web-srv1", Module: "certificate"}},
		Certs:       []store.ExpiringCertRow{{FindingID: "c1", Subject: "*.example.com", Hostname: "web-srv1", Algorithm: "RSA", KeySize: 2048, NotAfter: time.Now().Add(24 * time.Hour), DaysRemaining: 1, Status: "urgent"}},
		StatusLog:   []store.FindingStatusEntry{{FindingKey: "abc123", Status: "resolved", Reason: "migrated", ChangedBy: "admin", ChangedAt: time.Now()}},
		GeneratedAt: time.Now(),
	}

	outputPath := filepath.Join(t.TempDir(), "test-report.xlsx")
	err := GenerateAnalyticsExcel(data, outputPath)
	require.NoError(t, err)

	// Open and verify sheets
	f, err := excelize.OpenFile(outputPath)
	require.NoError(t, err)
	defer f.Close()

	sheets := f.GetSheetList()
	assert.Equal(t, 5, len(sheets), "workbook must have 5 sheets")
	assert.Equal(t, "Executive Summary", sheets[0])
	assert.Equal(t, "Systems Health", sheets[1])
	assert.Equal(t, "Top Blockers", sheets[2])
	assert.Equal(t, "Expiring Certificates", sheets[3])
	assert.Equal(t, "Remediation Log", sheets[4])
}

func TestGenerateAnalyticsExcel_EmptyData(t *testing.T) {
	data := &AnalyticsExcelData{
		OrgName:     "Empty Org",
		GeneratedAt: time.Now(),
	}

	outputPath := filepath.Join(t.TempDir(), "empty-report.xlsx")
	err := GenerateAnalyticsExcel(data, outputPath)
	require.NoError(t, err)

	f, err := excelize.OpenFile(outputPath)
	require.NoError(t, err)
	defer f.Close()
	assert.Equal(t, 5, len(f.GetSheetList()))
}
```

- [ ] **Step 2: Implement GenerateAnalyticsExcel**

Create `pkg/report/analytics_excel.go`. Use excelize to build a 5-sheet workbook:

```go
package report

import (
	"fmt"
	"time"

	"github.com/xuri/excelize/v2"
)
```

Implementation:
1. `excelize.NewFile()` — creates workbook with default "Sheet1"
2. Rename "Sheet1" to "Executive Summary", create 4 more sheets
3. **Sheet 1 (Executive Summary):** Key-value rows using SetCellValue — readiness %, trend, projection, policy verdicts, remediation counts, cert counts. Bold headers via style.
4. **Sheet 2 (Systems Health):** Header row + data rows from `data.Hosts`. Columns: Hostname, Readiness %, Total, Safe, Transitional, Deprecated, Unsafe, Resolved, Accepted, Trend, Max Priority, Last Scanned. Sorted by readiness ASC (hosts are already sorted from ListHostSummaries).
5. **Sheet 3 (Top Blockers):** Header row + data from `data.Blockers`. Columns: Hostname, Algorithm, Key Size, PQC Status, Module, Priority, File Path.
6. **Sheet 4 (Expiring Certificates):** Header row + data from `data.Certs`. Columns: Hostname, Subject, Issuer, Algorithm, Key Size, Expires, Days Remaining, Status.
7. **Sheet 5 (Remediation Log):** Header row + data from `data.StatusLog`. Columns: Finding Key (first 16 chars), Status, Reason, Changed By, Changed At.
8. Auto-set column widths via `SetColWidth` for each sheet.
9. `SaveAs(outputPath)`.

Handle nil/empty data gracefully — each sheet gets its headers even with no data rows.

- [ ] **Step 3: Run tests**

Run: `go test -v -run TestGenerateAnalyticsExcel ./pkg/report/`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/report/analytics_excel.go pkg/report/analytics_excel_test.go
git commit -m "feat(report): add GenerateAnalyticsExcel via excelize

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: HTTP handlers — handleExportPDF + handleExportExcel

**Files:**
- Create: `pkg/server/handlers_export.go`
- Modify: `pkg/server/server.go`

- [ ] **Step 1: Create handlers_export.go**

```go
package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/store"
)

// GET /api/v1/export/pdf
func (s *Server) handleExportPDF(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())

	data, orgName, err := s.gatherAnalyticsReportData(r)
	if err != nil {
		log.Printf("export pdf: gather data: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	tmpFile, err := os.CreateTemp("", "triton-report-*.pdf")
	if err != nil {
		log.Printf("export pdf: create temp: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := report.GenerateAnalyticsPDF(data, tmpPath); err != nil {
		log.Printf("export pdf: generate: %v", err)
		writeError(w, http.StatusInternalServerError, "report generation failed")
		return
	}

	s.streamFile(w, tmpPath, sanitizeFilename(orgName)+".pdf", "application/pdf")
	_ = orgID // used by gatherAnalyticsReportData via context
}

// GET /api/v1/export/xlsx
func (s *Server) handleExportExcel(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())

	reportData, orgName, err := s.gatherAnalyticsReportData(r)
	if err != nil {
		log.Printf("export xlsx: gather data: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Fetch additional detail data for Excel sheets
	blockers, err := s.store.ListTopPriorityFindings(r.Context(), orgID, 20, store.FilterParams{})
	if err != nil {
		log.Printf("export xlsx: blockers: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	certs, err := s.store.ListExpiringCertificates(r.Context(), orgID, 100*365*24*time.Hour, store.FilterParams{})
	if err != nil {
		log.Printf("export xlsx: certs: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	statusLog, err := s.store.ListFindingStatusLog(r.Context(), orgID, 1000)
	if err != nil {
		log.Printf("export xlsx: status log: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	data := &report.AnalyticsExcelData{
		OrgName:     reportData.OrgName,
		Snapshot:    reportData.Snapshot,
		Hosts:       reportData.Hosts,
		Remediation: reportData.Remediation,
		Blockers:    blockers,
		Certs:       certs,
		StatusLog:   statusLog,
		GeneratedAt: reportData.GeneratedAt,
	}

	tmpFile, err := os.CreateTemp("", "triton-report-*.xlsx")
	if err != nil {
		log.Printf("export xlsx: create temp: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := report.GenerateAnalyticsExcel(data, tmpPath); err != nil {
		log.Printf("export xlsx: generate: %v", err)
		writeError(w, http.StatusInternalServerError, "report generation failed")
		return
	}

	s.streamFile(w, tmpPath, sanitizeFilename(orgName)+".xlsx",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
}

// gatherAnalyticsReportData fetches the common data needed by both
// PDF and Excel export handlers.
func (s *Server) gatherAnalyticsReportData(r *http.Request) (*report.AnalyticsReportData, string, error) {
	orgID := TenantFromContext(r.Context())
	ctx := r.Context()

	org, err := s.store.GetOrg(ctx, orgID)
	orgName := "Unknown Organization"
	if err == nil && org != nil {
		orgName = org.Name
	}

	snapshot, err := s.store.GetOrgSnapshot(ctx, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("get org snapshot: %w", err)
	}

	hosts, err := s.store.ListHostSummaries(ctx, orgID, "")
	if err != nil {
		return nil, "", fmt.Errorf("list host summaries: %w", err)
	}

	remediation, err := s.store.GetRemediationSummary(ctx, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("get remediation summary: %w", err)
	}

	return &report.AnalyticsReportData{
		OrgName:     orgName,
		Snapshot:    snapshot,
		Hosts:       hosts,
		Remediation: remediation,
		GeneratedAt: time.Now().UTC(),
	}, orgName, nil
}

// streamFile sends a file as an HTTP attachment download.
func (s *Server) streamFile(w http.ResponseWriter, path, filename, contentType string) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("export: open file: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer f.Close()

	date := time.Now().Format("2006-01-02")
	fullFilename := fmt.Sprintf("triton-pqc-report-%s-%s", date, filename)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fullFilename))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// sanitizeFilename removes characters unsafe for filenames.
func sanitizeFilename(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, name)
	if safe == "" {
		return "report"
	}
	return safe
}
```

- [ ] **Step 2: Wire routes in server.go**

In `pkg/server/server.go`, in the RequireTenant group (near the analytics routes), add:

```go
r.Get("/export/pdf", s.handleExportPDF)
r.Get("/export/xlsx", s.handleExportExcel)
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`

- [ ] **Step 4: Commit**

```bash
git add pkg/server/handlers_export.go pkg/server/server.go
git commit -m "feat(server): add PDF + Excel export endpoints

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: UI export buttons

**Files:**
- Modify: `pkg/server/ui/dist/app.js`
- Modify: `pkg/server/ui/dist/style.css`

- [ ] **Step 1: Add export buttons to overview page**

In `pkg/server/ui/dist/app.js`, find the overview page render function (look for the page header where "Executive Dashboard" or "Overview" is rendered). Add two buttons in the header area:

```js
'<div class="export-buttons">' +
  '<button class="btn-export" id="btn-export-pdf" onclick="exportReport(\'pdf\')">PDF Report</button>' +
  '<button class="btn-export" id="btn-export-xlsx" onclick="exportReport(\'xlsx\')">Excel Export</button>' +
'</div>'
```

Add the `exportReport` function (can be at the bottom of app.js or in a component):

```js
function exportReport(format) {
  var btn = document.getElementById('btn-export-' + format);
  if (!btn) return;
  var origText = btn.textContent;
  btn.textContent = 'Generating...';
  btn.disabled = true;

  var headers = {};
  var token = localStorage.getItem('tritonJWT');
  if (token) headers['Authorization'] = 'Bearer ' + token;

  fetch('/api/v1/export/' + format, { headers: headers })
    .then(function(resp) {
      if (!resp.ok) throw new Error('Export failed: ' + resp.status);
      return resp.blob();
    })
    .then(function(blob) {
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'triton-pqc-report.' + (format === 'xlsx' ? 'xlsx' : 'pdf');
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    })
    .catch(function(err) {
      alert('Export failed: ' + err.message);
    })
    .finally(function() {
      btn.textContent = origText;
      btn.disabled = false;
    });
}
```

- [ ] **Step 2: Add CSS styles**

Append to `pkg/server/ui/dist/style.css`:

```css
/* Export buttons — Phase 5 */
.export-buttons { display: flex; gap: 0.5rem; margin-left: auto; }
.btn-export { padding: 0.4rem 1rem; border-radius: 4px; background: var(--bg-surface); color: var(--text-primary); border: 1px solid var(--border); cursor: pointer; font-size: 0.85rem; transition: border-color 0.2s, opacity 0.2s; }
.btn-export:hover { border-color: var(--accent); }
.btn-export:disabled { opacity: 0.5; cursor: not-allowed; }
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`

- [ ] **Step 4: Commit**

```bash
git add pkg/server/ui/dist/app.js pkg/server/ui/dist/style.css
git commit -m "feat(ui): add PDF + Excel export buttons on overview page

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Full verification + cleanup

**Files:** All modified files

- [ ] **Step 1: Run unit tests**

Run: `make test`
Expected: All PASS

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: 0 issues

- [ ] **Step 3: Build**

Run: `make build`
Expected: Clean

- [ ] **Step 4: Final commit if fixups needed**

```bash
git add -A
git commit -m "fix: address lint/test issues from Phase 5 implementation

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

## Review Checkpoint

After Task 7, pause for code review. Key areas:

1. **PDF validity:** Generated file starts with `%PDF` magic bytes and is openable
2. **Excel sheet structure:** 5 sheets with correct names and column headers
3. **Content-Disposition:** Correct filename format and content types
4. **Nil handling:** Both generators produce valid output when snapshot is nil (empty org)
5. **Tenant isolation:** Both handlers scope all queries to orgID from context
6. **File cleanup:** Temp files are removed via defer after streaming
7. **UI security:** Export buttons use JWT from localStorage for auth
