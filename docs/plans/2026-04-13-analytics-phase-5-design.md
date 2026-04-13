# Analytics Phase 5: Export — PDF Board Report + Excel Analytics — Design Spec

**Date:** 2026-04-13
**Branch:** `feat/analytics-phase-5`
**Status:** Approved
**Depends on:** Phase 4A (ETL pipeline, host_summary, org_snapshot), Phase 4B (remediation, finding_status)

## Problem

The analytics dashboard has everything a CISO needs — readiness, trends, systems health, remediation tracking. But the data is locked in the web UI. CISOs need to email a report to the deputy minister, present at board meetings, and share with auditors. Analysts need Excel files to drill into the data offline.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| PDF library | maroto v2 (pure Go) | No external binary deps; clean table API; government report style |
| PDF content | Tables + summary text (no charts) | Government reports are table-heavy; fast to build; prints well |
| Excel library | excelize v2 (existing) | Already a dependency; proven in scan-report Excel generation |
| Trigger | Both UI buttons + API endpoints | Discoverable for dashboard users, automatable for CI/cron |
| Data source | Pre-computed org_snapshot + host_summary | Sub-50ms generation; no heavy aggregation at export time |

## PDF Report Layout

Formal compliance document — not a dashboard reproduction.

### Page 1: Executive Summary + Remediation + Certificates

```
┌─────────────────────────────────────────────────┐
│  [Organization Name]                             │
│  PQC Readiness Assessment Report                 │
│  Generated: 13 Apr 2026, 2:32 PM                │
│  Data as of: 13 Apr 2026, 2:30 PM               │
├─────────────────────────────────────────────────┤
│  1. EXECUTIVE SUMMARY                            │
│                                                  │
│  PQC Readiness:     73.2%                        │
│  Trend:             Improving (+3.1%/month)      │
│  Projection:        On track for 2029            │
│  Target:            80% by 2030                  │
│  Systems:           50 (31 green, 15 yellow,     │
│                         4 red)                   │
│  NACSA-2030:        WARN (12 violations)         │
│  CNSA 2.0:          FAIL (28 violations)         │
├─────────────────────────────────────────────────┤
│  2. REMEDIATION PROGRESS                         │
│                                                  │
│  Open: 142 | In Progress: 8 | Resolved: 23      │
│  Accepted Risk: 11 | Total: 184                  │
├─────────────────────────────────────────────────┤
│  3. CERTIFICATE URGENCY                          │
│                                                  │
│  Expired: 3 | Expiring <30d: 7 | <90d: 15       │
├─────────────────────────────────────────────────┤
│  FOOTER: Page 1 of N · Triton PQC Scanner        │
└─────────────────────────────────────────────────┘
```

### Page 2+: Systems Health Table

```
┌─────────────────────────────────────────────────┐
│  4. SYSTEMS HEALTH                               │
│                                                  │
│  Hostname  │Ready%│Unsafe│Depr.│Resolved│Trend  │
│  ──────────│──────│──────│─────│────────│───────│
│  legacy-1  │ 12%  │  4   │ 12  │   0    │  ↓   │
│  web-srv1  │ 45%  │  0   │  8  │   2    │  ↑   │
│  db-main   │ 78%  │  0   │  3  │   5    │  ↑   │
│  k8s-prod  │ 91%  │  0   │  1  │   8    │  →   │
│  ...                                             │
├─────────────────────────────────────────────────┤
│  5. TOP BLOCKERS                                 │
│                                                  │
│  Hostname  │Algorithm │Priority│PQC Status       │
│  ──────────│──────────│────────│─────────────────│
│  web-srv1  │RSA-1024  │  92    │ UNSAFE          │
│  legacy-1  │DES       │  90    │ UNSAFE          │
│  db-main   │SHA-1     │  78    │ DEPRECATED      │
│  ...                                             │
├─────────────────────────────────────────────────┤
│  FOOTER: Page N of N · Triton PQC Scanner        │
└─────────────────────────────────────────────────┘
```

## Excel Report Layout

Multi-sheet workbook for analysts. Built programmatically with excelize (no template file).

| Sheet | Content | Sort |
|---|---|---|
| Executive Summary | Key-value pairs: readiness, trend, projection, policy verdicts, remediation counts, cert counts | N/A |
| Systems Health | Full host_summary: hostname, readiness %, total, safe, transitional, deprecated, unsafe, resolved, accepted, trend, max priority, last scanned | Readiness ASC |
| Top Blockers | Top 20 findings by priority: hostname, algorithm, key size, PQC status, module, priority, file path | Priority DESC |
| Expiring Certificates | Certs with not_after: hostname, subject, issuer, algorithm, key size, expires, days remaining, status | Expiry ASC |
| Remediation Log | finding_status entries: finding key (truncated), hostname, algorithm, status, reason, changed by, changed at | Changed at DESC |

## API Endpoints

```
GET /api/v1/export/pdf
  Auth: RequireTenant (any authenticated user)
  Response: application/pdf
  Header: Content-Disposition: attachment; filename="triton-pqc-report-{orgname}-{date}.pdf"
  
GET /api/v1/export/xlsx
  Auth: RequireTenant
  Response: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
  Header: Content-Disposition: attachment; filename="triton-pqc-report-{orgname}-{date}.xlsx"
```

### Handler data flow

Both handlers follow the same pattern:

1. Get orgID from `TenantFromContext`
2. Fetch org name from `store.GetOrg(orgID)`
3. Fetch `store.GetOrgSnapshot(orgID)` → executive summary data
4. Fetch `store.ListHostSummaries(orgID, "")` → systems health data
5. Fetch `store.GetRemediationSummary(orgID)` → remediation counts
6. For PDF: top blockers from `snapshot.TopBlockers` (already in org_snapshot, top 5)
7. For Excel: fetch `ListTopPriorityFindings(orgID, 20, FilterParams{})`, `ListExpiringCertificates(orgID, 100*365*24h, FilterParams{})`, `ListFindingStatusLog(orgID, 1000)`
7. Generate file to temp path
8. Stream response with Content-Disposition, cleanup via defer

Generation time: < 200ms (all data pre-computed in summary tables).

## Store Changes

One new method on the Store interface:

```go
// ListFindingStatusLog returns all finding_status entries for the org,
// ordered by changed_at DESC. Limited to 1000 rows. Used by the Excel
// Remediation Log sheet. Phase 5.
ListFindingStatusLog(ctx context.Context, orgID string, limit int) ([]FindingStatusEntry, error)
```

The existing `ListExpiringCertificates` and `ListTopPriorityFindings` methods are reused for the Excel sheets.

## UI Integration

Two buttons in the overview page header:

```
Executive Dashboard                 [PDF Report] [Excel Export]
```

Button behavior:
- Click → fetch with JWT auth → blob download
- Spinner while generating, disabled during request
- Error: inline message below button (not modal)
- Styled with existing CSS variables (dark theme)

## Component Changes

| File | Action | Responsibility |
|---|---|---|
| `pkg/report/analytics_pdf.go` | Create | GenerateAnalyticsPDF via maroto v2 |
| `pkg/report/analytics_excel.go` | Create | GenerateAnalyticsExcel via excelize |
| `pkg/report/analytics_pdf_test.go` | Create | Unit test: PDF generates, file exists, non-empty |
| `pkg/report/analytics_excel_test.go` | Create | Unit test: Excel generates, correct sheet names |
| `pkg/server/handlers_export.go` | Create | handleExportPDF, handleExportExcel |
| `pkg/server/server.go` | Modify | Wire export routes under RequireTenant |
| `pkg/store/store.go` | Modify | Add ListFindingStatusLog to Store interface |
| `pkg/store/remediation.go` | Modify | Implement ListFindingStatusLog |
| `pkg/server/ui/dist/app.js` | Modify | Export buttons on overview page |
| `pkg/server/ui/dist/style.css` | Modify | Export button styles |
| `go.mod` | Modify | Add github.com/johnfercher/maroto/v2 |

## What Does NOT Change

- Existing scan-based report generators (GenerateHTML, GenerateExcel, etc.)
- ETL pipeline, host_summary, org_snapshot tables
- Analytics endpoints and views (inventory, certificates, priority, systems, trends)
- Remediation endpoints and UI

## Function Signatures

```go
// pkg/report/analytics_pdf.go
type AnalyticsReportData struct {
    OrgName      string
    Snapshot     *store.OrgSnapshot
    Hosts        []store.HostSummary
    Remediation  *store.RemediationSummary
    GeneratedAt  time.Time
}

func GenerateAnalyticsPDF(data *AnalyticsReportData, outputPath string) error

// pkg/report/analytics_excel.go
type AnalyticsExcelData struct {
    OrgName      string
    Snapshot     *store.OrgSnapshot
    Hosts        []store.HostSummary
    Remediation  *store.RemediationSummary
    Blockers     []store.PriorityRow
    Certs        []store.ExpiringCertRow
    StatusLog    []store.FindingStatusEntry
    GeneratedAt  time.Time
}

func GenerateAnalyticsExcel(data *AnalyticsExcelData, outputPath string) error
```

## Test Plan

### Unit tests
- `analytics_pdf_test.go`: GenerateAnalyticsPDF with mock data → file exists, size > 0, starts with PDF magic bytes `%PDF`
- `analytics_excel_test.go`: GenerateAnalyticsExcel with mock data → file exists, has 5 sheets with correct names

### Integration tests
- Handler test: GET /api/v1/export/pdf with seeded org_snapshot → 200 with Content-Type application/pdf
- Handler test: GET /api/v1/export/xlsx → 200 with correct Content-Type
- Empty org (no snapshot): GET /api/v1/export/pdf → 200 with a minimal report showing "No data available"

### Manual tests
- Open PDF in a viewer, verify layout matches spec
- Open Excel in a spreadsheet app, verify 5 sheets with correct data

## Rollback

All changes are additive. Remove the route registrations in server.go to disable exports. The maroto dependency can be pruned with `go mod tidy` if the code is removed.
