package report

import (
	"time"

	"github.com/amiryahaya/triton/pkg/store"
)

// AnalyticsReportData holds all data needed to generate a PDF
// analytics report. Analytics Phase 5.
type AnalyticsReportData struct {
	OrgName     string
	Snapshot    *store.OrgSnapshot
	Hosts       []store.HostSummary
	Remediation *store.RemediationSummary
	GeneratedAt time.Time
}

// AnalyticsExcelData holds all data needed to generate an Excel
// analytics workbook. Analytics Phase 5.
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
