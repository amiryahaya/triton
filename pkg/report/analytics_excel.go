package report

import (
	"fmt"

	"github.com/xuri/excelize/v2"
)

// GenerateAnalyticsExcel creates a 5-sheet Excel workbook with
// analytics data from pre-computed summary tables. Analytics Phase 5.
func GenerateAnalyticsExcel(data *AnalyticsExcelData, outputPath string) error {
	f := excelize.NewFile()
	defer func() { _ = f.Close() }()

	// Rename default sheet and create additional sheets in order.
	_ = f.SetSheetName("Sheet1", "Executive Summary")
	_, _ = f.NewSheet("Systems Health")
	_, _ = f.NewSheet("Top Blockers")
	_, _ = f.NewSheet("Expiring Certificates")
	_, _ = f.NewSheet("Remediation Log")

	populateExecSummary(f, data)
	populateSystemsHealth(f, data)
	populateTopBlockers(f, data)
	populateExpiringCerts(f, data)
	populateRemediationLog(f, data)

	return f.SaveAs(outputPath)
}

// populateExecSummary writes key-value pairs to the Executive Summary sheet.
func populateExecSummary(f *excelize.File, data *AnalyticsExcelData) {
	const sheet = "Executive Summary"

	_ = f.SetColWidth(sheet, "A", "A", 30)
	_ = f.SetColWidth(sheet, "B", "B", 40)

	row := 1
	set := func(label string, value interface{}) {
		_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", row), label)
		_ = f.SetCellValue(sheet, fmt.Sprintf("B%d", row), value)
		row++
	}

	set("Organization", data.OrgName)
	set("Generated At", data.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))

	if data.Snapshot == nil {
		set("Data", "No data available")
		return
	}

	s := data.Snapshot

	row++ // blank separator
	set("PQC Readiness %", fmt.Sprintf("%.1f%%", s.ReadinessPct))
	set("Trend", fmt.Sprintf("%s (%.1f%%)", s.TrendDirection, s.TrendDeltaPct))
	set("Projection", s.ProjectionStatus)
	if s.ProjectedYear > 0 {
		set("Projected Compliance Year", s.ProjectedYear)
	}
	set("Target %", fmt.Sprintf("%.1f%%", s.TargetPct))
	set("Deadline Year", s.DeadlineYear)

	row++ // blank separator
	set("Systems Total", s.MachinesTotal)
	set("Systems Red", s.MachinesRed)
	set("Systems Yellow", s.MachinesYellow)
	set("Systems Green", s.MachinesGreen)

	row++ // blank separator
	set("Total Findings", s.TotalFindings)
	set("Safe Findings", s.SafeFindings)

	if len(s.PolicyVerdicts) > 0 {
		row++ // blank separator
		for _, pv := range s.PolicyVerdicts {
			set(fmt.Sprintf("Policy: %s", pv.PolicyLabel),
				fmt.Sprintf("%s (%d violations, %d findings checked)", pv.Verdict, pv.ViolationCount, pv.FindingsChecked))
		}
	}

	if data.Remediation != nil {
		r := data.Remediation
		row++ // blank separator
		set("Remediation: Open", r.Open)
		set("Remediation: In Progress", r.InProgress)
		set("Remediation: Resolved", r.Resolved)
		set("Remediation: Accepted", r.Accepted)
		set("Remediation: Total", r.Total)
	}

	row++ // blank separator
	set("Certs Expiring (30d)", s.CertsExpiring30d)
	set("Certs Expiring (90d)", s.CertsExpiring90d)
	set("Certs Expired", s.CertsExpired)
}

// populateSystemsHealth writes the per-host summary table.
func populateSystemsHealth(f *excelize.File, data *AnalyticsExcelData) {
	const sheet = "Systems Health"

	_ = f.SetColWidth(sheet, "A", "A", 25)
	_ = f.SetColWidth(sheet, "B", "B", 14)
	_ = f.SetColWidth(sheet, "C", "C", 16)
	_ = f.SetColWidth(sheet, "D", "D", 10)
	_ = f.SetColWidth(sheet, "E", "E", 14)
	_ = f.SetColWidth(sheet, "F", "F", 14)
	_ = f.SetColWidth(sheet, "G", "G", 12)
	_ = f.SetColWidth(sheet, "H", "H", 14)
	_ = f.SetColWidth(sheet, "I", "I", 14)
	_ = f.SetColWidth(sheet, "J", "J", 22)

	headers := []string{
		"Hostname", "Readiness %", "Total Findings", "Safe",
		"Transitional", "Deprecated", "Unsafe", "Trend", "Max Priority", "Last Scanned",
	}
	for i, h := range headers {
		col := string(rune('A' + i))
		_ = f.SetCellValue(sheet, fmt.Sprintf("%s1", col), h)
	}

	for i := range data.Hosts {
		host := &data.Hosts[i]
		r := i + 2
		_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", r), host.Hostname)
		_ = f.SetCellValue(sheet, fmt.Sprintf("B%d", r), fmt.Sprintf("%.1f%%", host.ReadinessPct))
		_ = f.SetCellValue(sheet, fmt.Sprintf("C%d", r), host.TotalFindings)
		_ = f.SetCellValue(sheet, fmt.Sprintf("D%d", r), host.SafeFindings)
		_ = f.SetCellValue(sheet, fmt.Sprintf("E%d", r), host.TransitionalFindings)
		_ = f.SetCellValue(sheet, fmt.Sprintf("F%d", r), host.DeprecatedFindings)
		_ = f.SetCellValue(sheet, fmt.Sprintf("G%d", r), host.UnsafeFindings)
		_ = f.SetCellValue(sheet, fmt.Sprintf("H%d", r), fmt.Sprintf("%s (%.1f%%)", host.TrendDirection, host.TrendDeltaPct))
		_ = f.SetCellValue(sheet, fmt.Sprintf("I%d", r), host.MaxPriority)
		_ = f.SetCellValue(sheet, fmt.Sprintf("J%d", r), host.ScannedAt.Format("2006-01-02 15:04"))
	}
}

// populateTopBlockers writes the top priority findings table.
func populateTopBlockers(f *excelize.File, data *AnalyticsExcelData) {
	const sheet = "Top Blockers"

	_ = f.SetColWidth(sheet, "A", "A", 25)
	_ = f.SetColWidth(sheet, "B", "B", 18)
	_ = f.SetColWidth(sheet, "C", "C", 12)
	_ = f.SetColWidth(sheet, "D", "D", 16)
	_ = f.SetColWidth(sheet, "E", "E", 16)
	_ = f.SetColWidth(sheet, "F", "F", 12)
	_ = f.SetColWidth(sheet, "G", "G", 40)

	headers := []string{"Hostname", "Algorithm", "Key Size", "PQC Status", "Module", "Priority", "File Path"}
	for i, h := range headers {
		col := string(rune('A' + i))
		_ = f.SetCellValue(sheet, fmt.Sprintf("%s1", col), h)
	}

	for i, b := range data.Blockers {
		r := i + 2
		_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", r), b.Hostname)
		_ = f.SetCellValue(sheet, fmt.Sprintf("B%d", r), b.Algorithm)
		_ = f.SetCellValue(sheet, fmt.Sprintf("C%d", r), b.KeySize)
		_ = f.SetCellValue(sheet, fmt.Sprintf("D%d", r), b.PQCStatus)
		_ = f.SetCellValue(sheet, fmt.Sprintf("E%d", r), b.Module)
		_ = f.SetCellValue(sheet, fmt.Sprintf("F%d", r), b.Priority)
		_ = f.SetCellValue(sheet, fmt.Sprintf("G%d", r), b.FilePath)
	}
}

// populateExpiringCerts writes the expiring certificates table.
func populateExpiringCerts(f *excelize.File, data *AnalyticsExcelData) {
	const sheet = "Expiring Certificates"

	_ = f.SetColWidth(sheet, "A", "A", 25)
	_ = f.SetColWidth(sheet, "B", "B", 35)
	_ = f.SetColWidth(sheet, "C", "C", 35)
	_ = f.SetColWidth(sheet, "D", "D", 14)
	_ = f.SetColWidth(sheet, "E", "E", 12)
	_ = f.SetColWidth(sheet, "F", "F", 22)
	_ = f.SetColWidth(sheet, "G", "G", 16)
	_ = f.SetColWidth(sheet, "H", "H", 12)

	headers := []string{"Hostname", "Subject", "Issuer", "Algorithm", "Key Size", "Expires", "Days Remaining", "Status"}
	for i, h := range headers {
		col := string(rune('A' + i))
		_ = f.SetCellValue(sheet, fmt.Sprintf("%s1", col), h)
	}

	for i := range data.Certs {
		c := &data.Certs[i]
		r := i + 2
		_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", r), c.Hostname)
		_ = f.SetCellValue(sheet, fmt.Sprintf("B%d", r), c.Subject)
		_ = f.SetCellValue(sheet, fmt.Sprintf("C%d", r), c.Issuer)
		_ = f.SetCellValue(sheet, fmt.Sprintf("D%d", r), c.Algorithm)
		_ = f.SetCellValue(sheet, fmt.Sprintf("E%d", r), c.KeySize)
		_ = f.SetCellValue(sheet, fmt.Sprintf("F%d", r), c.NotAfter.Format("2006-01-02"))
		_ = f.SetCellValue(sheet, fmt.Sprintf("G%d", r), c.DaysRemaining)
		_ = f.SetCellValue(sheet, fmt.Sprintf("H%d", r), c.Status)
	}
}

// populateRemediationLog writes the finding status log table.
// FindingKey is truncated to 16 characters for readability.
func populateRemediationLog(f *excelize.File, data *AnalyticsExcelData) {
	const sheet = "Remediation Log"

	_ = f.SetColWidth(sheet, "A", "A", 20)
	_ = f.SetColWidth(sheet, "B", "B", 14)
	_ = f.SetColWidth(sheet, "C", "C", 40)
	_ = f.SetColWidth(sheet, "D", "D", 20)
	_ = f.SetColWidth(sheet, "E", "E", 22)

	headers := []string{"Finding Key", "Status", "Reason", "Changed By", "Changed At"}
	for i, h := range headers {
		col := string(rune('A' + i))
		_ = f.SetCellValue(sheet, fmt.Sprintf("%s1", col), h)
	}

	for i, e := range data.StatusLog {
		r := i + 2
		key := e.FindingKey
		if len(key) > 16 {
			key = key[:16]
		}
		_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", r), key)
		_ = f.SetCellValue(sheet, fmt.Sprintf("B%d", r), e.Status)
		_ = f.SetCellValue(sheet, fmt.Sprintf("C%d", r), e.Reason)
		_ = f.SetCellValue(sheet, fmt.Sprintf("D%d", r), e.ChangedBy)
		_ = f.SetCellValue(sheet, fmt.Sprintf("E%d", r), e.ChangedAt.Format("2006-01-02 15:04"))
	}
}
