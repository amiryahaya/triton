package report

import (
	"fmt"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/amiryahaya/triton/pkg/store"
)

// headerBG is the dark navy background colour for section headers.
var headerBG = &props.Color{Red: 31, Green: 56, Blue: 100}

// headerText is white text used against dark headers.
var headerTextColor = &props.Color{Red: 255, Green: 255, Blue: 255}

// labelTextProps is the standard label style (bold, left-aligned).
func labelTextProps() props.Text {
	return props.Text{
		Style: fontstyle.Bold,
		Size:  9,
		Left:  2,
	}
}

// valueTextProps is the standard value style (normal, left-aligned).
func valueTextProps() props.Text {
	return props.Text{
		Size: 9,
		Left: 2,
	}
}

// sectionHeaderProps returns text props for section header rows.
func sectionHeaderProps() props.Text {
	return props.Text{
		Style: fontstyle.Bold,
		Size:  10,
		Align: align.Center,
		Color: headerTextColor,
		Top:   2,
	}
}

// tableHeaderProps returns text props for table column headers.
func tableHeaderProps() props.Text {
	return props.Text{
		Style: fontstyle.Bold,
		Size:  8,
		Align: align.Center,
		Color: headerTextColor,
		Top:   1,
	}
}

// tableCellProps returns text props for table data cells.
func tableCellProps() props.Text {
	return props.Text{
		Size:  8,
		Align: align.Center,
		Left:  1,
		Right: 1,
	}
}

// GenerateAnalyticsPDF generates a PDF analytics report for the given data
// and writes it to outputPath. All sections handle nil data gracefully.
func GenerateAnalyticsPDF(data *AnalyticsReportData, outputPath string) error {
	m := maroto.New()

	addPDFHeader(m, data)
	addExecutiveSummarySection(m, data)
	addRemediationSection(m, data)
	addCertificateUrgencySection(m, data)
	addSystemsHealthSection(m, data)
	addTopBlockersSection(m, data)

	doc, err := m.Generate()
	if err != nil {
		return fmt.Errorf("generate PDF: %w", err)
	}

	return doc.Save(outputPath)
}

// addPDFHeader writes the report title header rows.
func addPDFHeader(m core.Maroto, data *AnalyticsReportData) {
	// Org name — large bold title
	m.AddRow(14, text.NewCol(12, data.OrgName, props.Text{
		Style: fontstyle.Bold,
		Size:  18,
		Align: align.Center,
		Top:   3,
		Color: &props.Color{Red: 31, Green: 56, Blue: 100},
	}))

	// Report subtitle
	m.AddRow(8, text.NewCol(12, "PQC Readiness Assessment Report", props.Text{
		Style: fontstyle.Bold,
		Size:  11,
		Align: align.Center,
		Color: &props.Color{Red: 80, Green: 80, Blue: 80},
	}))

	// Generation date
	genDate := data.GeneratedAt.Format("2006-01-02 15:04:05 UTC")
	m.AddRow(6, text.NewCol(12, "Generated: "+genDate, props.Text{
		Size:  8,
		Align: align.Center,
		Color: &props.Color{Red: 120, Green: 120, Blue: 120},
	}))

	// Data as-of date (snapshot refresh time if available)
	if data.Snapshot != nil && !data.Snapshot.RefreshedAt.IsZero() {
		asOf := data.Snapshot.RefreshedAt.Format("2006-01-02 15:04:05 UTC")
		m.AddRow(6, text.NewCol(12, "Data as of: "+asOf, props.Text{
			Size:  8,
			Align: align.Center,
			Color: &props.Color{Red: 120, Green: 120, Blue: 120},
		}))
	}

	m.AddRows(line.NewRow(4))
}

// addExecutiveSummarySection adds Section 1: Executive Summary.
func addExecutiveSummarySection(m core.Maroto, data *AnalyticsReportData) {
	// Section header
	m.AddRow(8, col.New(12).WithStyle(&props.Cell{
		BackgroundColor: headerBG,
	}).Add(text.New("1. Executive Summary", sectionHeaderProps())))

	m.AddRow(2)

	if data.Snapshot == nil {
		m.AddRow(6, text.NewCol(12, "No data available", props.Text{
			Size:  9,
			Align: align.Center,
			Color: &props.Color{Red: 150, Green: 150, Blue: 150},
			Top:   1,
		}))
		m.AddRow(4)
		return
	}

	s := data.Snapshot

	// Readiness and trend
	kv := func(label, value string) {
		m.AddRow(6,
			text.NewCol(4, label, labelTextProps()),
			text.NewCol(8, value, valueTextProps()),
		)
	}

	kv("Readiness:", fmt.Sprintf("%.1f%%", s.ReadinessPct))
	kv("Target:", fmt.Sprintf("%.1f%% by %d", s.TargetPct, s.DeadlineYear))
	kv("Trend:", fmt.Sprintf("%s (%.1f%%)", s.TrendDirection, s.TrendDeltaPct))
	kv("Projection:", projectionLabel(s))
	kv("Total Findings:", fmt.Sprintf("%d (Safe: %d)", s.TotalFindings, s.SafeFindings))
	kv("Systems:", fmt.Sprintf("Total: %d  |  Red: %d  |  Yellow: %d  |  Green: %d",
		s.MachinesTotal, s.MachinesRed, s.MachinesYellow, s.MachinesGreen))

	// Policy verdicts sub-section
	if len(s.PolicyVerdicts) > 0 {
		m.AddRow(3)
		m.AddRow(6, text.NewCol(12, "Policy Verdicts", props.Text{
			Style: fontstyle.Bold,
			Size:  9,
			Left:  2,
			Color: &props.Color{Red: 60, Green: 60, Blue: 60},
		}))

		for _, pv := range s.PolicyVerdicts {
			kv(pv.PolicyLabel+":", fmt.Sprintf("%s — %d violations / %d findings checked",
				pv.Verdict, pv.ViolationCount, pv.FindingsChecked))
		}
	}

	m.AddRow(4)
}

// projectionLabel formats the projection status string.
func projectionLabel(s *store.OrgSnapshot) string {
	switch s.ProjectionStatus {
	case "on-track":
		if s.ProjectedYear > 0 {
			return fmt.Sprintf("On-track — projected completion %d", s.ProjectedYear)
		}
		return "On-track"
	case "at-risk":
		return "At-risk"
	case "off-track":
		return "Off-track"
	default:
		if s.ProjectionStatus != "" {
			return s.ProjectionStatus
		}
		return "Unknown"
	}
}

// addRemediationSection adds Section 2: Remediation Progress.
func addRemediationSection(m core.Maroto, data *AnalyticsReportData) {
	m.AddRow(8, col.New(12).WithStyle(&props.Cell{
		BackgroundColor: headerBG,
	}).Add(text.New("2. Remediation Progress", sectionHeaderProps())))

	m.AddRow(2)

	if data.Remediation == nil {
		m.AddRow(6, text.NewCol(12, "No data available", props.Text{
			Size:  9,
			Align: align.Center,
			Color: &props.Color{Red: 150, Green: 150, Blue: 150},
			Top:   1,
		}))
		m.AddRow(4)
		return
	}

	r := data.Remediation
	summary := fmt.Sprintf(
		"Open: %d   |   In Progress: %d   |   Resolved: %d   |   Accepted: %d   |   Total: %d",
		r.Open, r.InProgress, r.Resolved, r.Accepted, r.Total,
	)
	m.AddRow(8, text.NewCol(12, summary, props.Text{
		Size:  9,
		Align: align.Center,
		Left:  2,
		Top:   2,
	}))

	m.AddRow(4)
}

// addCertificateUrgencySection adds Section 3: Certificate Urgency.
func addCertificateUrgencySection(m core.Maroto, data *AnalyticsReportData) {
	m.AddRow(8, col.New(12).WithStyle(&props.Cell{
		BackgroundColor: headerBG,
	}).Add(text.New("3. Certificate Urgency", sectionHeaderProps())))

	m.AddRow(2)

	if data.Snapshot == nil {
		m.AddRow(6, text.NewCol(12, "No data available", props.Text{
			Size:  9,
			Align: align.Center,
			Color: &props.Color{Red: 150, Green: 150, Blue: 150},
			Top:   1,
		}))
		m.AddRow(4)
		return
	}

	s := data.Snapshot
	summary := fmt.Sprintf(
		"Expired: %d   |   Expiring within 30 days: %d   |   Expiring within 90 days: %d",
		s.CertsExpired, s.CertsExpiring30d, s.CertsExpiring90d,
	)
	m.AddRow(8, text.NewCol(12, summary, props.Text{
		Size:  9,
		Align: align.Center,
		Left:  2,
		Top:   2,
	}))

	m.AddRow(4)
}

// addSystemsHealthSection adds Section 4: Systems Health table.
func addSystemsHealthSection(m core.Maroto, data *AnalyticsReportData) {
	m.AddRow(8, col.New(12).WithStyle(&props.Cell{
		BackgroundColor: headerBG,
	}).Add(text.New("4. Systems Health", sectionHeaderProps())))

	m.AddRow(2)

	if len(data.Hosts) == 0 {
		m.AddRow(6, text.NewCol(12, "No data available", props.Text{
			Size:  9,
			Align: align.Center,
			Color: &props.Color{Red: 150, Green: 150, Blue: 150},
			Top:   1,
		}))
		m.AddRow(4)
		return
	}

	// Table header row
	colHeaderBG := &props.Cell{BackgroundColor: &props.Color{Red: 70, Green: 100, Blue: 150}}
	hdr := tableHeaderProps()
	m.AddRow(7,
		col.New(4).WithStyle(colHeaderBG).Add(text.New("Hostname", hdr)),
		col.New(2).WithStyle(colHeaderBG).Add(text.New("Ready %", hdr)),
		col.New(2).WithStyle(colHeaderBG).Add(text.New("Unsafe", hdr)),
		col.New(2).WithStyle(colHeaderBG).Add(text.New("Deprecated", hdr)),
		col.New(2).WithStyle(colHeaderBG).Add(text.New("Trend", hdr)),
	)

	// Alternating row background
	evenBG := &props.Cell{BackgroundColor: &props.Color{Red: 240, Green: 244, Blue: 250}}
	cell := tableCellProps()

	for i := range data.Hosts {
		h := &data.Hosts[i]
		var rowStyle *props.Cell
		if i%2 == 0 {
			rowStyle = evenBG
		}

		if rowStyle != nil {
			m.AddRow(6,
				col.New(4).WithStyle(rowStyle).Add(text.New(h.Hostname, cell)),
				col.New(2).WithStyle(rowStyle).Add(text.New(fmt.Sprintf("%.1f%%", h.ReadinessPct), cell)),
				col.New(2).WithStyle(rowStyle).Add(text.New(fmt.Sprintf("%d", h.UnsafeFindings), cell)),
				col.New(2).WithStyle(rowStyle).Add(text.New(fmt.Sprintf("%d", h.DeprecatedFindings), cell)),
				col.New(2).WithStyle(rowStyle).Add(text.New(h.TrendDirection, cell)),
			)
		} else {
			m.AddRow(6,
				text.NewCol(4, h.Hostname, cell),
				text.NewCol(2, fmt.Sprintf("%.1f%%", h.ReadinessPct), cell),
				text.NewCol(2, fmt.Sprintf("%d", h.UnsafeFindings), cell),
				text.NewCol(2, fmt.Sprintf("%d", h.DeprecatedFindings), cell),
				text.NewCol(2, h.TrendDirection, cell),
			)
		}
	}

	m.AddRow(4)
}

// addTopBlockersSection adds Section 5: Top Blockers table.
func addTopBlockersSection(m core.Maroto, data *AnalyticsReportData) {
	m.AddRow(8, col.New(12).WithStyle(&props.Cell{
		BackgroundColor: headerBG,
	}).Add(text.New("5. Top Blockers", sectionHeaderProps())))

	m.AddRow(2)

	var blockers []store.PriorityRow
	if data.Snapshot != nil {
		blockers = data.Snapshot.TopBlockers
	}

	if len(blockers) == 0 {
		m.AddRow(6, text.NewCol(12, "No data available", props.Text{
			Size:  9,
			Align: align.Center,
			Color: &props.Color{Red: 150, Green: 150, Blue: 150},
			Top:   1,
		}))
		m.AddRow(4)
		return
	}

	// Table header
	colHeaderBG := &props.Cell{BackgroundColor: &props.Color{Red: 70, Green: 100, Blue: 150}}
	hdr := tableHeaderProps()
	m.AddRow(7,
		col.New(4).WithStyle(colHeaderBG).Add(text.New("Hostname", hdr)),
		col.New(4).WithStyle(colHeaderBG).Add(text.New("Algorithm", hdr)),
		col.New(2).WithStyle(colHeaderBG).Add(text.New("Priority", hdr)),
		col.New(2).WithStyle(colHeaderBG).Add(text.New("PQC Status", hdr)),
	)

	evenBG := &props.Cell{BackgroundColor: &props.Color{Red: 240, Green: 244, Blue: 250}}
	cell := tableCellProps()

	for i, b := range blockers {
		var rowStyle *props.Cell
		if i%2 == 0 {
			rowStyle = evenBG
		}

		if rowStyle != nil {
			m.AddRow(6,
				col.New(4).WithStyle(rowStyle).Add(text.New(b.Hostname, cell)),
				col.New(4).WithStyle(rowStyle).Add(text.New(b.Algorithm, cell)),
				col.New(2).WithStyle(rowStyle).Add(text.New(fmt.Sprintf("%d", b.Priority), cell)),
				col.New(2).WithStyle(rowStyle).Add(text.New(b.PQCStatus, cell)),
			)
		} else {
			m.AddRow(6,
				text.NewCol(4, b.Hostname, cell),
				text.NewCol(4, b.Algorithm, cell),
				text.NewCol(2, fmt.Sprintf("%d", b.Priority), cell),
				text.NewCol(2, b.PQCStatus, cell),
			)
		}
	}

	m.AddRow(4)
}
