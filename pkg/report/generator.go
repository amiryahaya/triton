package report

import (
	"encoding/json"
	"fmt"
	"html"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// Generator creates reports in various formats
type Generator struct {
	outputDir string
}

func New(outputDir string) *Generator {
	return &Generator{outputDir: outputDir}
}

// GenerateAllReports produces the full set of government-format reports.
// The timestamp string is embedded in each filename.
// Returns a list of generated file paths.
func (g *Generator) GenerateAllReports(result *model.ScanResult, timestamp string) ([]string, error) {
	dir := g.outputDir
	if dir == "" {
		dir = "."
	}

	type reportFunc struct {
		name     string
		filename string
		gen      func() error
	}

	jsonFile := filepath.Join(dir, fmt.Sprintf("triton-report-%s.json", timestamp))
	htmlFile := filepath.Join(dir, fmt.Sprintf("triton-report-%s.html", timestamp))
	excelFile := filepath.Join(dir, fmt.Sprintf("Triton_PQC_Report-%s.xlsx", timestamp))
	cdxFile := filepath.Join(dir, fmt.Sprintf("triton-report-%s.cdx.json", timestamp))
	sarifFile := filepath.Join(dir, fmt.Sprintf("triton-report-%s.sarif", timestamp))

	reports := []reportFunc{
		{"JSON", jsonFile, func() error { return g.GenerateTritonJSON(result, jsonFile) }},
		{"CycloneDX", cdxFile, func() error { return g.GenerateCycloneDXBOM(result, cdxFile) }},
		{"HTML", htmlFile, func() error { return g.GenerateHTML(result, htmlFile) }},
		{"Excel", excelFile, func() error { return g.GenerateExcel(result, excelFile) }},
		{"SARIF", sarifFile, func() error { return g.GenerateSARIF(result, sarifFile) }},
	}

	files := make([]string, 0, len(reports))
	for _, r := range reports {
		if err := r.gen(); err != nil {
			return files, fmt.Errorf("generating %s: %w", r.name, err)
		}
		files = append(files, r.filename)
	}

	return files, nil
}

// GenerateTritonJSON outputs scan results in Triton's proprietary JSON format.
// This is the legacy format — use GenerateCycloneDXBOM for proper CycloneDX 1.7.
func (g *Generator) GenerateTritonJSON(result *model.ScanResult, filename string) error {
	report := struct {
		GeneratedAt string            `json:"generatedAt"`
		Result      *model.ScanResult `json:"result"`
	}{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Result:      result,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0o600)
}

// GenerateHTML creates an HTML report with PQC dashboard, systems table, and CBOM detail.
func (g *Generator) GenerateHTML(result *model.ScanResult, filename string) error {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html>
<head>
	<title>Triton CBOM Report</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
		h1 { color: #1a237e; }
		h2 { color: #283593; margin-top: 30px; }
		.summary { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
		.card { padding: 20px; border-radius: 8px; min-width: 150px; text-align: center; }
		.card h3 { margin: 0 0 8px 0; font-size: 2em; }
		.card p { margin: 0; font-size: 0.9em; }
		.safe { background: #e8f5e9; color: #2e7d32; }
		.transitional { background: #fff3e0; color: #e65100; }
		.deprecated { background: #fce4ec; color: #c62828; }
		.unsafe { background: #ffebee; color: #b71c1c; }
		.info { background: #e3f2fd; color: #1565c0; }
		table { border-collapse: collapse; width: 100%; margin-top: 15px; }
		th, td { border: 1px solid #ddd; padding: 10px; text-align: left; font-size: 0.9em; }
		th { background-color: #1a237e; color: white; }
		tr:nth-child(even) { background-color: #f5f5f5; }
		.status-SAFE { color: #2e7d32; font-weight: bold; }
		.status-TRANSITIONAL { color: #e65100; font-weight: bold; }
		.status-DEPRECATED { color: #c62828; font-weight: bold; }
		.status-UNSAFE { color: #b71c1c; font-weight: bold; }
		.meta { color: #666; font-size: 0.9em; }
		.chart-section { display: flex; gap: 40px; align-items: flex-start; flex-wrap: wrap; margin: 20px 0; }
		.chart-legend { display: flex; flex-direction: column; gap: 6px; font-size: 0.9em; margin-top: 8px; }
		.legend-dot { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
	</style>
</head>
<body>
`)

	// Title and metadata
	scanTime := result.Metadata.Timestamp
	if scanTime.IsZero() {
		scanTime = time.Now()
	}
	profile := result.Metadata.ScanProfile
	if profile == "" {
		profile = "unknown"
	}
	b.WriteString(fmt.Sprintf(`	<h1>Triton CBOM Report</h1>
	<p class="meta">Profile: %s | Scan: %s | Generated: %s</p>
`, html.EscapeString(profile), scanTime.Format("2006-01-02 15:04:05"), time.Now().Format("2006-01-02 15:04:05")))

	// PQC Summary Cards
	b.WriteString(`	<h2>PQC Summary</h2>
	<div class="summary">
`)
	b.WriteString(fmt.Sprintf(`		<div class="card info"><h3>%d</h3><p>Total Systems</p></div>
`, result.Summary.TotalSystems))
	b.WriteString(fmt.Sprintf(`		<div class="card info"><h3>%d</h3><p>Crypto Assets</p></div>
`, result.Summary.TotalCryptoAssets))
	b.WriteString(fmt.Sprintf(`		<div class="card safe"><h3>%d</h3><p>Safe</p></div>
`, result.Summary.Safe))
	b.WriteString(fmt.Sprintf(`		<div class="card transitional"><h3>%d</h3><p>Transitional</p></div>
`, result.Summary.Transitional))
	b.WriteString(fmt.Sprintf(`		<div class="card deprecated"><h3>%d</h3><p>Deprecated</p></div>
`, result.Summary.Deprecated))
	b.WriteString(fmt.Sprintf(`		<div class="card unsafe"><h3>%d</h3><p>Unsafe</p></div>
`, result.Summary.Unsafe))
	b.WriteString(`	</div>
`)

	// PQC Donut Chart
	if chart := svgDonutChart(result.Summary.Safe, result.Summary.Transitional, result.Summary.Deprecated, result.Summary.Unsafe); chart != "" {
		b.WriteString(`	<div class="chart-section">
`)
		b.WriteString(chart)
		b.WriteString(`	</div>
`)
	}

	// Systems Table (Jadual 1 summary)
	b.WriteString(`	<h2>Systems Inventory</h2>
	<table>
		<tr>
			<th>#</th>
			<th>System / Application</th>
			<th>Critical Level</th>
			<th>Crypto Assets</th>
			<th>Link to CBOM</th>
		</tr>
`)
	for i := range result.Systems {
		sys := &result.Systems[i]
		cbomLink := strings.Join(sys.CBOMRefs, ", ")
		b.WriteString(fmt.Sprintf(`		<tr>
			<td>%d</td>
			<td>%s</td>
			<td>%s</td>
			<td>%d</td>
			<td>%s</td>
		</tr>
`, i+1, html.EscapeString(sys.Name), html.EscapeString(sys.CriticalityLevel),
			len(sys.CryptoAssets), html.EscapeString(cbomLink)))
	}
	b.WriteString(`	</table>
`)

	// CBOM Detail Table (Jadual 2 summary)
	b.WriteString(`	<h2>Cryptographic Assets (CBOM)</h2>
	<table>
		<tr>
			<th># (CBOM)</th>
			<th>System / Application</th>
			<th>Algorithm Used</th>
			<th>Key Length</th>
			<th>Purpose / Usage</th>
			<th>PQC Status</th>
			<th>CNSA 2.0</th>
			<th>Compliance</th>
		</tr>
`)
	// Flatten and sort CBOM rows by severity (UNSAFE first, SAFE last)
	var rows []cbomRow
	for i := range result.Systems {
		sys := &result.Systems[i]
		for j := range sys.CryptoAssets {
			rows = append(rows, cbomRow{systemName: sys.Name, asset: &sys.CryptoAssets[j]})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return pqcSortOrder(rows[i].asset.PQCStatus) < pqcSortOrder(rows[j].asset.PQCStatus)
	})

	for i, row := range rows {
		statusClass := "status-" + html.EscapeString(row.asset.PQCStatus)
		b.WriteString(fmt.Sprintf(`		<tr>
			<td>CBOM #%d</td>
			<td>%s</td>
			<td>%s</td>
			<td>%s</td>
			<td>%s</td>
			<td class="%s">%s</td>
			<td>%s</td>
			<td>%s</td>
		</tr>
`, i+1, html.EscapeString(row.systemName),
			html.EscapeString(row.asset.Algorithm),
			html.EscapeString(crypto.FormatKeySize(row.asset.KeySize)),
			html.EscapeString(row.asset.Purpose),
			statusClass, html.EscapeString(row.asset.PQCStatus),
			html.EscapeString(row.asset.CNSA2Status),
			html.EscapeString(row.asset.ComplianceWarning)))
	}
	b.WriteString(`	</table>
`)

	// NACSA Compliance Summary
	nacsa := crypto.ComputeNACSASummary(result.Systems)
	camm := crypto.AssessCAMM(result.Systems, result.Findings)

	b.WriteString(`	<h2>NACSA Compliance Summary</h2>
	<div class="summary">
`)
	b.WriteString(fmt.Sprintf(`		<div class="card safe"><h3>%.0f%%</h3><p>NACSA Readiness</p></div>
`, nacsa.ReadinessPercent))
	b.WriteString(fmt.Sprintf(`		<div class="card safe"><h3>%d</h3><p>Patuh</p></div>
`, nacsa.Patuh))
	b.WriteString(fmt.Sprintf(`		<div class="card transitional"><h3>%d</h3><p>Dalam Peralihan</p></div>
`, nacsa.DalamPeralihan))
	b.WriteString(fmt.Sprintf(`		<div class="card deprecated"><h3>%d</h3><p>Tidak Patuh</p></div>
`, nacsa.TidakPatuh))
	b.WriteString(fmt.Sprintf(`		<div class="card unsafe"><h3>%d</h3><p>Tindakan Segera</p></div>
`, nacsa.TindakanSegera))
	b.WriteString(fmt.Sprintf(`		<div class="card info"><h3>%d</h3><p>CNSA 2.0 Compliant</p></div>
`, nacsa.CNSA2Compliant))
	b.WriteString(`	</div>
`)

	// NACSA Bar Chart
	if barChart := svgBarChart(
		[]string{"Patuh", "Dalam Peralihan", "Tidak Patuh", "Tindakan Segera"},
		[]int{nacsa.Patuh, nacsa.DalamPeralihan, nacsa.TidakPatuh, nacsa.TindakanSegera},
		[]string{"#2e7d32", "#e65100", "#c62828", "#b71c1c"},
	); barChart != "" {
		b.WriteString(`	<div class="chart-section">
`)
		b.WriteString(barChart)
		b.WriteString(`	</div>
`)
	}

	// CAMM Assessment
	b.WriteString(fmt.Sprintf(`	<h2>CAMM Crypto-Agility Assessment</h2>
	<p><strong>%s</strong> (%s)</p>
`, html.EscapeString(crypto.CAMMLevelLabel(camm.Level)), html.EscapeString(camm.Confidence)))

	if len(camm.Indicators) > 0 {
		b.WriteString(`	<h3>Indicators Met</h3>
	<ul>
`)
		for _, ind := range camm.Indicators {
			b.WriteString(fmt.Sprintf(`		<li>%s</li>
`, html.EscapeString(ind)))
		}
		b.WriteString(`	</ul>
`)
	}

	if len(camm.Manual) > 0 {
		b.WriteString(`	<h3>Manual Assessment Required</h3>
	<ul>
`)
		for _, m := range camm.Manual {
			b.WriteString(fmt.Sprintf(`		<li>%s</li>
`, html.EscapeString(m)))
		}
		b.WriteString(`	</ul>
`)
	}

	b.WriteString(`</body>
</html>`)

	return os.WriteFile(filename, []byte(b.String()), 0o600)
}

// pqcSortOrder returns a numeric priority for PQC status (lower = more severe).
func pqcSortOrder(status string) int {
	switch strings.ToUpper(status) {
	case "UNSAFE":
		return 0
	case "DEPRECATED":
		return 1
	case "TRANSITIONAL":
		return 2
	case "SAFE":
		return 3
	default:
		return 4
	}
}

// cbomRow is a flattened CBOM entry for sorting.
type cbomRow struct {
	systemName string
	asset      *model.CryptoAsset
}

// svgDonutChart renders an inline SVG donut chart for PQC status breakdown.
func svgDonutChart(safe, transitional, deprecated, unsafe int) string {
	total := safe + transitional + deprecated + unsafe
	if total == 0 {
		return ""
	}

	type segment struct {
		count int
		color string
		label string
	}
	segments := []segment{
		{safe, "#2e7d32", "Safe"},
		{transitional, "#e65100", "Transitional"},
		{deprecated, "#c62828", "Deprecated"},
		{unsafe, "#b71c1c", "Unsafe"},
	}

	const (
		r       = 70.0
		strokeW = 35.0
		circumf = 2 * math.Pi * r
		cx, cy  = 100.0, 100.0
	)

	var b strings.Builder
	b.WriteString(`<div style="text-align:center">`)
	b.WriteString(fmt.Sprintf(`<svg width="200" height="200" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
<circle cx="%.0f" cy="%.0f" r="%.0f" fill="none" stroke="#eee" stroke-width="%.0f"/>
`, cx, cy, r, strokeW))

	offset := 0.0
	for _, seg := range segments {
		if seg.count == 0 {
			continue
		}
		frac := float64(seg.count) / float64(total)
		dashLen := frac * circumf
		gapLen := circumf - dashLen
		b.WriteString(fmt.Sprintf(
			`<circle cx="%.0f" cy="%.0f" r="%.0f" fill="none" stroke="%s" stroke-width="%.0f" stroke-dasharray="%.1f %.1f" stroke-dashoffset="%.1f" transform="rotate(-90 %.0f %.0f)"/>
`,
			cx, cy, r, seg.color, strokeW, dashLen, gapLen, -offset, cx, cy))
		offset += dashLen
	}

	b.WriteString(fmt.Sprintf(
		`<text x="%.0f" y="%.0f" text-anchor="middle" dominant-baseline="central" font-size="28" font-weight="bold" fill="#333">%d</text>
`, cx, cy, total))
	b.WriteString(`</svg>
`)

	// Legend
	b.WriteString(`<div class="chart-legend">`)
	for _, seg := range segments {
		if seg.count == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf(
			`<div><span class="legend-dot" style="background:%s"></span>%s: %d</div>
`, seg.color, seg.label, seg.count))
	}
	b.WriteString(`</div></div>`)
	return b.String()
}

// svgBarChart renders an inline SVG horizontal stacked bar chart.
func svgBarChart(labels []string, values []int, colors []string) string {
	total := 0
	for _, v := range values {
		total += v
	}
	if total == 0 {
		return ""
	}

	const (
		width  = 500.0
		barH   = 30.0
		barY   = 10.0
		svgH   = 80.0
		radius = 4.0
	)

	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<svg width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f" xmlns="http://www.w3.org/2000/svg">
`, width, svgH, width, svgH))

	// Background bar
	b.WriteString(fmt.Sprintf(`<rect x="0" y="%.0f" width="%.0f" height="%.0f" rx="%.0f" fill="#eee"/>
`, barY, width, barH, radius))

	x := 0.0
	for i, v := range values {
		if v == 0 {
			continue
		}
		segW := float64(v) / float64(total) * width
		color := "#999"
		if i < len(colors) {
			color = colors[i]
		}
		// Use clip-path for rounded ends on first/last segments
		b.WriteString(fmt.Sprintf(`<rect x="%.1f" y="%.0f" width="%.1f" height="%.0f" fill="%s"/>
`, x, barY, segW, barH, color))
		x += segW
	}

	// Rounded overlay
	b.WriteString(fmt.Sprintf(`<rect x="0" y="%.0f" width="%.0f" height="%.0f" rx="%.0f" fill="none" stroke="#ddd" stroke-width="1"/>
`, barY, width, barH, radius))

	// Labels below
	x = 0.0
	for i, v := range values {
		if v == 0 {
			continue
		}
		segW := float64(v) / float64(total) * width
		pct := float64(v) / float64(total) * 100
		label := ""
		if i < len(labels) {
			label = labels[i]
		}
		midX := x + segW/2
		b.WriteString(fmt.Sprintf(
			`<text x="%.1f" y="%.0f" text-anchor="middle" font-size="10" fill="#333">%s (%.0f%%)</text>
`, midX, barY+barH+16, label, pct))
		x += segW
	}

	b.WriteString(`</svg>`)
	return b.String()
}
