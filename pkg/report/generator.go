package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
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

	reports := []reportFunc{
		{"JSON", jsonFile, func() error { return g.GenerateTritonJSON(result, jsonFile) }},
		{"CycloneDX", cdxFile, func() error { return g.GenerateCycloneDXBOM(result, cdxFile) }},
		{"HTML", htmlFile, func() error { return g.GenerateHTML(result, htmlFile) }},
		{"Excel", excelFile, func() error { return g.GenerateExcel(result, excelFile) }},
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

	return os.WriteFile(filename, data, 0o644)
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
	</style>
</head>
<body>
`)

	// Title and metadata
	scanTime := result.Metadata.Timestamp
	if scanTime.IsZero() {
		scanTime = time.Now()
	}
	b.WriteString(fmt.Sprintf(`	<h1>Triton CBOM Report</h1>
	<p class="meta">Scan: %s | Generated: %s</p>
`, scanTime.Format("2006-01-02 15:04:05"), time.Now().Format("2006-01-02 15:04:05")))

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
	cbomNum := 1
	for i := range result.Systems {
		sys := &result.Systems[i]
		for j := range sys.CryptoAssets {
			asset := &sys.CryptoAssets[j]
			statusClass := "status-" + html.EscapeString(asset.PQCStatus)
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
`, cbomNum, html.EscapeString(sys.Name),
				html.EscapeString(asset.Algorithm),
				html.EscapeString(crypto.FormatKeySize(asset.KeySize)),
				html.EscapeString(asset.Purpose),
				statusClass, html.EscapeString(asset.PQCStatus),
				html.EscapeString(asset.CNSA2Status),
				html.EscapeString(asset.ComplianceWarning)))
			cbomNum++
		}
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

	return os.WriteFile(filename, []byte(b.String()), 0o644)
}
