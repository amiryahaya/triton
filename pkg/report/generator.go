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
// Returns a list of generated file paths.
func (g *Generator) GenerateAllReports(result *model.ScanResult) ([]string, error) {
	dir := g.outputDir
	if dir == "" {
		dir = "."
	}

	type reportFunc struct {
		name     string
		filename string
		gen      func() error
	}

	jsonFile := filepath.Join(dir, "triton-report.json")
	htmlFile := filepath.Join(dir, "triton-report.html")
	excelFile := filepath.Join(dir, "Triton_PQC_Report.xlsx")

	reports := []reportFunc{
		{"JSON", jsonFile, func() error { return g.GenerateCycloneDX(result, jsonFile) }},
		{"HTML", htmlFile, func() error { return g.GenerateHTML(result, htmlFile) }},
		{"Excel", excelFile, func() error { return g.GenerateExcel(result, excelFile) }},
	}

	var files []string
	for _, r := range reports {
		if err := r.gen(); err != nil {
			return files, fmt.Errorf("generating %s: %w", r.name, err)
		}
		files = append(files, r.filename)
	}

	return files, nil
}

// GenerateCycloneDX outputs scan results in JSON format
func (g *Generator) GenerateCycloneDX(result *model.ScanResult, filename string) error {
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

	return os.WriteFile(filename, data, 0644)
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
	b.WriteString(fmt.Sprintf(`	<h1>Triton CBOM Report</h1>
	<p class="meta">Generated: %s</p>
`, time.Now().Format("2006-01-02 15:04:05")))

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
	for i, sys := range result.Systems {
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
		</tr>
`)
	cbomNum := 1
	for _, sys := range result.Systems {
		for _, asset := range sys.CryptoAssets {
			statusClass := "status-" + html.EscapeString(asset.PQCStatus)
			b.WriteString(fmt.Sprintf(`		<tr>
			<td>CBOM #%d</td>
			<td>%s</td>
			<td>%s</td>
			<td>%s</td>
			<td>%s</td>
			<td class="%s">%s</td>
		</tr>
`, cbomNum, html.EscapeString(sys.Name),
				html.EscapeString(asset.Algorithm),
				html.EscapeString(crypto.FormatKeySize(asset.KeySize)),
				html.EscapeString(asset.Purpose),
				statusClass, html.EscapeString(asset.PQCStatus)))
			cbomNum++
		}
	}
	b.WriteString(`	</table>
`)

	b.WriteString(`</body>
</html>`)

	return os.WriteFile(filename, []byte(b.String()), 0644)
}

