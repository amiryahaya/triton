package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// Generator creates reports in various formats
type Generator struct {
	outputDir string
}

func New(outputDir string) *Generator {
	return &Generator{outputDir: outputDir}
}

// GenerateCycloneDX outputs SBOM/CBOM in CycloneDX JSON format
func (g *Generator) GenerateCycloneDX(sbom *model.SBOM, cbom *model.CBOM, filename string) error {
	// For MVP, we'll output a combined report
	report := struct {
		GeneratedAt string              `json:"generatedAt"`
		SBOM        *model.SBOM         `json:"sbom"`
		CBOM        *model.CBOM         `json:"cbom"`
		Summary     map[string]interface{} `json:"summary"`
	}{
		GeneratedAt: time.Now().Format(time.RFC3339),
		SBOM:        sbom,
		CBOM:        cbom,
		Summary:     g.generateSummary(cbom),
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// GenerateCSV creates a CSV report matching the Malaysian government format
func (g *Generator) GenerateCSV(findings []*model.Finding, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write headers matching the sample format
	headers := []string{
		"No.",
		"Sistem / Aplikasi",
		"Tujuan/Penggunaan",
		"Komponen Perisian",
		"Algoritma",
		"Panjang Kunci",
		"Aras Kritikal",
		"PQC Status",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Write findings
	for i, f := range findings {
		if f.CryptoAsset == nil {
			continue
		}

		record := []string{
			fmt.Sprintf("%d", i+1),
			f.Path,
			f.Type,
			f.CryptoAsset.Type,
			f.CryptoAsset.Algorithm,
			fmt.Sprintf("%d", f.CryptoAsset.KeySize),
			g.classifyCriticality(f),
			f.CryptoAsset.PQCStatus,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// GenerateHTML creates an HTML report for presentation
func (g *Generator) GenerateHTML(findings []*model.Finding, filename string) error {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>Triton CBOM Report</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; }
		h1 { color: #333; }
		table { border-collapse: collapse; width: 100%%; margin-top: 20px; }
		th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
		th { background-color: #4CAF50; color: white; }
		tr:nth-child(even) { background-color: #f2f2f2; }
		.SAFE { color: green; font-weight: bold; }
		.TRANSITIONAL { color: orange; font-weight: bold; }
		.DEPRECATED { color: red; font-weight: bold; }
		.UNSAFE { color: darkred; font-weight: bold; }
	</style>
</head>
<body>
	<h1>🔍 Triton Cryptographic Inventory Report</h1>
	<p>Generated: %s</p>
	
	<table>
		<tr>
			<th>No.</th>
			<th>Path</th>
			<th>Type</th>
			<th>Algorithm</th>
			<th>Key Size</th>
			<th>PQC Status</th>
		</tr>
`, time.Now().Format("2006-01-02 15:04:05"))

	for i, f := range findings {
		if f.CryptoAsset == nil {
			continue
		}
		html += fmt.Sprintf(`
		<tr>
			<td>%d</td>
			<td>%s</td>
			<td>%s</td>
			<td>%s</td>
			<td>%d</td>
			<td class="%s">%s</td>
		</tr>
`, i+1, f.Path, f.CryptoAsset.Type, f.CryptoAsset.Algorithm, 
   f.CryptoAsset.KeySize, f.CryptoAsset.PQCStatus, f.CryptoAsset.PQCStatus)
	}

	html += `
	</table>
</body>
</html>`

	return os.WriteFile(filename, []byte(html), 0644)
}

func (g *Generator) generateSummary(cbom *model.CBOM) map[string]interface{} {
	summary := map[string]interface{}{
		"totalAssets":   len(cbom.CryptoAssets),
		"safe":          0,
		"transitional":  0,
		"deprecated":    0,
		"unsafe":        0,
		"certificates":  0,
		"keys":          0,
	}

	for _, asset := range cbom.CryptoAssets {
		switch asset.PQCStatus {
		case "SAFE":
			summary["safe"] = summary["safe"].(int) + 1
		case "TRANSITIONAL":
			summary["transitional"] = summary["transitional"].(int) + 1
		case "DEPRECATED":
			summary["deprecated"] = summary["deprecated"].(int) + 1
		case "UNSAFE":
			summary["unsafe"] = summary["unsafe"].(int) + 1
		}

		if asset.Type == "certificate" {
			summary["certificates"] = summary["certificates"].(int) + 1
		}
		if asset.Type == "key" {
			summary["keys"] = summary["keys"].(int) + 1
		}
	}

	return summary
}

func (g *Generator) classifyCriticality(f *model.Finding) string {
	if f.CryptoAsset == nil {
		return "Rendah"
	}

	switch f.CryptoAsset.PQCStatus {
	case "UNSAFE":
		return "Tinggi"
	case "DEPRECATED":
		return "Tinggi"
	case "TRANSITIONAL":
		return "Sederhana"
	default:
		return "Rendah"
	}
}
