package report

import (
	"fmt"
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// clearRange defines a row range to clear in a sheet.
type clearRange struct {
	sheet    string
	startRow int
	endRow   int
	maxCol   int
}

// exampleRanges defines per-sheet example row ranges to clear.
var exampleRanges = []clearRange{
	{"0_Inventory", 5, 14, 9},
	{"1_SBOM", 5, 12, 17},
	{"2_CBOM", 5, 12, 12},
	{"3_RiskRegister", 5, 8, 8},
	{"4_RiskAssessment", 5, 8, 11},
}

// dataRowRanges defines pre-filled data rows in the template to clear.
var dataRowRanges = []clearRange{
	{"0_Inventory", 17, 30, 9},
	{"1_SBOM", 15, 30, 17},
	{"2_CBOM", 15, 30, 12},
	{"3_RiskRegister", 10, 30, 8},
	{"4_RiskAssessment", 11, 30, 11},
}

// GenerateExcel creates a single .xlsx report by populating the embedded
// government PQC template with scan results.
func (g *Generator) GenerateExcel(result *model.ScanResult, filename string) error {
	if err := copyTemplate(filename); err != nil {
		return fmt.Errorf("copying template: %w", err)
	}

	f, err := excelize.OpenFile(filename)
	if err != nil {
		return fmt.Errorf("opening template: %w", err)
	}
	defer f.Close()

	clearExampleRows(f)

	populateInventory(f, result.Systems)
	populateSBOM(f, result.Systems)
	populateCBOM(f, result.Systems)
	populateRiskRegister(f, result.Systems)
	populateRiskAssessment(f, result.Systems)
	populateComplianceSummary(f, result)

	return f.Save()
}

// clearExampleRows removes the EXAMPLE data, unmerges cells within the
// example range, and clears pre-filled data rows in all data sheets.
func clearExampleRows(f *excelize.File) {
	for _, er := range exampleRanges {
		// Unmerge only merged cells that fall within the example row range
		mc, _ := f.GetMergeCells(er.sheet)
		for _, m := range mc {
			start := m.GetStartAxis()
			end := m.GetEndAxis()
			_, startRow, _ := excelize.CellNameToCoordinates(start)
			_, endRow, _ := excelize.CellNameToCoordinates(end)
			if startRow >= er.startRow && endRow <= er.endRow {
				_ = f.UnmergeCell(er.sheet, start, end)
			}
		}

		clearCells(f, er)
	}

	// Clear pre-filled data rows (row numbers like "1", "2", "CBOM #1", etc.)
	for _, dr := range dataRowRanges {
		clearCells(f, dr)
	}
}

// clearCells blanks every cell in the given range.
func clearCells(f *excelize.File, cr clearRange) {
	for row := cr.startRow; row <= cr.endRow; row++ {
		for col := 1; col <= cr.maxCol; col++ {
			cell, _ := excelize.CoordinatesToCellName(col, row)
			_ = f.SetCellValue(cr.sheet, cell, "")
		}
	}
}

// populateInventory fills sheet "0_Inventory" starting at row 17.
// Columns: #, Asset Type, Asset Name, Location/Owner, Crypto Present?, Algorithms, SBOM/CBOM, Readiness, Notes
func populateInventory(f *excelize.File, systems []model.System) {
	const sheet = "0_Inventory"
	const startRow = 17

	for i := range systems {
		row := startRow + i

		algorithms := collectAlgorithms(systems[i])
		assetType := deriveAssetType(systems[i])
		readiness := deriveReadiness(systems[i])

		vals := []interface{}{
			fmt.Sprintf("%d", i+1), // A: #
			assetType,              // B: Asset Type
			systems[i].Name,        // C: Asset Name
			systems[i].Vendor,      // D: Location / Owner
			"Yes",                  // E: Crypto Present?
			algorithms,             // F: Algorithms Used
			"CBOM",                 // G: SBOM/CBOM Available?
			readiness,              // H: Migration Readiness Level
			"",                     // I: Notes
		}

		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, row)
			_ = f.SetCellValue(sheet, cell, v)
		}
	}
}

// populateSBOM fills sheet "1_SBOM" starting at row 15.
// 17 columns matching the government Jadual 1 format.
func populateSBOM(f *excelize.File, systems []model.System) {
	const sheet = "1_SBOM"
	const startRow = 15

	for i := range systems {
		row := startRow + i

		inUse := "Tidak"
		if systems[i].InUse {
			inUse = "Ya"
		}

		cbomLink := strings.Join(systems[i].CBOMRefs, ", ")

		vals := []interface{}{
			fmt.Sprintf("%d", i+1),                           // A: #
			systems[i].Name,                                  // B: System / Application
			systems[i].Purpose,                               // C: Purpose / Usage
			systems[i].URL,                                   // D: URL
			systems[i].ServiceMode,                           // E: Services Mode
			systems[i].TargetCustomer,                        // F: Target Customer
			strings.Join(systems[i].Components, ", "),        // G: Software Component
			strings.Join(systems[i].ThirdPartyModules, ", "), // H: Third-party Modules
			strings.Join(systems[i].ExternalAPIs, ", "),      // I: External APIs
			systems[i].CriticalityLevel,                      // J: Critical Level
			systems[i].DataCategory,                          // K: Data Category
			inUse,                                            // L: In Use?
			systems[i].Developer,                             // M: Developer
			systems[i].Vendor,                                // N: Vendor
			"",                                               // O: Has expertise?
			"",                                               // P: Has budget?
			cbomLink,                                         // Q: Link to CBOM
		}

		for col, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(col+1, row)
			_ = f.SetCellValue(sheet, cell, v)
		}
	}
}

// populateCBOM fills sheet "2_CBOM" starting at row 15.
// One row per crypto asset across all systems.
func populateCBOM(f *excelize.File, systems []model.System) {
	const sheet = "2_CBOM"
	const startRow = 15

	cbomNum := 1
	for i := range systems {
		for j := range systems[i].CryptoAssets {
			row := startRow + cbomNum - 1
			asset := &systems[i].CryptoAssets[j]

			vals := []interface{}{
				fmt.Sprintf("CBOM #%d", cbomNum),    // A: # (CBOM)
				systems[i].Name,                     // B: System / Application
				asset.Function,                      // C: Cryptographic Function
				asset.Algorithm,                     // D: Algorithm Used
				asset.Library,                       // E: Library / Module
				crypto.FormatKeySize(asset.KeySize), // F: Key Length
				asset.Purpose,                       // G: Purpose / Usage
				asset.CryptoAgility,                 // H: Crypto-Agility Support
				asset.PQCStatus,                     // I: PQC Status
				asset.CNSA2Status,                   // J: CNSA 2.0
				asset.ComplianceWarning,             // K: Compliance Warning
				asset.NACSALabel,                    // L: NACSA Status
			}

			for col, v := range vals {
				cell, _ := excelize.CoordinatesToCellName(col+1, row)
				_ = f.SetCellValue(sheet, cell, v)
			}
			cbomNum++
		}
	}
}

// populateRiskRegister fills sheet "3_RiskRegister" starting at row 10.
// One row per crypto asset.
func populateRiskRegister(f *excelize.File, systems []model.System) {
	const sheet = "3_RiskRegister"
	const startRow = 10

	rowNum := 1
	for i := range systems {
		for j := range systems[i].CryptoAssets {
			row := startRow + rowNum - 1
			asset := &systems[i].CryptoAssets[j]

			vals := []interface{}{
				fmt.Sprintf("%d", rowNum),   // A: #
				systems[i].Name,             // B: System Name
				classifyAssetType(*asset),   // C: Type of Asset
				asset.Algorithm,             // D: Cryptographic Algorithm
				asset.Function,              // E: Algorithm Usage
				systems[i].CriticalityLevel, // F: Criticality
				assessRisk(*asset),          // G: Risk
				"",                          // H: Risk Owner
			}

			for col, v := range vals {
				cell, _ := excelize.CoordinatesToCellName(col+1, row)
				_ = f.SetCellValue(sheet, cell, v)
			}
			rowNum++
		}
	}
}

// populateRiskAssessment fills sheet "4_RiskAssessment" starting at row 11.
// One row per crypto asset with computed risk scores.
func populateRiskAssessment(f *excelize.File, systems []model.System) {
	const sheet = "4_RiskAssessment"
	const startRow = 11

	rowNum := 1
	for i := range systems {
		for j := range systems[i].CryptoAssets {
			row := startRow + rowNum - 1
			asset := &systems[i].CryptoAssets[j]

			impact := assessImpact(systems[i].CriticalityLevel)
			likelihood := assessLikelihood(asset.PQCStatus)
			score := impact * likelihood

			vals := []interface{}{
				fmt.Sprintf("%d", rowNum), // A: #
				systems[i].Name,           // B: Nama Sistem
				asset.Algorithm,           // C: Algoritma Kriptografi
				assessRisk(*asset),        // D: Risiko
				riskSource(*asset),        // E: Punca Risiko
				impact,                    // F: Impak
				likelihood,                // G: Kemungkinan
				score,                     // H: Skor Risiko
				riskLevel(score),          // I: Risk Level
				asset.CNSA2Status,         // J: CNSA 2.0 Status
				asset.ComplianceWarning,   // K: Compliance Note
			}

			for col, v := range vals {
				cell, _ := excelize.CoordinatesToCellName(col+1, row)
				_ = f.SetCellValue(sheet, cell, v)
			}
			rowNum++
		}
	}
}

// assessLikelihood maps PQC status to a 1-5 likelihood score.
func assessLikelihood(pqcStatus string) int {
	switch pqcStatus {
	case "UNSAFE":
		return 5
	case "DEPRECATED":
		return 4
	case "TRANSITIONAL":
		return 3
	case "SAFE":
		return 1
	default:
		return 3
	}
}

// assessImpact maps criticality level to a 1-5 impact score.
func assessImpact(criticality string) int {
	switch criticality {
	case "Sangat Tinggi":
		return 5
	case "Tinggi":
		return 4
	case "Sederhana":
		return 3
	case "Rendah":
		return 2
	default:
		return 3
	}
}

// riskLevel maps a risk score (impact * likelihood) to a textual level.
func riskLevel(score int) string {
	switch {
	case score >= 20:
		return "Very High Risk"
	case score >= 12:
		return "High Risk"
	case score >= 6:
		return "Medium Risk"
	case score >= 3:
		return "Low Risk"
	default:
		return "Very Low Risk"
	}
}

// riskSource returns a Malay risk source description based on PQC status.
func riskSource(asset model.CryptoAsset) string {
	switch asset.PQCStatus {
	case "UNSAFE":
		return "Algoritma tidak selamat terhadap serangan kuantum"
	case "DEPRECATED":
		return "Algoritma usang dan tidak lagi disokong"
	case "TRANSITIONAL":
		return "Algoritma klasik belum bersedia untuk PQC"
	case "SAFE":
		return "Algoritma selamat kuantum"
	default:
		return "Status kriptografi tidak dapat ditentukan"
	}
}

// classifyAssetType derives the asset type from the crypto asset properties.
func classifyAssetType(asset model.CryptoAsset) string {
	fn := strings.ToLower(asset.Function)
	switch {
	case strings.Contains(fn, "certificate"):
		return "Certificate"
	case strings.Contains(fn, "key exchange") || strings.Contains(fn, "key agreement"):
		return "Key Exchange"
	case strings.Contains(fn, "cipher") || strings.Contains(fn, "encryption"):
		return "Encryption"
	case strings.Contains(fn, "signature") || strings.Contains(fn, "signing"):
		return "Digital Signature"
	case strings.Contains(fn, "hash") || strings.Contains(fn, "digest"):
		return "Hash"
	default:
		return "Cryptographic Asset"
	}
}

// assessRisk returns a risk description based on the PQC status.
func assessRisk(asset model.CryptoAsset) string {
	switch asset.PQCStatus {
	case "UNSAFE":
		return "Kritikal — algoritma tidak selamat terhadap serangan kuantum"
	case "DEPRECATED":
		return "Tinggi — algoritma usang; perlu digantikan segera"
	case "TRANSITIONAL":
		return "Sederhana — algoritma klasik; rancangan migrasi PQC diperlukan"
	case "SAFE":
		return "Rendah — algoritma selamat kuantum"
	default:
		return "Tidak dapat dinilai"
	}
}

// populateComplianceSummary creates the "5_ComplianceSummary" sheet with NACSA and CAMM data.
func populateComplianceSummary(f *excelize.File, result *model.ScanResult) {
	const sheet = "5_ComplianceSummary"

	// Create the sheet if it doesn't exist
	idx, err := f.GetSheetIndex(sheet)
	if idx < 0 || err != nil {
		_, _ = f.NewSheet(sheet)
	}

	// Headers
	headers := []string{
		"Metric", "Value",
	}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = f.SetCellValue(sheet, cell, h)
	}

	nacsa := crypto.ComputeNACSASummary(result.Systems)
	camm := crypto.AssessCAMM(result.Systems, result.Findings)

	rows := [][]interface{}{
		{"NACSA Readiness", fmt.Sprintf("%.1f%%", nacsa.ReadinessPercent)},
		{"Total Crypto Assets", nacsa.TotalAssets},
		{"Patuh (Compliant)", nacsa.Patuh},
		{"Dalam Peralihan (In Transition)", nacsa.DalamPeralihan},
		{"Tidak Patuh (Non-Compliant)", nacsa.TidakPatuh},
		{"Perlu Tindakan Segera (Immediate Action)", nacsa.TindakanSegera},
		{"CNSA 2.0 Compliant", nacsa.CNSA2Compliant},
		{"", ""},
		{"CAMM Level", crypto.CAMMLevelLabel(camm.Level)},
		{"CAMM Confidence", camm.Confidence},
	}

	// Add CAMM indicators
	for _, ind := range camm.Indicators {
		rows = append(rows, []interface{}{"CAMM Indicator Met", ind})
	}
	for _, manual := range camm.Manual {
		rows = append(rows, []interface{}{"CAMM Manual Assessment", manual})
	}

	for i, row := range rows {
		for j, v := range row {
			cell, _ := excelize.CoordinatesToCellName(j+1, i+2) // Start at row 2
			_ = f.SetCellValue(sheet, cell, v)
		}
	}
}

// collectAlgorithms returns a comma-separated list of algorithms from a system's crypto assets.
func collectAlgorithms(sys model.System) string {
	if len(sys.CryptoAssets) == 0 {
		return ""
	}
	seen := make(map[string]bool)
	var algos []string
	for i := range sys.CryptoAssets {
		if sys.CryptoAssets[i].Algorithm != "" && !seen[sys.CryptoAssets[i].Algorithm] {
			algos = append(algos, sys.CryptoAssets[i].Algorithm)
			seen[sys.CryptoAssets[i].Algorithm] = true
		}
	}
	return strings.Join(algos, ", ")
}

// deriveAssetType determines the asset type for the inventory sheet.
// More-specific keywords are checked before broader ones to avoid
// misclassification (e.g. "AWS CloudHSM" → Cloud, not HSM).
func deriveAssetType(sys model.System) string {
	name := strings.ToLower(sys.Name)
	switch {
	case strings.Contains(name, "cloud") || strings.Contains(name, "aws") || strings.Contains(name, "azure"):
		return "Cloud Services"
	case strings.Contains(name, "firmware"):
		return "Firmware"
	case strings.Contains(name, "hsm"):
		return "Hardware (HSM)"
	case strings.Contains(name, "database") || strings.Contains(name, "postgres") || strings.Contains(name, "mysql"):
		return "Database"
	case strings.Contains(name, "api") && !strings.Contains(name, "process"):
		return "API Gateway"
	case strings.Contains(name, "process") || strings.Contains(name, "service"):
		return "Application Stack"
	default:
		return "Application Stack"
	}
}

// deriveReadiness maps worst PQC status in the system to a readiness level.
// Unknown/empty PQC status is treated as TRANSITIONAL (needs investigation).
func deriveReadiness(sys model.System) string {
	worst := "SAFE"
	priority := map[string]int{"SAFE": 0, "TRANSITIONAL": 1, "DEPRECATED": 2, "UNSAFE": 3}
	for i := range sys.CryptoAssets {
		p, known := priority[sys.CryptoAssets[i].PQCStatus]
		if !known {
			// Unknown status — treat as at least TRANSITIONAL
			p = priority["TRANSITIONAL"]
		}
		if p > priority[worst] {
			worst = sys.CryptoAssets[i].PQCStatus
			if !known {
				worst = "TRANSITIONAL"
			}
		}
	}
	switch worst {
	case "UNSAFE":
		return "Very Low"
	case "DEPRECATED":
		return "Low"
	case "TRANSITIONAL":
		return "Medium"
	default:
		return "High"
	}
}
