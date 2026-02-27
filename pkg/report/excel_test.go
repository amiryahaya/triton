package report

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xuri/excelize/v2"

	"github.com/amiryahaya/triton/pkg/model"
)

// excelTestResult returns a scan result with 2 systems and 3 crypto assets.
func excelTestResult() *model.ScanResult {
	return &model.ScanResult{
		ID: "test-scan-001",
		Metadata: model.ScanMetadata{
			Timestamp:   time.Date(2026, 2, 26, 10, 0, 0, 0, time.UTC),
			Hostname:    "test-host",
			ScanProfile: "standard",
			ToolVersion: "0.1.0",
		},
		Systems: []model.System{
			{
				ID:                "sys-1",
				Name:              "Portal Gov",
				Purpose:           "Public portal",
				URL:               "https://portal.gov.my",
				ServiceMode:       "Online",
				TargetCustomer:    "G2C",
				Components:        []string{"OpenSSL 3.0", "Apache"},
				ThirdPartyModules: []string{"mod_ssl"},
				ExternalAPIs:      []string{"MyKAD API"},
				CriticalityLevel:  "Sangat Tinggi",
				DataCategory:      "Sulit",
				InUse:             true,
				Developer:         "MAMPU",
				Vendor:            "Internal",
				CBOMRefs:          []string{"CBOM #1 - CBOM #2"},
				CryptoAssets: []model.CryptoAsset{
					{
						Algorithm:     "RSA-2048",
						Function:      "TLS server certificate",
						Library:       "OpenSSL",
						KeySize:       2048,
						Purpose:       "Server authentication",
						CryptoAgility: "Terhad (algoritma klasik)",
						PQCStatus:     "TRANSITIONAL",
					},
					{
						Algorithm:     "AES-256-GCM",
						Function:      "TLS cipher suite",
						Library:       "OpenSSL",
						KeySize:       256,
						Purpose:       "Encryption for TLS channel",
						CryptoAgility: "Ya (algoritma selamat kuantum untuk simetri)",
						PQCStatus:     "SAFE",
					},
				},
			},
			{
				ID:               "sys-2",
				Name:             "sshd (process)",
				CriticalityLevel: "Tinggi",
				InUse:            true,
				CBOMRefs:         []string{"CBOM #3"},
				CryptoAssets: []model.CryptoAsset{
					{
						Algorithm:     "Ed25519",
						Function:      "SSH host key",
						Library:       "OpenSSH",
						KeySize:       256,
						Purpose:       "Host authentication",
						CryptoAgility: "Terhad (algoritma klasik)",
						PQCStatus:     "SAFE",
					},
				},
			},
		},
		Summary: model.Summary{
			TotalSystems:      2,
			TotalFindings:     3,
			TotalCryptoAssets: 3,
			Safe:              2,
			Transitional:      1,
		},
	}
}

func TestGenerateExcelCreatesValidFile(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	sheets := f.GetSheetList()
	assert.Len(t, sheets, 9)

	expected := []string{
		"00_ReadMe", "0_Inventory", "1_SBOM", "2_CBOM",
		"3_RiskRegister", "4_RiskAssessment", "5_RiskMatrix", "6_ProtocolCryptoMap",
		"5_ComplianceSummary",
	}
	assert.Equal(t, expected, sheets)
}

func TestGenerateExcelStaticSheetsPreserved(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// ReadMe sheet should still have content in A1
	val, err := f.GetCellValue("00_ReadMe", "A1")
	require.NoError(t, err)
	assert.NotEmpty(t, val)

	// RiskMatrix should still have content
	val, err = f.GetCellValue("5_RiskMatrix", "A1")
	require.NoError(t, err)
	assert.NotEmpty(t, val)
}

func TestGenerateExcelExampleRowsCleared(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// The EXAMPLE rows should be cleared in all data sheets
	sheets := []struct {
		name     string
		startRow int
		endRow   int
	}{
		{"0_Inventory", 5, 14},
		{"1_SBOM", 5, 12},
		{"2_CBOM", 5, 12},
		{"3_RiskRegister", 5, 8},
		{"4_RiskAssessment", 5, 8},
	}

	for _, s := range sheets {
		// Check A column in example range — should NOT contain "EXAMPLE"
		for row := s.startRow; row <= s.endRow; row++ {
			cell, _ := excelize.CoordinatesToCellName(1, row)
			val, err := f.GetCellValue(s.name, cell)
			require.NoError(t, err)
			assert.NotContains(t, val, "EXAMPLE", "sheet %s row %d should not have EXAMPLE", s.name, row)
		}
	}

	// Title row merges outside example range must be preserved
	// 3_RiskRegister has A2:E2, 4_RiskAssessment has A2:K2
	titleMerges := []struct {
		sheet string
		start string
		end   string
	}{
		{"3_RiskRegister", "A2", "E2"},
		{"4_RiskAssessment", "A2", "K2"},
	}
	for _, tm := range titleMerges {
		mc, err := f.GetMergeCells(tm.sheet)
		require.NoError(t, err)
		found := false
		for _, m := range mc {
			if m.GetStartAxis() == tm.start && m.GetEndAxis() == tm.end {
				found = true
				break
			}
		}
		assert.True(t, found, "sheet %s should preserve merge %s:%s", tm.sheet, tm.start, tm.end)
	}
}

func TestGenerateExcelInventoryHeaders(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// Row 4 should have headers (row 16 has 2nd header row — same headers)
	headers := map[string]string{
		"A4": "#",
		"B4": "Asset Type",
		"C4": "Asset Name / Identifier",
		"D4": "Location / Owner",
		"E4": "Cryptographic Functionality Present?",
		"F4": "Examples of Algorithms Used",
		"G4": "SBOM/CBOM Available?",
		"H4": "Migration Readiness Level",
		"I4": "Notes / Action Items",
	}
	for cell, expected := range headers {
		val, err := f.GetCellValue("0_Inventory", cell)
		require.NoError(t, err)
		assert.Equal(t, expected, val, "0_Inventory header %s", cell)
	}
}

func TestGenerateExcelInventoryData(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// Data starts at row 17
	val, _ := f.GetCellValue("0_Inventory", "A17")
	assert.Equal(t, "1", val)

	val, _ = f.GetCellValue("0_Inventory", "B17")
	assert.Equal(t, "Application Stack", val)

	val, _ = f.GetCellValue("0_Inventory", "C17")
	assert.Equal(t, "Portal Gov", val)

	// Second system at row 18
	val, _ = f.GetCellValue("0_Inventory", "A18")
	assert.Equal(t, "2", val)

	val, _ = f.GetCellValue("0_Inventory", "C18")
	assert.Equal(t, "sshd (process)", val)
}

func TestGenerateExcelSBOMHeaders(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// Headers at row 4 preserved
	val, _ := f.GetCellValue("1_SBOM", "A4")
	assert.Equal(t, "#", val)
	val, _ = f.GetCellValue("1_SBOM", "B4")
	assert.Equal(t, "System / Application", val)
	val, _ = f.GetCellValue("1_SBOM", "Q4")
	assert.Equal(t, "Link to CBOM", val)
}

func TestGenerateExcelSBOMData(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// Data starts at row 15
	val, _ := f.GetCellValue("1_SBOM", "A15")
	assert.Equal(t, "1", val)

	val, _ = f.GetCellValue("1_SBOM", "B15")
	assert.Equal(t, "Portal Gov", val)

	val, _ = f.GetCellValue("1_SBOM", "C15")
	assert.Equal(t, "Public portal", val)

	val, _ = f.GetCellValue("1_SBOM", "D15")
	assert.Equal(t, "https://portal.gov.my", val)

	val, _ = f.GetCellValue("1_SBOM", "E15")
	assert.Equal(t, "Online", val)

	val, _ = f.GetCellValue("1_SBOM", "F15")
	assert.Equal(t, "G2C", val)

	val, _ = f.GetCellValue("1_SBOM", "G15")
	assert.Equal(t, "OpenSSL 3.0, Apache", val)

	val, _ = f.GetCellValue("1_SBOM", "H15")
	assert.Equal(t, "mod_ssl", val)

	val, _ = f.GetCellValue("1_SBOM", "I15")
	assert.Equal(t, "MyKAD API", val)

	val, _ = f.GetCellValue("1_SBOM", "J15")
	assert.Equal(t, "Sangat Tinggi", val)

	val, _ = f.GetCellValue("1_SBOM", "K15")
	assert.Equal(t, "Sulit", val)

	val, _ = f.GetCellValue("1_SBOM", "L15")
	assert.Equal(t, "Ya", val)

	val, _ = f.GetCellValue("1_SBOM", "M15")
	assert.Equal(t, "MAMPU", val)

	val, _ = f.GetCellValue("1_SBOM", "N15")
	assert.Equal(t, "Internal", val)

	val, _ = f.GetCellValue("1_SBOM", "Q15")
	assert.Equal(t, "CBOM #1 - CBOM #2", val)

	// Second system
	val, _ = f.GetCellValue("1_SBOM", "A16")
	assert.Equal(t, "2", val)

	val, _ = f.GetCellValue("1_SBOM", "B16")
	assert.Equal(t, "sshd (process)", val)
}

func TestGenerateExcelCBOMData(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// CBOM headers at row 4 preserved
	val, _ := f.GetCellValue("2_CBOM", "A4")
	assert.Equal(t, "# (CBOM)", val)

	// Data starts at row 15
	// First crypto asset (from sys-1)
	val, _ = f.GetCellValue("2_CBOM", "A15")
	assert.Equal(t, "CBOM #1", val)

	val, _ = f.GetCellValue("2_CBOM", "B15")
	assert.Equal(t, "Portal Gov", val)

	val, _ = f.GetCellValue("2_CBOM", "C15")
	assert.Equal(t, "TLS server certificate", val)

	val, _ = f.GetCellValue("2_CBOM", "D15")
	assert.Equal(t, "RSA-2048", val)

	val, _ = f.GetCellValue("2_CBOM", "E15")
	assert.Equal(t, "OpenSSL", val)

	val, _ = f.GetCellValue("2_CBOM", "F15")
	assert.Equal(t, "2048-bit", val)

	val, _ = f.GetCellValue("2_CBOM", "G15")
	assert.Equal(t, "Server authentication", val)

	val, _ = f.GetCellValue("2_CBOM", "H15")
	assert.Equal(t, "Terhad (algoritma klasik)", val)

	// Second crypto asset (from sys-1)
	val, _ = f.GetCellValue("2_CBOM", "A16")
	assert.Equal(t, "CBOM #2", val)

	val, _ = f.GetCellValue("2_CBOM", "D16")
	assert.Equal(t, "AES-256-GCM", val)

	val, _ = f.GetCellValue("2_CBOM", "F16")
	assert.Equal(t, "256-bit", val)

	// Third crypto asset (from sys-2)
	val, _ = f.GetCellValue("2_CBOM", "A17")
	assert.Equal(t, "CBOM #3", val)

	val, _ = f.GetCellValue("2_CBOM", "B17")
	assert.Equal(t, "sshd (process)", val)

	val, _ = f.GetCellValue("2_CBOM", "D17")
	assert.Equal(t, "Ed25519", val)
}

func TestGenerateExcelRiskRegisterData(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// Headers at row 4 and Malay headers at row 9 preserved
	val, _ := f.GetCellValue("3_RiskRegister", "A4")
	assert.Equal(t, "#", val)

	val, _ = f.GetCellValue("3_RiskRegister", "A9")
	assert.Equal(t, "#", val)

	// Data starts at row 10
	val, _ = f.GetCellValue("3_RiskRegister", "A10")
	assert.Equal(t, "1", val)

	val, _ = f.GetCellValue("3_RiskRegister", "B10")
	assert.Equal(t, "Portal Gov", val)

	val, _ = f.GetCellValue("3_RiskRegister", "C10")
	assert.Equal(t, "Certificate", val)

	val, _ = f.GetCellValue("3_RiskRegister", "D10")
	assert.Equal(t, "RSA-2048", val)

	val, _ = f.GetCellValue("3_RiskRegister", "E10")
	assert.Equal(t, "TLS server certificate", val)

	val, _ = f.GetCellValue("3_RiskRegister", "F10")
	assert.Equal(t, "Sangat Tinggi", val)

	val, _ = f.GetCellValue("3_RiskRegister", "G10")
	assert.Contains(t, val, "Sederhana")

	// Second row
	val, _ = f.GetCellValue("3_RiskRegister", "A11")
	assert.Equal(t, "2", val)

	val, _ = f.GetCellValue("3_RiskRegister", "D11")
	assert.Equal(t, "AES-256-GCM", val)
}

func TestGenerateExcelRiskAssessmentData(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// Malay headers at row 10 preserved
	val, _ := f.GetCellValue("4_RiskAssessment", "A10")
	assert.Equal(t, "#", val)

	// Data starts at row 11
	val, _ = f.GetCellValue("4_RiskAssessment", "A11")
	assert.Equal(t, "1", val)

	val, _ = f.GetCellValue("4_RiskAssessment", "B11")
	assert.Equal(t, "Portal Gov", val)

	val, _ = f.GetCellValue("4_RiskAssessment", "C11")
	assert.Equal(t, "RSA-2048", val)

	// Row 1: RSA-2048, TRANSITIONAL, Sangat Tinggi
	// D: Risk description
	val, _ = f.GetCellValue("4_RiskAssessment", "D11")
	assert.Contains(t, val, "Sederhana")

	// E: Risk source
	val, _ = f.GetCellValue("4_RiskAssessment", "E11")
	assert.Contains(t, val, "klasik")

	// F: Impact = 5 (Sangat Tinggi)
	val, _ = f.GetCellValue("4_RiskAssessment", "F11")
	assert.Equal(t, "5", val)

	// G: Likelihood = 3 (TRANSITIONAL)
	val, _ = f.GetCellValue("4_RiskAssessment", "G11")
	assert.Equal(t, "3", val)

	// H: Risk Score = 5 * 3 = 15
	val, _ = f.GetCellValue("4_RiskAssessment", "H11")
	assert.Equal(t, "15", val)

	// I: Risk Level = High Risk (score 15 >= 12)
	val, _ = f.GetCellValue("4_RiskAssessment", "I11")
	assert.Equal(t, "High Risk", val)
}

func TestGenerateExcelEmptyResult(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := &model.ScanResult{}

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// Should still have 9 sheets (including ComplianceSummary)
	assert.Len(t, f.GetSheetList(), 9)

	// No data rows in SBOM — row 15 col A should be empty
	val, _ := f.GetCellValue("1_SBOM", "A15")
	assert.Empty(t, val)

	// Headers should still be there
	val, _ = f.GetCellValue("1_SBOM", "A4")
	assert.Equal(t, "#", val)
}

func TestGenerateExcelCBOMNumberingConsistency(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")
	result := excelTestResult()

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// CBOM numbers should match across 2_CBOM and 1_SBOM link columns
	cbomVal, _ := f.GetCellValue("2_CBOM", "A15")
	assert.Equal(t, "CBOM #1", cbomVal)

	cbomVal, _ = f.GetCellValue("2_CBOM", "A16")
	assert.Equal(t, "CBOM #2", cbomVal)

	cbomVal, _ = f.GetCellValue("2_CBOM", "A17")
	assert.Equal(t, "CBOM #3", cbomVal)

	// SBOM link to CBOM for sys-1
	linkVal, _ := f.GetCellValue("1_SBOM", "Q15")
	assert.Equal(t, "CBOM #1 - CBOM #2", linkVal)

	// SBOM link to CBOM for sys-2
	linkVal, _ = f.GetCellValue("1_SBOM", "Q16")
	assert.Equal(t, "CBOM #3", linkVal)
}

func TestAssessLikelihood(t *testing.T) {
	tests := []struct {
		status   string
		expected int
	}{
		{"UNSAFE", 5},
		{"DEPRECATED", 4},
		{"TRANSITIONAL", 3},
		{"SAFE", 1},
		{"UNKNOWN", 3},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			assert.Equal(t, tt.expected, assessLikelihood(tt.status))
		})
	}
}

func TestAssessImpact(t *testing.T) {
	tests := []struct {
		level    string
		expected int
	}{
		{"Sangat Tinggi", 5},
		{"Tinggi", 4},
		{"Sederhana", 3},
		{"Rendah", 2},
		{"", 3},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			assert.Equal(t, tt.expected, assessImpact(tt.level))
		})
	}
}

func TestRiskLevel(t *testing.T) {
	tests := []struct {
		score    int
		expected string
	}{
		{25, "Very High Risk"},
		{20, "Very High Risk"},
		{15, "High Risk"},
		{12, "High Risk"},
		{8, "Medium Risk"},
		{6, "Medium Risk"},
		{4, "Low Risk"},
		{3, "Low Risk"},
		{2, "Very Low Risk"},
		{1, "Very Low Risk"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, riskLevel(tt.score))
		})
	}
}

func TestClassifyAssetType(t *testing.T) {
	tests := []struct {
		function string
		expected string
	}{
		{"TLS server certificate", "Certificate"},
		{"X.509 Certificate validation", "Certificate"},
		{"Key Exchange (ECDHE)", "Key Exchange"},
		{"Key agreement protocol", "Key Exchange"},
		{"TLS cipher suite", "Encryption"},
		{"AES encryption", "Encryption"},
		{"Digital Signature", "Digital Signature"},
		{"Code signing", "Digital Signature"},
		{"SHA-256 hash", "Hash"},
		{"Message digest", "Hash"},
		{"SSH host key", "Cryptographic Asset"},
		{"", "Cryptographic Asset"},
	}
	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			asset := model.CryptoAsset{Function: tt.function}
			assert.Equal(t, tt.expected, classifyAssetType(asset))
		})
	}
}

func TestAssessRisk(t *testing.T) {
	tests := []struct {
		status   string
		contains string
	}{
		{"UNSAFE", "Kritikal"},
		{"DEPRECATED", "Tinggi"},
		{"TRANSITIONAL", "Sederhana"},
		{"SAFE", "Rendah"},
		{"", "Tidak dapat dinilai"},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			asset := model.CryptoAsset{PQCStatus: tt.status}
			assert.Contains(t, assessRisk(asset), tt.contains)
		})
	}
}

func TestRiskSource(t *testing.T) {
	tests := []struct {
		status   string
		contains string
	}{
		{"UNSAFE", "tidak selamat"},
		{"DEPRECATED", "usang"},
		{"TRANSITIONAL", "klasik"},
		{"SAFE", "selamat kuantum"},
		{"UNKNOWN", "tidak dapat ditentukan"},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			asset := model.CryptoAsset{PQCStatus: tt.status}
			assert.Contains(t, riskSource(asset), tt.contains)
		})
	}
}

func TestDeriveAssetType(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"sshd (process)", "Application Stack"},
		{"TLS Service (10.0.0.1:443)", "Application Stack"},
		{"IoT Sensor Firmware v1.0", "Firmware"},
		{"Thales HSM Cluster", "Hardware (HSM)"},
		{"AWS CloudHSM", "Cloud Services"},
		{"Azure Key Vault", "Cloud Services"},
		{"REST API Gateway", "API Gateway"},
		{"PostgreSQL 14.2", "Database"},
		{"MySQL Server", "Database"},
		{"Portal Gov", "Application Stack"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := model.System{Name: tt.name}
			assert.Equal(t, tt.expected, deriveAssetType(sys))
		})
	}
}

func TestDeriveReadiness(t *testing.T) {
	tests := []struct {
		name     string
		assets   []model.CryptoAsset
		expected string
	}{
		{
			"all safe",
			[]model.CryptoAsset{{PQCStatus: "SAFE"}, {PQCStatus: "SAFE"}},
			"High",
		},
		{
			"one transitional",
			[]model.CryptoAsset{{PQCStatus: "SAFE"}, {PQCStatus: "TRANSITIONAL"}},
			"Medium",
		},
		{
			"one deprecated",
			[]model.CryptoAsset{{PQCStatus: "SAFE"}, {PQCStatus: "DEPRECATED"}},
			"Low",
		},
		{
			"one unsafe",
			[]model.CryptoAsset{{PQCStatus: "TRANSITIONAL"}, {PQCStatus: "UNSAFE"}},
			"Very Low",
		},
		{
			"empty PQCStatus treated as transitional",
			[]model.CryptoAsset{{PQCStatus: "SAFE"}, {PQCStatus: ""}},
			"Medium",
		},
		{
			"unknown PQCStatus treated as transitional",
			[]model.CryptoAsset{{PQCStatus: "GARBAGE"}},
			"Medium",
		},
		{
			"no assets",
			nil,
			"High",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := model.System{CryptoAssets: tt.assets}
			assert.Equal(t, tt.expected, deriveReadiness(sys))
		})
	}
}

func TestCollectAlgorithms(t *testing.T) {
	t.Run("multiple unique", func(t *testing.T) {
		sys := model.System{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
				{Algorithm: "AES-256"},
				{Algorithm: "RSA-2048"}, // duplicate
			},
		}
		assert.Equal(t, "RSA-2048, AES-256", collectAlgorithms(sys))
	})

	t.Run("empty", func(t *testing.T) {
		sys := model.System{}
		assert.Equal(t, "", collectAlgorithms(sys))
	})

	t.Run("single", func(t *testing.T) {
		sys := model.System{
			CryptoAssets: []model.CryptoAsset{{Algorithm: "Ed25519"}},
		}
		assert.Equal(t, "Ed25519", collectAlgorithms(sys))
	})
}

func TestGenerateExcelInUseFalse(t *testing.T) {
	tmpFile := t.TempDir() + "/report.xlsx"
	g := New("")

	result := &model.ScanResult{
		Systems: []model.System{
			{
				Name:  "Decommissioned App",
				InUse: false,
			},
		},
	}

	err := g.GenerateExcel(result, tmpFile)
	require.NoError(t, err)

	f, err := excelize.OpenFile(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	// Column L (In Use?) at data row 15 should be "Tidak"
	val, _ := f.GetCellValue("1_SBOM", "L15")
	assert.Equal(t, "Tidak", val)
}
