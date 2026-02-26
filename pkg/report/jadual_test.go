package report

import (
	"encoding/csv"
	"os"
	"strings"
	"testing"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateJadual1Headers(t *testing.T) {
	tmpFile := t.TempDir() + "/jadual1.csv"
	g := New("")

	result := &model.ScanResult{
		Systems: []model.System{
			{
				ID:   "sys-1",
				Name: "Test System",
			},
		},
	}

	err := g.GenerateJadual1(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	require.True(t, len(records) >= 1)

	// Verify exact headers match the original Excel format
	expectedHeaders := []string{
		"#",
		"System / Application",
		"Purpose / Usage",
		"URL",
		"Services Mode",
		"Target Customer",
		"Software Component",
		"Third-party Modules",
		"External APIs or Services",
		"Critical Level",
		"Data Category",
		"Is the application/system currently in use?",
		"Application/System Developer",
		"Vendor's Name",
		"Does the agency have expertise?",
		"Does the agency have a special budget allocation?",
		"Link to CBOM",
	}
	assert.Equal(t, expectedHeaders, records[0])
	assert.Len(t, records[0], 17, "Jadual 1 must have exactly 17 columns")
}

func TestGenerateJadual1DataRows(t *testing.T) {
	tmpFile := t.TempDir() + "/jadual1.csv"
	g := New("")

	result := &model.ScanResult{
		Systems: []model.System{
			{
				ID:                "sys-1",
				Name:              "Portal Gov",
				Purpose:           "Public portal",
				URL:               "https://portal.gov.my",
				ServiceMode:       "Online",
				TargetCustomer:    "Public",
				Components:        []string{"OpenSSL 3.0", "Apache"},
				ThirdPartyModules: []string{"mod_ssl"},
				ExternalAPIs:      []string{"MyKAD API"},
				CriticalityLevel:  "Sangat Tinggi",
				DataCategory:      "Sulit",
				InUse:             true,
				Developer:         "MAMPU",
				Vendor:            "Internal",
				CBOMRefs:          []string{"CBOM #1 - CBOM #3"},
			},
			{
				ID:       "sys-2",
				Name:     "SSH Service",
				InUse:    true,
				CBOMRefs: []string{"CBOM #4"},
			},
		},
	}

	err := g.GenerateJadual1(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// Header + 2 data rows
	require.Len(t, records, 3)

	// First data row
	assert.Equal(t, "1", records[1][0])
	assert.Equal(t, "Portal Gov", records[1][1])
	assert.Equal(t, "Public portal", records[1][2])
	assert.Equal(t, "https://portal.gov.my", records[1][3])
	assert.Equal(t, "Online", records[1][4])
	assert.Equal(t, "Public", records[1][5])
	assert.Equal(t, "OpenSSL 3.0, Apache", records[1][6])
	assert.Equal(t, "mod_ssl", records[1][7])
	assert.Equal(t, "MyKAD API", records[1][8])
	assert.Equal(t, "Sangat Tinggi", records[1][9])
	assert.Equal(t, "Sulit", records[1][10])
	assert.Equal(t, "Ya", records[1][11])
	assert.Equal(t, "MAMPU", records[1][12])
	assert.Equal(t, "Internal", records[1][13])
	assert.Equal(t, "CBOM #1 - CBOM #3", records[1][16])

	// Second data row
	assert.Equal(t, "2", records[2][0])
	assert.Equal(t, "SSH Service", records[2][1])
}

func TestGenerateJadual1Empty(t *testing.T) {
	tmpFile := t.TempDir() + "/jadual1.csv"
	g := New("")
	result := &model.ScanResult{}

	err := g.GenerateJadual1(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	assert.Len(t, records, 1, "should have only header row")
}

func TestGenerateJadual2Headers(t *testing.T) {
	tmpFile := t.TempDir() + "/jadual2.csv"
	g := New("")

	result := &model.ScanResult{
		Systems: []model.System{
			{
				Name: "Test System",
				CryptoAssets: []model.CryptoAsset{
					{Algorithm: "RSA-2048"},
				},
			},
		},
	}

	err := g.GenerateJadual2(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	require.True(t, len(records) >= 1)

	// Verify exact headers match the original Excel format
	expectedHeaders := []string{
		"# (CBOM)",
		"System / Application",
		"Cryptographic Function",
		"Algorithm Used",
		"Library / Module",
		"Key Length",
		"Purpose / Usage",
		"Crypto-Agility Support",
	}
	assert.Equal(t, expectedHeaders, records[0])
	assert.Len(t, records[0], 8, "Jadual 2 must have exactly 8 columns")
}

func TestGenerateJadual2DataRows(t *testing.T) {
	tmpFile := t.TempDir() + "/jadual2.csv"
	g := New("")

	result := &model.ScanResult{
		Systems: []model.System{
			{
				Name: "TLS Service (10.0.0.1:443)",
				CryptoAssets: []model.CryptoAsset{
					{
						Algorithm:     "AES-256-GCM",
						Function:      "TLS cipher suite",
						Library:       "TLS 1.3",
						KeySize:       256,
						Purpose:       "Encryption for TLS channel",
						CryptoAgility: "Ya (algoritma selamat kuantum untuk simetri)",
					},
					{
						Algorithm:     "RSA-4096",
						Function:      "TLS server certificate",
						Library:       "X.509",
						KeySize:       4096,
						Purpose:       "Server authentication",
						CryptoAgility: "Terhad (algoritma klasik)",
					},
				},
			},
		},
	}

	err := g.GenerateJadual2(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// Header + 2 data rows
	require.Len(t, records, 3)

	// First CBOM entry
	assert.Equal(t, "CBOM #1", records[1][0])
	assert.Equal(t, "TLS Service (10.0.0.1:443)", records[1][1])
	assert.Equal(t, "TLS cipher suite", records[1][2])
	assert.Equal(t, "AES-256-GCM", records[1][3])
	assert.Equal(t, "TLS 1.3", records[1][4])
	assert.Equal(t, "256-bit", records[1][5])
	assert.Equal(t, "Encryption for TLS channel", records[1][6])

	// Second CBOM entry
	assert.Equal(t, "CBOM #2", records[2][0])
	assert.Equal(t, "4096-bit", records[2][5])
}

func TestGenerateJadual2Empty(t *testing.T) {
	tmpFile := t.TempDir() + "/jadual2.csv"
	g := New("")
	result := &model.ScanResult{}

	err := g.GenerateJadual2(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	assert.Len(t, records, 1, "should have only header row")
}

func TestGenerateRiskRegisterHeaders(t *testing.T) {
	tmpFile := t.TempDir() + "/risk.csv"
	g := New("")
	result := &model.ScanResult{}

	err := g.GenerateRiskRegister(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	require.True(t, len(records) >= 1)

	expectedHeaders := []string{
		"#",
		"System Name",
		"Type of Asset",
		"Cryptographic Algorithm",
		"Algorithm Usage",
		"Criticality",
		"Risk",
		"Risk Owner",
	}
	assert.Equal(t, expectedHeaders, records[0])
}

func TestGenerateRiskRegisterData(t *testing.T) {
	tmpFile := t.TempDir() + "/risk.csv"
	g := New("")
	result := &model.ScanResult{
		Systems: []model.System{
			{
				Name:             "Test App",
				CriticalityLevel: "Sangat Tinggi",
				CryptoAssets: []model.CryptoAsset{
					{Algorithm: "RSA-2048", Function: "TLS certificate", PQCStatus: "TRANSITIONAL"},
					{Algorithm: "DES", Function: "Encryption", PQCStatus: "UNSAFE"},
				},
			},
		},
	}

	err := g.GenerateRiskRegister(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	// Header + 2 data rows (one per crypto asset)
	require.Len(t, records, 3)
	assert.Equal(t, "Test App", records[1][1])
	assert.Equal(t, "RSA-2048", records[1][3])
}
