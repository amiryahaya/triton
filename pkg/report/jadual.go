package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// GenerateJadual1 creates the SBOM table (Table 1) matching the government Excel format.
// 17 columns with English headers.
func (g *Generator) GenerateJadual1(result *model.ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	headers := []string{
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
	if err := writer.Write(headers); err != nil {
		return err
	}

	for i, sys := range result.Systems {
		inUse := "Tidak"
		if sys.InUse {
			inUse = "Ya"
		}

		cbomLink := strings.Join(sys.CBOMRefs, ", ")

		record := []string{
			fmt.Sprintf("%d", i+1),
			sys.Name,
			sys.Purpose,
			sys.URL,
			sys.ServiceMode,
			sys.TargetCustomer,
			strings.Join(sys.Components, ", "),
			strings.Join(sys.ThirdPartyModules, ", "),
			strings.Join(sys.ExternalAPIs, ", "),
			sys.CriticalityLevel,
			sys.DataCategory,
			inUse,
			sys.Developer,
			sys.Vendor,
			"", // Does the agency have expertise? (manual field)
			"", // Does the agency have a special budget allocation? (manual field)
			cbomLink,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}

// GenerateJadual2 creates the CBOM table (Table 2) matching the government Excel format.
// 8 columns with English headers. One row per crypto asset across all systems.
func (g *Generator) GenerateJadual2(result *model.ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	headers := []string{
		"# (CBOM)",
		"System / Application",
		"Cryptographic Function",
		"Algorithm Used",
		"Library / Module",
		"Key Length",
		"Purpose / Usage",
		"Crypto-Agility Support",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	cbomNum := 1
	for _, sys := range result.Systems {
		for _, asset := range sys.CryptoAssets {
			record := []string{
				fmt.Sprintf("CBOM #%d", cbomNum),
				sys.Name,
				asset.Function,
				asset.Algorithm,
				asset.Library,
				crypto.FormatKeySize(asset.KeySize),
				asset.Purpose,
				asset.CryptoAgility,
			}
			if err := writer.Write(record); err != nil {
				return err
			}
			cbomNum++
		}
	}

	writer.Flush()
	return writer.Error()
}

// GenerateRiskRegister creates the Risk Register table (Table 3) matching the government Excel format.
// 8 columns. One row per crypto asset with risk assessment.
func (g *Generator) GenerateRiskRegister(result *model.ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	headers := []string{
		"#",
		"System Name",
		"Type of Asset",
		"Cryptographic Algorithm",
		"Algorithm Usage",
		"Criticality",
		"Risk",
		"Risk Owner",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	rowNum := 1
	for _, sys := range result.Systems {
		for _, asset := range sys.CryptoAssets {
			record := []string{
				fmt.Sprintf("%d", rowNum),
				sys.Name,
				classifyAssetType(asset),
				asset.Algorithm,
				asset.Function,
				sys.CriticalityLevel,
				assessRisk(asset),
				"", // Risk Owner (manual field)
			}
			if err := writer.Write(record); err != nil {
				return err
			}
			rowNum++
		}
	}

	writer.Flush()
	return writer.Error()
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
