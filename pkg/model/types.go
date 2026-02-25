package model

import (
	"time"
)

// ModuleCategory classifies scanner modules by their scanning approach.
type ModuleCategory int

const (
	CategoryPassiveFile   ModuleCategory = iota // File-based passive scanning
	CategoryPassiveCode                         // Source code analysis
	CategoryActiveRuntime                       // Runtime/process inspection
	CategoryActiveNetwork                       // Network-based scanning
)

// ScanTargetType defines what kind of target a module scans.
type ScanTargetType int

const (
	TargetFilesystem ScanTargetType = iota
	TargetNetwork
	TargetProcess
)

// ScanResult is the top-level container for all scan output.
type ScanResult struct {
	ID       string       `json:"id"`
	Metadata ScanMetadata `json:"metadata"`
	Systems  []System     `json:"systems"`
	Findings []Finding    `json:"findings"`
	Summary  Summary      `json:"summary"`
}

// ScanMetadata captures scan execution context.
type ScanMetadata struct {
	Timestamp   time.Time     `json:"timestamp"`
	Hostname    string        `json:"hostname"`
	OS          string        `json:"os"`
	ScanProfile string        `json:"scanProfile"`
	Targets     []ScanTarget  `json:"targets"`
	Duration    time.Duration `json:"duration"`
	ToolVersion string        `json:"toolVersion"`
}

// System represents a system/application entity for Jadual 1 rows.
type System struct {
	ID                string        `json:"id"`
	Name              string        `json:"name"`
	Purpose           string        `json:"purpose,omitempty"`
	URL               string        `json:"url,omitempty"`
	ServiceMode       string        `json:"serviceMode,omitempty"`
	TargetCustomer    string        `json:"targetCustomer,omitempty"`
	Components        []string      `json:"components,omitempty"`
	ThirdPartyModules []string      `json:"thirdPartyModules,omitempty"`
	ExternalAPIs      []string      `json:"externalAPIs,omitempty"`
	CriticalityLevel  string        `json:"criticalityLevel,omitempty"`
	DataCategory      string        `json:"dataCategory,omitempty"`
	InUse             bool          `json:"inUse"`
	Developer         string        `json:"developer,omitempty"`
	Vendor            string        `json:"vendor,omitempty"`
	CBOMRefs          []string      `json:"cbomRefs,omitempty"`
	CryptoAssets      []CryptoAsset `json:"cryptoAssets,omitempty"`
}

// Finding is a raw scan result produced by a scanner module.
type Finding struct {
	ID          string        `json:"id"`
	Category    int           `json:"category"`
	Source      FindingSource `json:"source"`
	CryptoAsset *CryptoAsset  `json:"cryptoAsset,omitempty"`
	Confidence  float64       `json:"confidence"`
	Module      string        `json:"module"`
	Timestamp   time.Time     `json:"timestamp"`
}

// FindingSource discriminates between file, process, and network sources.
type FindingSource struct {
	Type     string `json:"type"`
	Path     string `json:"path,omitempty"`
	PID      int    `json:"pid,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

// CryptoAsset represents a cryptographic discovery for Jadual 2 rows.
type CryptoAsset struct {
	ID            string `json:"id"`
	SystemName    string `json:"systemName,omitempty"`
	Function      string `json:"function,omitempty"`
	Algorithm     string `json:"algorithm"`
	Library       string `json:"library,omitempty"`
	KeySize       int    `json:"keySize,omitempty"`
	Purpose       string `json:"purpose,omitempty"`
	CryptoAgility string `json:"cryptoAgility,omitempty"`

	// PQC Classification
	PQCStatus         string `json:"pqcStatus,omitempty"`
	MigrationPriority int    `json:"migrationPriority,omitempty"`
	BreakYear         int    `json:"breakYear,omitempty"`

	// Certificate-specific (optional)
	Subject      string     `json:"subject,omitempty"`
	Issuer       string     `json:"issuer,omitempty"`
	SerialNumber string     `json:"serialNumber,omitempty"`
	NotBefore    *time.Time `json:"notBefore,omitempty"`
	NotAfter     *time.Time `json:"notAfter,omitempty"`
	IsCA         bool       `json:"isCA,omitempty"`
}

// Summary holds aggregated statistics for a scan result.
type Summary struct {
	TotalSystems      int `json:"totalSystems"`
	TotalFindings     int `json:"totalFindings"`
	TotalCryptoAssets int `json:"totalCryptoAssets"`

	// PQC breakdown
	Safe         int `json:"safe"`
	Transitional int `json:"transitional"`
	Deprecated   int `json:"deprecated"`
	Unsafe       int `json:"unsafe"`

	// Category coverage
	CategoriesScanned []int `json:"categoriesScanned,omitempty"`
	CategoriesSkipped []int `json:"categoriesSkipped,omitempty"`

	// Crypto-agility
	OverallAgility string `json:"overallAgility,omitempty"`
	AgilityDetails string `json:"agilityDetails,omitempty"`
}

// ScanTarget defines a target for scanning.
type ScanTarget struct {
	Type  ScanTargetType `json:"type"`
	Value string         `json:"value"`
	Depth int            `json:"depth"`
}

// ComputeSummary calculates aggregate statistics from a list of findings.
func ComputeSummary(findings []Finding) Summary {
	s := Summary{
		TotalFindings: len(findings),
	}

	for _, f := range findings {
		if f.CryptoAsset == nil {
			continue
		}
		s.TotalCryptoAssets++

		switch f.CryptoAsset.PQCStatus {
		case "SAFE":
			s.Safe++
		case "TRANSITIONAL":
			s.Transitional++
		case "DEPRECATED":
			s.Deprecated++
		case "UNSAFE":
			s.Unsafe++
		}
	}

	return s
}
