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
	TargetDatabase
	TargetHSM
	TargetLDAP
	TargetOCIImage          // OCI image reference (e.g. nginx:1.25)
	TargetKubernetesCluster // kubeconfig path (Wave 1 Sprint 1b)
)

// PQC readiness status constants.
const (
	PQCStatusSafe         = "SAFE"
	PQCStatusTransitional = "TRANSITIONAL"
	PQCStatusDeprecated   = "DEPRECATED"
	PQCStatusUnsafe       = "UNSAFE"
)

// PolicyViolation holds a single policy rule violation for report rendering.
type PolicyViolation struct {
	RuleID   string `json:"ruleID"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Message  string `json:"message"`
}

// PolicyThresholdViolation holds a threshold violation for report rendering.
type PolicyThresholdViolation struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Message  string `json:"message"`
}

// PolicySystemEvaluation holds per-system policy evaluation results.
type PolicySystemEvaluation struct {
	SystemName          string                     `json:"systemName"`
	Verdict             string                     `json:"verdict"`
	Violations          []PolicyViolation          `json:"violations,omitempty"`
	ThresholdViolations []PolicyThresholdViolation `json:"thresholdViolations,omitempty"`
	FindingsChecked     int                        `json:"findingsChecked"`
}

// PolicyEvaluationResult holds policy evaluation data for report rendering.
type PolicyEvaluationResult struct {
	PolicyName          string                     `json:"policyName"`
	Verdict             string                     `json:"verdict"`
	Violations          []PolicyViolation          `json:"violations,omitempty"`
	ThresholdViolations []PolicyThresholdViolation `json:"thresholdViolations,omitempty"`
	RulesEvaluated      int                        `json:"rulesEvaluated"`
	FindingsChecked     int                        `json:"findingsChecked"`
	SystemEvaluations   []PolicySystemEvaluation   `json:"systemEvaluations,omitempty"`
}

// ScanResult is the top-level container for all scan output.
type ScanResult struct {
	ID               string                  `json:"id"`
	OrgID            string                  `json:"orgID,omitempty"` // Tenant org ID (set by server from token)
	PreviousScanID   string                  `json:"previousScanID,omitempty"`
	Metadata         ScanMetadata            `json:"metadata"`
	Systems          []System                `json:"systems"`
	Findings         []Finding               `json:"findings"`
	Summary          Summary                 `json:"summary"`
	PolicyEvaluation *PolicyEvaluationResult `json:"policyEvaluation,omitempty"`
}

// ScanMetadata captures scan execution context.
type ScanMetadata struct {
	Timestamp          time.Time      `json:"timestamp"`
	Hostname           string         `json:"hostname"`
	OS                 string         `json:"os"`
	ScanProfile        string         `json:"scanProfile"`
	Targets            []ScanTarget   `json:"targets"`
	Duration           time.Duration  `json:"duration"`
	ToolVersion        string         `json:"toolVersion"`
	ModuleMetrics      []ModuleMetric `json:"moduleMetrics,omitempty"`
	PeakMemoryMB       float64        `json:"peakMemoryMB,omitempty"`
	AgentID            string         `json:"agentID,omitempty"`
	MachineFingerprint string         `json:"machineFingerprint,omitempty"`
	IncrementalMode    bool           `json:"incrementalMode,omitempty"`
	FilesSkipped       int64          `json:"filesSkipped,omitempty"`
	PolicyResult       string         `json:"policyResult,omitempty"`
}

// ModuleMetric captures per-module-target scan performance metrics.
type ModuleMetric struct {
	Module        string        `json:"module"`
	Target        string        `json:"target"`
	Duration      time.Duration `json:"duration"`
	FilesScanned  int64         `json:"filesScanned"`
	FilesMatched  int64         `json:"filesMatched"`
	Findings      int           `json:"findings"`
	MemoryDeltaMB float64       `json:"memoryDeltaMB"`
	Error         string        `json:"error,omitempty"`
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
	Type            string `json:"type"`
	Path            string `json:"path,omitempty"`
	PID             int    `json:"pid,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	DetectionMethod string `json:"detectionMethod,omitempty"` // symbol, string, import, api-call, command, configuration, library-linkage
	ContainerImage  string `json:"containerImage,omitempty"`
	ContainerLayer  string `json:"containerLayer,omitempty"`
	Evidence        string `json:"evidence,omitempty"` // free-form provenance, e.g. ELF section name
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

	// Compliance
	CNSA2Status        string `json:"cnsa2Status,omitempty"`
	NISTDeprecatedYear int    `json:"nistDeprecatedYear,omitempty"`
	NISTDisallowedYear int    `json:"nistDisallowedYear,omitempty"`
	ComplianceWarning  string `json:"complianceWarning,omitempty"`

	// Hybrid certificate
	IsHybrid            bool     `json:"isHybrid,omitempty"`
	ComponentAlgorithms []string `json:"componentAlgorithms,omitempty"`

	// NACSA
	NACSALabel string `json:"nacsaLabel,omitempty"`

	// Dependency reachability analysis
	Reachability   string   `json:"reachability,omitempty"`   // "direct", "transitive", "unreachable"
	DependencyPath []string `json:"dependencyPath,omitempty"` // import chain: ["myapp", "github.com/foo/bar", "crypto/des"]

	// Binary/library analysis
	Language string `json:"language,omitempty"` // Go, Rust, C/C++, Python, etc.
	// OID is the ASN.1 Object Identifier (dotted decimal) when discovery
	// was OID-based or when the asset has an authoritative OID mapping.
	OID             string   `json:"oid,omitempty"`
	State           string   `json:"state,omitempty"`           // IN_TRANSIT, AT_REST, IN_USE
	CryptoLibraries []string `json:"cryptoLibraries,omitempty"` // OpenSSL, BoringSSL, etc.

	// Certificate-specific (optional)
	Subject      string     `json:"subject,omitempty"`
	Issuer       string     `json:"issuer,omitempty"`
	SerialNumber string     `json:"serialNumber,omitempty"`
	NotBefore    *time.Time `json:"notBefore,omitempty"`
	NotAfter     *time.Time `json:"notAfter,omitempty"`
	IsCA         bool       `json:"isCA,omitempty"`

	// Revocation status (for OCSP/CRL checking)
	RevocationStatus string   `json:"revocationStatus,omitempty"` // "GOOD", "REVOKED", "UNKNOWN", "ERROR"
	OCSPResponder    string   `json:"ocspResponder,omitempty"`
	CRLDistPoints    []string `json:"crlDistributionPoints,omitempty"`

	// Chain position (for TLS chain analysis)
	ChainPosition string `json:"chainPosition,omitempty"` // "leaf", "intermediate", "root"
	ChainDepth    int    `json:"chainDepth,omitempty"`

	// TLS probing (protocol scanner)
	KeyExchange    string   `json:"keyExchange,omitempty"`    // "ECDHE", "DHE", "RSA", "TLS13"
	ForwardSecrecy bool     `json:"forwardSecrecy,omitempty"` // true if ECDHE/DHE
	SANs           []string `json:"sans,omitempty"`           // Subject Alternative Names

	// Container image annotation (populated by OCIImageModule delegation
	// wrapper). Empty on filesystem-scan findings.
	ImageRef    string `json:"imageRef,omitempty"`
	ImageDigest string `json:"imageDigest,omitempty"`
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

	// CAMM (Cryptographic Agility Maturity Model)
	CAMMLevel      int      `json:"cammLevel,omitempty"`
	CAMMConfidence string   `json:"cammConfidence,omitempty"`
	CAMMIndicators []string `json:"cammIndicators,omitempty"`

	// NACSA Compliance
	NACSAReadinessPercent float64 `json:"nacsaReadinessPercent,omitempty"`
	NACSAPatuh            int     `json:"nacsaPatuh,omitempty"`
	NACSAPeralihan        int     `json:"nacsaPeralihan,omitempty"`
	NACSATidakPatuh       int     `json:"nacsaTidakPatuh,omitempty"`
	NACSATindakanSegera   int     `json:"nacsaTindakanSegera,omitempty"`
}

// ScanTarget defines a target for scanning.
type ScanTarget struct {
	Type  ScanTargetType `json:"type"`
	Value string         `json:"value"`
	Depth int            `json:"depth"`
}

// AllCategories returns the full list of CBOM scanning categories (1-9).
func AllCategories() []int {
	return []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
}

// ComputeSummary calculates aggregate statistics from a list of findings.
func ComputeSummary(findings []Finding) Summary {
	s := Summary{
		TotalFindings: len(findings),
	}

	scannedSet := make(map[int]bool)

	for i := range findings {
		if findings[i].Category >= 1 && findings[i].Category <= 9 {
			scannedSet[findings[i].Category] = true
		}

		if findings[i].CryptoAsset == nil {
			continue
		}
		s.TotalCryptoAssets++

		switch findings[i].CryptoAsset.PQCStatus {
		case PQCStatusSafe:
			s.Safe++
		case PQCStatusTransitional:
			s.Transitional++
		case PQCStatusDeprecated:
			s.Deprecated++
		case PQCStatusUnsafe:
			s.Unsafe++
		}
	}

	// Populate categories scanned/skipped
	for _, cat := range AllCategories() {
		if scannedSet[cat] {
			s.CategoriesScanned = append(s.CategoriesScanned, cat)
		} else {
			s.CategoriesSkipped = append(s.CategoriesSkipped, cat)
		}
	}

	return s
}
