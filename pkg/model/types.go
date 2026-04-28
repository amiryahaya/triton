package model

import (
	"time"
)

// ScanSource identifies which program produced a ScanResult.
type ScanSource string

const (
	ScanSourceAgent    ScanSource = "triton-agent"
	ScanSourcePortscan ScanSource = "triton-portscan"
	ScanSourceSSHAgent ScanSource = "triton-sshagent"
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
	TargetPcap              // pcap file or live network capture
)

// PQC readiness status constants.
const (
	PQCStatusSafe         = "SAFE"
	PQCStatusTransitional = "TRANSITIONAL"
	PQCStatusDeprecated   = "DEPRECATED"
	PQCStatusUnsafe       = "UNSAFE"
)

// QualityWarning is one key-material quality finding (ROCA, Debian PRNG,
// small-prime factor, size-mismatch). Emitted by pkg/crypto/keyquality.
type QualityWarning struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	CVE      string `json:"cve,omitempty"`
}

// PolicyViolation holds a single policy rule violation for report rendering.
type PolicyViolation struct {
	RuleID    string `json:"ruleID"`
	Severity  string `json:"severity"`
	Action    string `json:"action"`
	Message   string `json:"message"`
	RiskLevel string `json:"riskLevel,omitempty"`
	// FindingID links the violation back to the originating finding ID (if any).
	FindingID string `json:"findingID,omitempty"`
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
	RiskSummary         *RiskSummary               `json:"riskSummary,omitempty"`
	ExemptionsApplied   []ExemptionApplied         `json:"exemptionsApplied,omitempty"`
	ExemptionsExpired   []ExemptionExpired         `json:"exemptionsExpired,omitempty"`
}

// RiskSummary holds counts of violations by risk level.
type RiskSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ExemptionApplied records an exemption that suppressed one or more violations.
type ExemptionApplied struct {
	Reason       string `json:"reason"`
	Expires      string `json:"expires,omitempty"`
	ApprovedBy   string `json:"approvedBy,omitempty"`
	FindingCount int    `json:"findingCount"`
	Algorithm    string `json:"algorithm,omitempty"`
	Location     string `json:"location,omitempty"`
}

// ExemptionExpired records an exemption whose expiry date has passed.
type ExemptionExpired struct {
	Algorithm string `json:"algorithm"`
	Location  string `json:"location,omitempty"`
	ExpiredOn string `json:"expiredOn"`
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
	Source             ScanSource     `json:"source,omitempty"`
	ManageServerID     string         `json:"manageServerID,omitempty"`
	ManageServerName   string         `json:"manageServerName,omitempty"`
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

	// QualityWarnings holds key-material-level warnings (ROCA, Debian PRNG,
	// small prime factors, size mismatch) emitted by pkg/crypto/keyquality.
	// Orthogonal to PQCStatus: a SAFE algorithm with a broken key still
	// surfaces here.
	QualityWarnings []QualityWarning `json:"qualityWarnings,omitempty"`

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
	IsSelfSigned bool       `json:"isSelfSigned,omitempty"`

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

	// TLS fingerprinting (pcap observer / passive capture)
	JA3Fingerprint  string `json:"ja3Fingerprint,omitempty"`
	JA3SFingerprint string `json:"ja3sFingerprint,omitempty"`
	JA4Fingerprint  string `json:"ja4Fingerprint,omitempty"`
	JA4SFingerprint string `json:"ja4sFingerprint,omitempty"`
	SNI             string `json:"sni,omitempty"`
	TLSFlowSource   string `json:"tlsFlowSource,omitempty"` // "pcap_file" or "live_capture"

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
