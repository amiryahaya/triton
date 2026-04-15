// Package agility computes multi-dimensional crypto-agility scores per host.
//
// Orthogonal to pkg/crypto.AssessCAMM (maturity level 0-4) and
// pkg/crypto.AssessCryptoAgility (per-asset Malay label): this package
// produces a numerical 0-100 score with actionable recommendations.
package agility

import "time"

// Dimension names (stable identifiers used in reports, JSON, and tests).
const (
	DimPQCCoverage       = "PQC Coverage"
	DimProtocolAgility   = "Protocol Agility"
	DimConfigFlexibility = "Configuration Flexibility"
	DimOperationalReady  = "Operational Readiness"
)

// Effort is a coarse T-shirt sizing of recommendation effort.
type Effort string

const (
	EffortSmall  Effort = "S"
	EffortMedium Effort = "M"
	EffortLarge  Effort = "L"
)

// Signal is a single piece of evidence that contributed to a dimension score.
type Signal struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Contributes int    `json:"contributes"` // signed delta against the dimension baseline
}

// Dimension is one of the four scored dimensions.
type Dimension struct {
	Name        string   `json:"name"`
	Score       int      `json:"score"`  // 0-100
	Weight      float64  `json:"weight"` // contribution to Overall, sums to 1.0 across dimensions
	Signals     []Signal `json:"signals,omitempty"`
	Explanation string   `json:"explanation"`
}

// Recommendation is one actionable next step for a low-scoring dimension.
type Recommendation struct {
	Dimension string `json:"dimension"`
	Action    string `json:"action"`
	Effort    Effort `json:"effort"`
	Impact    int    `json:"impact"` // expected dimension-score delta if applied
}

// Score is the per-host agility assessment.
type Score struct {
	Hostname        string           `json:"hostname"`
	Overall         int              `json:"overall"` // 0-100
	Dimensions      []Dimension      `json:"dimensions"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
	GeneratedAt     time.Time        `json:"generatedAt"`
}
