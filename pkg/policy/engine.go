package policy

import (
	"fmt"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// Verdict is the overall policy evaluation outcome.
type Verdict string

const (
	VerdictPass Verdict = "PASS"
	VerdictFail Verdict = "FAIL"
	VerdictWarn Verdict = "WARN"
)

// ExemptionList holds active and expired exemptions. Real type populated in Task 3.
type ExemptionList struct{}

// RiskSummary counts violations by risk level.
type RiskSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Violation records a single policy rule that was triggered.
type Violation struct {
	RuleID    string         `json:"ruleID"`
	Severity  string         `json:"severity"`
	Action    string         `json:"action"`
	Message   string         `json:"message"`
	RiskLevel string         `json:"riskLevel,omitempty"`
	Finding   *model.Finding `json:"finding,omitempty"`
}

// ThresholdViolation records a threshold that was not met.
type ThresholdViolation struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Message  string `json:"message"`
}

// SystemEvaluation holds policy results for a single system.
type SystemEvaluation struct {
	SystemName          string               `json:"systemName"`
	Verdict             Verdict              `json:"verdict"`
	Violations          []Violation          `json:"violations,omitempty"`
	ThresholdViolations []ThresholdViolation `json:"thresholdViolations,omitempty"`
	FindingsChecked     int                  `json:"findingsChecked"`
}

// EvaluationResult holds the complete policy evaluation outcome.
type EvaluationResult struct {
	PolicyName          string               `json:"policyName"`
	Verdict             Verdict              `json:"verdict"`
	Violations          []Violation          `json:"violations,omitempty"`
	ThresholdViolations []ThresholdViolation `json:"thresholdViolations,omitempty"`
	RulesEvaluated      int                  `json:"rulesEvaluated"`
	FindingsChecked     int                  `json:"findingsChecked"`
	SystemEvaluations   []SystemEvaluation   `json:"systemEvaluations,omitempty"`
	RiskSummary         *RiskSummary         `json:"riskSummary,omitempty"`
}

// riskLevelDefault is the risk level assigned when a rule omits risk_level.
const riskLevelDefault = "medium"

// Evaluate runs the policy rules and thresholds against a scan result.
// exemptions is reserved for Task 3; pass nil until then.
func Evaluate(pol *Policy, result *model.ScanResult, _ *ExemptionList) *EvaluationResult {
	if pol == nil || result == nil {
		return &EvaluationResult{
			Verdict: VerdictFail,
			Violations: []Violation{{
				RuleID:    "system",
				Severity:  "error",
				Action:    "fail",
				Message:   "nil policy or scan result",
				RiskLevel: riskLevelDefault,
			}},
		}
	}

	eval := &EvaluationResult{
		PolicyName:      pol.Name,
		Verdict:         VerdictPass,
		RulesEvaluated:  len(pol.Rules),
		FindingsChecked: len(result.Findings),
	}

	// Evaluate rules against findings.
	for i := range result.Findings {
		f := &result.Findings[i]
		for j := range pol.Rules {
			rule := &pol.Rules[j]
			if matchesCondition(f, &rule.Condition) {
				msg := rule.Message
				if msg == "" {
					msg = defaultMessage(f, rule)
				}
				rl := rule.RiskLevel
				if rl == "" {
					rl = riskLevelDefault
				}
				eval.Violations = append(eval.Violations, Violation{
					RuleID:    rule.ID,
					Severity:  rule.Severity,
					Action:    rule.Action,
					Message:   msg,
					RiskLevel: rl,
					Finding:   f,
				})
				if rule.Action == "fail" {
					eval.Verdict = VerdictFail
				} else if rule.Action == "warn" && eval.Verdict == VerdictPass {
					eval.Verdict = VerdictWarn
				}
			}
		}
	}

	// Evaluate thresholds.
	evaluateThresholds(pol, result, eval)

	// Per-system evaluation
	systems := model.GroupFindingsIntoSystems(result.Findings)
	for i := range systems {
		sysEval := EvaluateSystem(pol, &systems[i])
		eval.SystemEvaluations = append(eval.SystemEvaluations, sysEval)
		// Worst per-system verdict escalates overall verdict
		if sysEval.Verdict == VerdictFail && eval.Verdict != VerdictFail {
			eval.Verdict = VerdictFail
		} else if sysEval.Verdict == VerdictWarn && eval.Verdict == VerdictPass {
			eval.Verdict = VerdictWarn
		}
	}

	// Compute RiskSummary from violations (nil when no violations).
	if len(eval.Violations) > 0 {
		rs := &RiskSummary{}
		for _, v := range eval.Violations {
			switch strings.ToLower(v.RiskLevel) {
			case "critical":
				rs.Critical++
			case "high":
				rs.High++
			case "low":
				rs.Low++
			default:
				rs.Medium++
			}
		}
		eval.RiskSummary = rs
	}

	return eval
}

// EvaluateSystem evaluates policy rules against a single system's crypto assets.
func EvaluateSystem(pol *Policy, sys *model.System) SystemEvaluation {
	sysEval := SystemEvaluation{
		SystemName:      sys.Name,
		Verdict:         VerdictPass,
		FindingsChecked: len(sys.CryptoAssets),
	}

	// Build synthetic findings from system crypto assets for rule evaluation
	for i := range sys.CryptoAssets {
		asset := &sys.CryptoAssets[i]
		f := &model.Finding{
			CryptoAsset: asset,
		}

		for j := range pol.Rules {
			rule := &pol.Rules[j]
			// For system-scoped rules, check SystemPattern against system name
			if rule.Condition.SystemPattern != "" {
				if !matchSystemPattern(sys.Name, rule.Condition.SystemPattern) {
					continue
				}
			}
			if matchesConditionForAsset(asset, &rule.Condition) {
				msg := rule.Message
				if msg == "" {
					msg = fmt.Sprintf("[%s] %s: %s in system %s", rule.ID, rule.Severity, asset.Algorithm, sys.Name)
				}
				rl := rule.RiskLevel
				if rl == "" {
					rl = riskLevelDefault
				}
				sysEval.Violations = append(sysEval.Violations, Violation{
					RuleID:    rule.ID,
					Severity:  rule.Severity,
					Action:    rule.Action,
					Message:   msg,
					RiskLevel: rl,
					Finding:   f,
				})
				if rule.Action == "fail" {
					sysEval.Verdict = VerdictFail
				} else if rule.Action == "warn" && sysEval.Verdict == VerdictPass {
					sysEval.Verdict = VerdictWarn
				}
			}
		}
	}

	// Evaluate per-system thresholds
	evaluatePerSystemThresholds(pol, sys, &sysEval)

	return sysEval
}

// matchesConditionForAsset tests whether a crypto asset matches a rule condition
// (without needing a full Finding). Returns false for conditions that require
// Finding-level metadata (Module, Category) since assets lack that context.
func matchesConditionForAsset(a *model.CryptoAsset, c *Condition) bool {
	// Skip rules that filter on Finding-level fields unavailable in asset context
	if c.Module != "" || c.Category > 0 {
		return false
	}
	if c.PQCStatus != "" && !strings.EqualFold(a.PQCStatus, c.PQCStatus) {
		return false
	}
	if c.Algorithm != "" && !strings.EqualFold(a.Algorithm, c.Algorithm) {
		return false
	}
	if c.AlgorithmFamily != "" && !matchesFamily(a, c.AlgorithmFamily) {
		return false
	}
	if c.KeySizeBelow > 0 && (a.KeySize == 0 || a.KeySize >= c.KeySizeBelow) {
		return false
	}
	if c.KeySizeAbove > 0 && (a.KeySize == 0 || a.KeySize <= c.KeySizeAbove) {
		return false
	}
	return true
}

// evaluatePerSystemThresholds checks per-system thresholds.
func evaluatePerSystemThresholds(pol *Policy, sys *model.System, sysEval *SystemEvaluation) {
	for _, st := range pol.Thresholds.PerSystem {
		if !matchSystemPattern(sys.Name, st.SystemPattern) {
			continue
		}

		// Count per-status
		var safe, unsafe, deprecated, total int
		for i := range sys.CryptoAssets {
			total++
			switch strings.ToUpper(sys.CryptoAssets[i].PQCStatus) {
			case "SAFE":
				safe++
			case "UNSAFE":
				unsafe++
			case "DEPRECATED":
				deprecated++
			}
		}

		if st.MaxUnsafeCount != nil && unsafe > *st.MaxUnsafeCount {
			tv := ThresholdViolation{
				Name:     "per_system_max_unsafe",
				Expected: fmt.Sprintf("<= %d", *st.MaxUnsafeCount),
				Actual:   fmt.Sprintf("%d", unsafe),
				Message:  fmt.Sprintf("System %q: unsafe count %d exceeds maximum %d", sys.Name, unsafe, *st.MaxUnsafeCount),
			}
			sysEval.ThresholdViolations = append(sysEval.ThresholdViolations, tv)
			sysEval.Verdict = VerdictFail
		}

		if st.MaxDeprecated != nil && deprecated > *st.MaxDeprecated {
			tv := ThresholdViolation{
				Name:     "per_system_max_deprecated",
				Expected: fmt.Sprintf("<= %d", *st.MaxDeprecated),
				Actual:   fmt.Sprintf("%d", deprecated),
				Message:  fmt.Sprintf("System %q: deprecated count %d exceeds maximum %d", sys.Name, deprecated, *st.MaxDeprecated),
			}
			sysEval.ThresholdViolations = append(sysEval.ThresholdViolations, tv)
			sysEval.Verdict = VerdictFail
		}

		if st.MinSafePercent > 0 && total > 0 {
			pct := float64(safe) / float64(total) * 100
			if pct < st.MinSafePercent {
				tv := ThresholdViolation{
					Name:     "per_system_min_safe_percent",
					Expected: fmt.Sprintf(">= %.1f%%", st.MinSafePercent),
					Actual:   fmt.Sprintf("%.1f%%", pct),
					Message:  fmt.Sprintf("System %q: safe percentage %.1f%% below minimum %.1f%%", sys.Name, pct, st.MinSafePercent),
				}
				sysEval.ThresholdViolations = append(sysEval.ThresholdViolations, tv)
				sysEval.Verdict = VerdictFail
			}
		}
	}
}

// matchesCondition tests whether a finding matches a rule condition.
func matchesCondition(f *model.Finding, c *Condition) bool {
	if f.CryptoAsset == nil {
		return false
	}
	a := f.CryptoAsset

	if c.SystemPattern != "" && !matchSystemPattern(a.SystemName, c.SystemPattern) {
		return false
	}
	if c.PQCStatus != "" && !strings.EqualFold(a.PQCStatus, c.PQCStatus) {
		return false
	}
	if c.Algorithm != "" && !strings.EqualFold(a.Algorithm, c.Algorithm) {
		return false
	}
	if c.AlgorithmFamily != "" && !matchesFamily(a, c.AlgorithmFamily) {
		return false
	}
	if c.KeySizeBelow > 0 && (a.KeySize == 0 || a.KeySize >= c.KeySizeBelow) {
		return false
	}
	if c.KeySizeAbove > 0 && (a.KeySize == 0 || a.KeySize <= c.KeySizeAbove) {
		return false
	}
	if c.Module != "" && !strings.EqualFold(f.Module, c.Module) {
		return false
	}
	if c.Category > 0 && f.Category != c.Category {
		return false
	}

	return true
}

// matchSystemPattern checks if a system name matches a pattern.
// Supports '*' as a wildcard prefix/suffix (e.g., "TLS*", "*ssl*").
// Uses case-insensitive matching for convenience.
func matchSystemPattern(systemName, pattern string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	name := strings.ToLower(systemName)
	p := strings.ToLower(pattern)

	// Handle common glob patterns without filepath.Match (which fails on slashes)
	if strings.HasPrefix(p, "*") && strings.HasSuffix(p, "*") {
		return strings.Contains(name, p[1:len(p)-1])
	}
	if strings.HasSuffix(p, "*") {
		return strings.HasPrefix(name, p[:len(p)-1])
	}
	if strings.HasPrefix(p, "*") {
		return strings.HasSuffix(name, p[1:])
	}
	return name == p
}

// algorithmFamilies maps family identifiers to their known algorithm prefixes.
var algorithmFamilies = map[string][]string{
	"RSA":     {"RSA"},
	"ECDSA":   {"ECDSA", "ECDSA-P"},
	"EDDSA":   {"ED25519", "ED448"},
	"AES":     {"AES"},
	"DES":     {"DES", "3DES", "TRIPLE-DES"},
	"SHA":     {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA1", "SHA256", "SHA384", "SHA512"},
	"SHA3":    {"SHA3"},
	"MD5":     {"MD5"},
	"CHACHA":  {"CHACHA20"},
	"LATTICE": {"ML-KEM", "ML-DSA", "FN-DSA", "FALCON", "KYBER", "DILITHIUM"},
}

// matchesFamily checks if a crypto asset belongs to an algorithm family.
func matchesFamily(a *model.CryptoAsset, family string) bool {
	algo := strings.ToUpper(a.Algorithm)
	fam := strings.ToUpper(family)

	// Direct prefix match.
	if strings.HasPrefix(algo, fam) {
		return true
	}

	// Known family mappings.
	if members, ok := algorithmFamilies[fam]; ok {
		for _, m := range members {
			if strings.HasPrefix(algo, m) {
				return true
			}
		}
	}
	return false
}

// evaluateThresholds checks aggregate thresholds.
func evaluateThresholds(pol *Policy, result *model.ScanResult, eval *EvaluationResult) {
	t := &pol.Thresholds
	s := &result.Summary

	if t.MaxUnsafeCount != nil && s.Unsafe > *t.MaxUnsafeCount {
		tv := ThresholdViolation{
			Name:     "max_unsafe_count",
			Expected: fmt.Sprintf("<= %d", *t.MaxUnsafeCount),
			Actual:   fmt.Sprintf("%d", s.Unsafe),
			Message:  fmt.Sprintf("Unsafe algorithm count %d exceeds maximum %d", s.Unsafe, *t.MaxUnsafeCount),
		}
		eval.ThresholdViolations = append(eval.ThresholdViolations, tv)
		eval.Verdict = VerdictFail
	}

	if t.MaxDeprecated != nil && s.Deprecated > *t.MaxDeprecated {
		tv := ThresholdViolation{
			Name:     "max_deprecated_count",
			Expected: fmt.Sprintf("<= %d", *t.MaxDeprecated),
			Actual:   fmt.Sprintf("%d", s.Deprecated),
			Message:  fmt.Sprintf("Deprecated algorithm count %d exceeds maximum %d", s.Deprecated, *t.MaxDeprecated),
		}
		eval.ThresholdViolations = append(eval.ThresholdViolations, tv)
		eval.Verdict = VerdictFail
	}

	if t.MinNACSAReadiness > 0 {
		readiness := s.NACSAReadinessPercent
		if readiness < t.MinNACSAReadiness {
			tv := ThresholdViolation{
				Name:     "min_nacsa_readiness",
				Expected: fmt.Sprintf(">= %.1f%%", t.MinNACSAReadiness),
				Actual:   fmt.Sprintf("%.1f%%", readiness),
				Message:  fmt.Sprintf("NACSA readiness %.1f%% below minimum %.1f%%", readiness, t.MinNACSAReadiness),
			}
			eval.ThresholdViolations = append(eval.ThresholdViolations, tv)
			eval.Verdict = VerdictFail
		}
	}

	if t.MinSafePercent > 0 {
		total := s.Safe + s.Transitional + s.Deprecated + s.Unsafe
		pct := 0.0
		if total > 0 {
			pct = float64(s.Safe) / float64(total) * 100
		}
		if pct < t.MinSafePercent {
			tv := ThresholdViolation{
				Name:     "min_safe_percent",
				Expected: fmt.Sprintf(">= %.1f%%", t.MinSafePercent),
				Actual:   fmt.Sprintf("%.1f%%", pct),
				Message:  fmt.Sprintf("Safe algorithm percentage %.1f%% below minimum %.1f%%", pct, t.MinSafePercent),
			}
			eval.ThresholdViolations = append(eval.ThresholdViolations, tv)
			eval.Verdict = VerdictFail
		}
	}
}

func defaultMessage(f *model.Finding, rule *Rule) string {
	algo := ""
	if f.CryptoAsset != nil {
		algo = f.CryptoAsset.Algorithm
	}
	source := f.Source.Path
	if source == "" {
		source = f.Source.Endpoint
	}
	return fmt.Sprintf("[%s] %s: %s found at %s", rule.ID, rule.Severity, algo, source)
}

// ToModelResult converts an EvaluationResult to the model type for storage/rendering.
func (e *EvaluationResult) ToModelResult() *model.PolicyEvaluationResult {
	if e == nil {
		return nil
	}
	r := &model.PolicyEvaluationResult{
		PolicyName:      e.PolicyName,
		Verdict:         string(e.Verdict),
		RulesEvaluated:  e.RulesEvaluated,
		FindingsChecked: e.FindingsChecked,
	}
	for _, v := range e.Violations {
		r.Violations = append(r.Violations, model.PolicyViolation{
			RuleID:    v.RuleID,
			Severity:  v.Severity,
			Action:    v.Action,
			Message:   v.Message,
			RiskLevel: v.RiskLevel,
		})
	}
	if e.RiskSummary != nil {
		r.RiskSummary = &model.RiskSummary{
			Critical: e.RiskSummary.Critical,
			High:     e.RiskSummary.High,
			Medium:   e.RiskSummary.Medium,
			Low:      e.RiskSummary.Low,
		}
	}
	for _, tv := range e.ThresholdViolations {
		r.ThresholdViolations = append(r.ThresholdViolations, model.PolicyThresholdViolation{
			Name:     tv.Name,
			Expected: tv.Expected,
			Actual:   tv.Actual,
			Message:  tv.Message,
		})
	}
	for _, se := range e.SystemEvaluations {
		mse := model.PolicySystemEvaluation{
			SystemName:      se.SystemName,
			Verdict:         string(se.Verdict),
			FindingsChecked: se.FindingsChecked,
		}
		for _, v := range se.Violations {
			mse.Violations = append(mse.Violations, model.PolicyViolation{
				RuleID:    v.RuleID,
				Severity:  v.Severity,
				Action:    v.Action,
				Message:   v.Message,
				RiskLevel: v.RiskLevel,
			})
		}
		for _, tv := range se.ThresholdViolations {
			mse.ThresholdViolations = append(mse.ThresholdViolations, model.PolicyThresholdViolation{
				Name:     tv.Name,
				Expected: tv.Expected,
				Actual:   tv.Actual,
				Message:  tv.Message,
			})
		}
		r.SystemEvaluations = append(r.SystemEvaluations, mse)
	}
	return r
}
