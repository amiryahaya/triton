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

// Violation records a single policy rule that was triggered.
type Violation struct {
	RuleID   string         `json:"ruleID"`
	Severity string         `json:"severity"`
	Action   string         `json:"action"`
	Message  string         `json:"message"`
	Finding  *model.Finding `json:"finding,omitempty"`
}

// ThresholdViolation records a threshold that was not met.
type ThresholdViolation struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Message  string `json:"message"`
}

// EvaluationResult holds the complete policy evaluation outcome.
type EvaluationResult struct {
	PolicyName          string               `json:"policyName"`
	Verdict             Verdict              `json:"verdict"`
	Violations          []Violation          `json:"violations,omitempty"`
	ThresholdViolations []ThresholdViolation `json:"thresholdViolations,omitempty"`
	RulesEvaluated      int                  `json:"rulesEvaluated"`
	FindingsChecked     int                  `json:"findingsChecked"`
}

// Evaluate runs the policy rules and thresholds against a scan result.
func Evaluate(pol *Policy, result *model.ScanResult) *EvaluationResult {
	if pol == nil || result == nil {
		return &EvaluationResult{
			Verdict: VerdictFail,
			Violations: []Violation{{
				RuleID:   "system",
				Severity: "error",
				Action:   "fail",
				Message:  "nil policy or scan result",
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
				eval.Violations = append(eval.Violations, Violation{
					RuleID:   rule.ID,
					Severity: rule.Severity,
					Action:   rule.Action,
					Message:  msg,
					Finding:  f,
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

	return eval
}

// matchesCondition tests whether a finding matches a rule condition.
func matchesCondition(f *model.Finding, c *Condition) bool {
	if f.CryptoAsset == nil {
		return false
	}
	a := f.CryptoAsset

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
	"LATTICE": {"ML-KEM", "ML-DSA", "KYBER", "DILITHIUM"},
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
