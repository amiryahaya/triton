package scanner

import (
	"regexp"
	"strings"
)

// PatternKind distinguishes between literal string matching and regex matching.
const (
	PatternLiteral = 0
	PatternRegex   = 1
)

// CryptoPattern defines a single crypto detection pattern used by script and webapp scanners.
type CryptoPattern struct {
	Kind            int            // PatternLiteral or PatternRegex
	Literal         string         // Used when Kind == PatternLiteral
	Regex           *regexp.Regexp // Used when Kind == PatternRegex
	Algorithm       string         // Canonical algorithm name (empty = informational match only)
	Function        string         // Human-readable function description
	DetectionMethod string         // symbol, string, import, api-call, command, configuration
}

// Match returns true if the pattern matches the given content.
func (p *CryptoPattern) Match(content string) bool {
	if p.Kind == PatternLiteral {
		return strings.Contains(content, p.Literal)
	}
	return p.Regex.MatchString(content)
}

// lit creates a literal-match CryptoPattern (faster than regex, ~65% of patterns).
func lit(literal, algorithm, function, detection string) CryptoPattern {
	return CryptoPattern{
		Kind:            PatternLiteral,
		Literal:         literal,
		Algorithm:       algorithm,
		Function:        function,
		DetectionMethod: detection,
	}
}

// rx creates a regex-match CryptoPattern (needed for complex patterns, ~35%).
func rx(pattern, algorithm, function, detection string) CryptoPattern {
	return CryptoPattern{
		Kind:            PatternRegex,
		Regex:           regexp.MustCompile(pattern),
		Algorithm:       algorithm,
		Function:        function,
		DetectionMethod: detection,
	}
}
