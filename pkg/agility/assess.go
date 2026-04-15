package agility

import "github.com/amiryahaya/triton/pkg/model"

// AssessAll returns one Score per host in the scan result.
// Returns nil when result is nil or has no findings.
func AssessAll(result *model.ScanResult) []Score {
	if result == nil || len(result.Findings) == 0 {
		return nil
	}
	// Real implementation lands in Task 6.
	return nil
}
