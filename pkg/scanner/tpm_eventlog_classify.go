package scanner

import "github.com/amiryahaya/triton/pkg/scanner/internal/tpmfs"

// classifyEventLog returns a PQC status string summarising the log's hash
// algorithm coverage:
//   - "SAFE" if every algorithm used is SHA-256 or stronger (no SHA-1)
//   - "UNSAFE" if only SHA-1 is used (no modern banks)
//   - "TRANSITIONAL" if both SHA-1 and a modern algorithm are extended
//   - "" if the log is empty (no events)
func classifyEventLog(log *tpmfs.EventLog) string {
	if log == nil || len(log.AlgoCounts) == 0 {
		return ""
	}
	hasSHA1 := log.AlgoCounts[tpmfs.AlgSHA1] > 0
	hasModern := log.AlgoCounts[tpmfs.AlgSHA256]+log.AlgoCounts[tpmfs.AlgSHA384]+log.AlgoCounts[tpmfs.AlgSHA512] > 0
	switch {
	case hasModern && !hasSHA1:
		return "SAFE"
	case hasSHA1 && !hasModern:
		return "UNSAFE"
	case hasSHA1 && hasModern:
		return "TRANSITIONAL"
	}
	return ""
}
