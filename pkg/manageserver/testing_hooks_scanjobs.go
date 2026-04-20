package manageserver

import "github.com/amiryahaya/triton/pkg/manageserver/scanjobs"

// SetScanCapGuardForTest swaps the scan-cap guard on the scanjobs
// admin handler. Covers LimitCap + CurrentUsage + SoftBufferCeiling
// because the soft-buffer enforcement path consults all three.
//
// Production code never calls this; /startLicence wires the real
// *license.Guard. Pair with ClearSeatCapGuardForTest in t.Cleanup.
// Handlers observe the change on their next request because they
// consult the GuardProvider closure — which reads
// s.scanCapGuardOverride under s.mu — per call.
func SetScanCapGuardForTest(s *Server, g scanjobs.ScanCapGuard) {
	s.mu.Lock()
	s.scanCapGuardOverride = g
	s.mu.Unlock()
}
