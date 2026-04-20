package manageserver

import (
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/manageserver/scanresults"
)

// Compile-time assertion that scanresults.PostgresStore satisfies the
// narrow scanjobs.QueueDepther interface used by the Enqueue handler
// for backpressure. Catches accidental renames / signature drift of
// QueueDepth(ctx) before the test suite runs.
//
// This lives here rather than in either package to avoid an import
// cycle: scanresults cannot import scanjobs (scanjobs depends on
// scanresults.Store for the orchestrator bridge). server.go is the
// one place that already imports both.
var _ scanjobs.QueueDepther = (*scanresults.PostgresStore)(nil)

// Compile-time assertions that *license.Guard satisfies each Batch H
// cap-guard interface. Catches drift between the guard's public API
// (LimitCap, CurrentUsage, SoftBufferCeiling) and the interfaces the
// admin handlers import it by, without the handlers having to pull in
// internal/license directly.
var (
	_ SeatCapGuard          = (*license.Guard)(nil)
	_ hosts.HostCapGuard    = (*license.Guard)(nil)
	_ agents.AgentCapGuard  = (*license.Guard)(nil)
	_ scanjobs.ScanCapGuard = (*license.Guard)(nil)
)
