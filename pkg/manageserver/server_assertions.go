package manageserver

import (
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
