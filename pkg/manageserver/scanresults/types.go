// Package scanresults owns the `manage_scan_results_queue` bounded
// context: the outbox of completed scan payloads waiting to be pushed
// to the upstream Report Server via mTLS. Types here are the stable
// surface shared between the postgres store, the drain goroutine, the
// orchestrator bridge, and the admin HTTP handlers.
package scanresults

import (
	"time"

	"github.com/google/uuid"
)

// QueueRow models one row of `manage_scan_results_queue`. Consumers of
// ClaimDue read these directly; PayloadJSON is the opaque wrapper
// Enqueue assembled — never unwrap it here, just forward the bytes to
// the Report Server unchanged.
//
// ScanJobID is a pointer because agent-submitted rows (from the :8443
// gateway) carry no originating scan_job row; migration v7 made the
// column nullable. Manage-orchestrated rows always populate it.
type QueueRow struct {
	ID            uuid.UUID
	ScanJobID     *uuid.UUID
	SourceType    string
	SourceID      uuid.UUID
	PayloadJSON   []byte
	EnqueuedAt    time.Time
	NextAttemptAt time.Time
	AttemptCount  int
	LastError     string
}

// Status is the JSON body of GET /api/v1/admin/push-status. The struct
// tags pin the wire format; reordering the fields is a breaking change
// for the Manage admin UI.
type Status struct {
	QueueDepth          int64      `json:"queue_depth"`
	OldestRowAgeSeconds int64      `json:"oldest_row_age_seconds"`
	LastPushError       string     `json:"last_push_error"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastPushedAt        *time.Time `json:"last_pushed_at,omitempty"`
}

// PushCreds holds the mTLS bundle the drain goroutine uses to reach
// the upstream Report Server. The drain loads this once at startup;
// Batch G's auto-enrol flow persists it via SavePushCreds after the
// signed-token hand-off.
type PushCreds struct {
	ClientCertPEM string
	ClientKeyPEM  string
	CACertPEM     string
	ReportURL     string
	TenantID      string
}
