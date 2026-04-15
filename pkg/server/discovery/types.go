// Package discovery implements the engine-driven network discovery
// pipeline: operators queue a job targeting one or more CIDRs + ports,
// the engine polls, scans, and streams back candidate addresses, and
// a human (or batch promote-all) lifts candidates into inventory_hosts.
//
// This file defines the domain types. Storage lives in store.go /
// postgres.go; HTTP handlers are wired separately.
package discovery

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// JobStatus is the lifecycle marker for a discovery job.
type JobStatus string

// Job lifecycle states. Transitions:
//
//	queued -> claimed (engine poll picked it up)
//	       -> cancelled (operator aborted before claim)
//	claimed -> running -> completed / failed
//
// cancelled is terminal and only reachable from queued — once an
// engine has claimed a job the server no longer owns it.
const (
	StatusQueued    JobStatus = "queued"
	StatusClaimed   JobStatus = "claimed"
	StatusRunning   JobStatus = "running"
	StatusCompleted JobStatus = "completed"
	StatusFailed    JobStatus = "failed"
	StatusCancelled JobStatus = "cancelled"
)

// Job is a request to an engine to probe one or more CIDRs for hosts
// listening on the named ports. CIDRs and ports are stored as-submitted
// (no normalization) so operators can re-read what they asked for.
type Job struct {
	ID             uuid.UUID
	OrgID          uuid.UUID
	EngineID       uuid.UUID
	RequestedBy    *uuid.UUID // nullable — user may have been deleted
	CIDRs          []string
	Ports          []int
	Status         JobStatus
	Error          string
	RequestedAt    time.Time
	ClaimedAt      *time.Time
	CompletedAt    *time.Time
	CandidateCount int
}

// Candidate is an address the engine reported back as responsive on at
// least one of the requested ports. One row per (job_id, address); the
// engine is expected to dedupe its own probe results, but the store
// enforces idempotency via ON CONFLICT DO NOTHING regardless.
type Candidate struct {
	ID         uuid.UUID
	JobID      uuid.UUID
	Address    net.IP
	Hostname   string // may be empty if rDNS failed or was skipped
	OpenPorts  []int
	DetectedAt time.Time
	Promoted   bool
}
