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

// DiscoveryMaxAddresses is the total-address ceiling the portal enforces
// across all CIDRs in a single job. Mirrors maxAddressesTotal in
// pkg/engine/discovery/scanner.go so operators get immediate 400
// feedback instead of waiting for the engine to fail mid-scan.
const DiscoveryMaxAddresses = 262144

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
	ID             uuid.UUID  `json:"id"`
	OrgID          uuid.UUID  `json:"org_id"`
	EngineID       uuid.UUID  `json:"engine_id"`
	RequestedBy    *uuid.UUID `json:"requested_by,omitempty"`
	CIDRs          []string   `json:"cidrs"`
	Ports          []int      `json:"ports"`
	Status         JobStatus  `json:"status"`
	Error          string     `json:"error,omitempty"`
	RequestedAt    time.Time  `json:"requested_at"`
	ClaimedAt      *time.Time `json:"claimed_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	CandidateCount int        `json:"candidate_count"`
}

// Candidate is an address the engine reported back as responsive on at
// least one of the requested ports. One row per (job_id, address); the
// engine is expected to dedupe its own probe results, but the store
// enforces idempotency via ON CONFLICT DO NOTHING regardless.
type Candidate struct {
	ID         uuid.UUID `json:"id"`
	JobID      uuid.UUID `json:"job_id"`
	Address    net.IP    `json:"address"`
	Hostname   string    `json:"hostname,omitempty"`
	OpenPorts  []int     `json:"open_ports"`
	MACAddress string    `json:"mac_address,omitempty"`
	MACVendor  string    `json:"mac_vendor,omitempty"`
	Services   []string  `json:"services,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
	Promoted   bool      `json:"promoted"`
}
