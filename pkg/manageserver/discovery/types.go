package discovery

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Job represents a network discovery scan job.
type Job struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	CIDR            string     `json:"cidr"`
	Ports           []int      `json:"ports"`
	Status          string     `json:"status"` // queued|running|completed|failed|cancelled
	TotalIPs        int        `json:"total_ips"`
	ScannedIPs      int        `json:"scanned_ips"`
	CancelRequested bool       `json:"cancel_requested"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	ErrorMessage    string     `json:"error_message,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Candidate represents a discovered host that could be imported.
type Candidate struct {
	ID             uuid.UUID  `json:"id"`
	JobID          uuid.UUID  `json:"job_id"`
	IP             string     `json:"ip"`
	Hostname       *string    `json:"hostname,omitempty"`
	OpenPorts      []int      `json:"open_ports"`
	OS             string     `json:"os,omitempty"`
	ExistingHostID *uuid.UUID `json:"existing_host_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// EnqueueReq is the request to enqueue a new discovery job.
type EnqueueReq struct {
	CIDR     string `json:"cidr"`
	Ports    []int  `json:"ports"`
	TotalIPs int    `json:"total_ips"`
}

// ImportItem represents a candidate selected for import.
type ImportItem struct {
	ID       uuid.UUID `json:"id"`
	Hostname string    `json:"hostname"`
}

// ImportResult is the result of importing candidates.
type ImportResult struct {
	Imported int            `json:"imported"`
	Skipped  int            `json:"skipped"`
	Errors   []ImportError  `json:"errors"`
}

// ImportError represents a single import failure.
type ImportError struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// StatusUpdate is used to update a job's status.
type StatusUpdate struct {
	JobID        uuid.UUID  `json:"job_id"`
	Status       string     `json:"status"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

// Sentinel errors for the discovery bounded context.
var (
	ErrNotFound = errors.New("discovery: not found")
	ErrConflict = errors.New("discovery: conflict")
)
