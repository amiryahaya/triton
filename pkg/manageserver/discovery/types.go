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
	SSHPort         int        `json:"ssh_port"`
	Status          string     `json:"status"` // queued|running|completed|failed|cancelled
	TotalIPs        int        `json:"total_ips"`
	ScannedIPs      int        `json:"scanned_ips"`
	FoundIPs        int        `json:"found_ips"`
	CancelRequested bool       `json:"cancel_requested"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	ErrorMessage    string     `json:"error_message,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Candidate represents a discovered host with the SSH port open.
type Candidate struct {
	ID             uuid.UUID  `json:"id"`
	JobID          uuid.UUID  `json:"job_id"`
	IP             string     `json:"ip"`
	Hostname       *string    `json:"hostname,omitempty"`
	ExistingHostID *uuid.UUID `json:"existing_host_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// EnqueueReq is the request to start a new discovery job.
type EnqueueReq struct {
	CIDR     string `json:"cidr"`
	SSHPort  int    `json:"ssh_port"`
	TotalIPs int    `json:"total_ips"`
}

// ImportItem is a candidate selected for import.
type ImportItem struct {
	ID       uuid.UUID `json:"id"`
	Hostname string    `json:"hostname"`
}

// ImportResult is the result of an import operation.
type ImportResult struct {
	Imported int           `json:"imported"`
	Skipped  int           `json:"skipped"`
	Errors   []ImportError `json:"errors"`
}

// ImportError represents a single import failure.
type ImportError struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// StatusUpdate carries the fields written by UpdateStatus.
type StatusUpdate struct {
	JobID        uuid.UUID  `json:"job_id"`
	Status       string     `json:"status"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

var (
	ErrNotFound = errors.New("discovery: not found")
	ErrConflict = errors.New("discovery: conflict")
)
