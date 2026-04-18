package jobrunner

import "time"

// State enumerates the observable states of a detached scan.
type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateDone      State = "done"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
)

// IsTerminal reports whether the state is final (won't transition further).
func (s State) IsTerminal() bool {
	switch s {
	case StateDone, StateFailed, StateCancelled:
		return true
	}
	return false
}

// Status is the on-disk contract for ~/.triton/jobs/<job-id>/status.json.
// Stable fields — adding new ones is safe; removing/renaming is breaking.
type Status struct {
	JobID         string     `json:"job_id"`
	PID           int        `json:"pid"`
	State         State      `json:"state"`
	StartedAt     time.Time  `json:"started_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CompletedAt   *time.Time `json:"completed_at"`
	ProgressPct   float64    `json:"progress_pct"`
	CurrentModule string     `json:"current_module"`
	FindingsCount int        `json:"findings_count"`
	RSSMB         int        `json:"rss_mb"`
	Limits        string     `json:"limits"`
	Error         string     `json:"error"`
	Host          string     `json:"host"`
	TritonVersion string     `json:"triton_version"`
	Profile       string     `json:"profile"`
}

// InitialStatus returns a fresh Status with state=running, StartedAt=now.
// Host is populated from os.Hostname() by the caller (not here to avoid a
// syscall in test paths).
func InitialStatus(jobID string, pid int, profile, version, limits string) *Status {
	now := time.Now().UTC()
	return &Status{
		JobID:         jobID,
		PID:           pid,
		State:         StateRunning,
		StartedAt:     now,
		UpdatedAt:     now,
		TritonVersion: version,
		Limits:        limits,
		Profile:       profile,
	}
}

// MarkTerminal transitions the status to a terminal state and records the
// completion time and error message (if err is non-nil). Does nothing if
// the state is already terminal (sticky terminal states).
func (s *Status) MarkTerminal(next State, err error) {
	if s.State.IsTerminal() {
		return
	}
	s.State = next
	now := time.Now().UTC()
	s.UpdatedAt = now
	s.CompletedAt = &now
	if err != nil {
		s.Error = err.Error()
	}
}

// Touch updates UpdatedAt to now. Called by the status writer loop.
func (s *Status) Touch() {
	s.UpdatedAt = time.Now().UTC()
}
