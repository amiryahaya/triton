package server

import (
	"encoding/json"
	"time"
)

// agentPollResponse is the payload returned by GET /api/v1/agent/commands/poll.
// Empty response (no state, no commands) → HTTP 204; handlers return this
// struct only when there is something to send.
type agentPollResponse struct {
	State    agentPollState     `json:"state"`
	Commands []agentPollCommand `json:"commands,omitempty"`
}

type agentPollState struct {
	// PausedUntil is the UTC time until which the agent should pause.
	// Zero value serializes as an omitted field, which the agent reads
	// as "not paused" — same semantics as a past value.
	PausedUntil time.Time `json:"pausedUntil,omitempty"`
}

type agentPollCommand struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Args      json.RawMessage `json:"args,omitempty"`
	IssuedAt  time.Time       `json:"issuedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
}

// agentResultRequest is the body of POST /api/v1/agent/commands/{id}/result.
// Status is one of "executed", "rejected". Meta is opaque — whatever the
// agent wants to report back for this command type.
type agentResultRequest struct {
	Status string          `json:"status"`
	Meta   json.RawMessage `json:"meta,omitempty"`
}

// adminAgentCommandRequest is the admin enqueue-command body.
type adminAgentCommandRequest struct {
	Type             string          `json:"type"`
	Args             json.RawMessage `json:"args,omitempty"`
	ExpiresInMinutes int             `json:"expiresInMinutes,omitempty"` // default 60
}

// adminPauseRequest is the admin pause body. Exactly one of Until /
// DurationSeconds must be set.
type adminPauseRequest struct {
	Until           *time.Time `json:"until,omitempty"`
	DurationSeconds int        `json:"durationSeconds,omitempty"`
}
