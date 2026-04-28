// Package credentials implements operator-defined credential profiles,
// sealed-box delivery to engines, and operator-triggered connectivity
// tests. See docs/plans/2026-04-14-onboarding-phase-4-credentials-plan.md
// for the full design.
package credentials

import (
	"time"

	"github.com/google/uuid"
)

// AuthType enumerates the authentication mechanisms a credentials
// profile can encode. Values mirror the CHECK constraint on
// credentials_profiles.auth_type.
type AuthType string

const (
	AuthSSHPassword    AuthType = "ssh-password"
	AuthSSHKey         AuthType = "ssh-key"
	AuthWinRMPassword  AuthType = "winrm-password"
	AuthBootstrapAdmin AuthType = "bootstrap-admin"
)

// Matcher describes which inventory hosts a credentials profile applies
// to. All specified predicates must match (AND semantics). An empty
// Matcher matches every host in the org. Tags require every (k,v)
// pair to be present on the host with matching values.
type Matcher struct {
	GroupIDs []uuid.UUID       `json:"group_ids,omitempty"`
	OS       string            `json:"os,omitempty"`
	CIDR     string            `json:"cidr,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// Profile is a named credentials bundle authored by an operator. The
// actual secret never lives on the server — only SecretRef (an opaque
// UUID the engine uses as a keystore handle) is persisted.
type Profile struct {
	ID           uuid.UUID  `json:"id"`
	OrgID        uuid.UUID  `json:"org_id"`
	EngineID     uuid.UUID  `json:"engine_id"`
	Name         string     `json:"name"`
	AuthType     AuthType   `json:"auth_type"`
	Matcher      Matcher    `json:"matcher"`
	SecretRef    uuid.UUID  `json:"secret_ref"`
	CreatedBy    uuid.UUID  `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	LastTestedAt *time.Time `json:"last_tested_at,omitempty"`
}

// DeliveryKind distinguishes secret push (new ciphertext) from secret
// delete (tombstone — engine should drop the SecretRef from its
// keystore).
type DeliveryKind string

const (
	DeliveryPush   DeliveryKind = "push"
	DeliveryDelete DeliveryKind = "delete"
)

// Delivery is one queued payload for a consumer. Ciphertext
// is the sealed-box blob (nil for delete rows).
//
// JSON tags are REQUIRED — this struct is emitted verbatim on the
// wire by GatewayHandlers.PollDelivery and the engine client decodes
// it into client.DeliveryPayload keyed on these exact snake_case
// names. Do not drop or rename tags without updating the client.
// []byte Ciphertext is marshalled as base64 by encoding/json, which
// matches the client's `string` decode.
type Delivery struct {
	ID          uuid.UUID    `json:"id"`
	OrgID       uuid.UUID    `json:"org_id"`
	EngineID    uuid.UUID    `json:"engine_id"`
	ProfileID   *uuid.UUID   `json:"profile_id,omitempty"` // nullable: delete rows can outlive their profile
	SecretRef   uuid.UUID    `json:"secret_ref"`
	AuthType    AuthType     `json:"auth_type"`
	Kind        DeliveryKind `json:"kind"`
	Ciphertext  []byte       `json:"ciphertext,omitempty"`
	Status      string       `json:"status"`
	Error       string       `json:"error,omitempty"`
	RequestedAt time.Time    `json:"requested_at"`
	ClaimedAt   *time.Time   `json:"claimed_at,omitempty"`
	AckedAt     *time.Time   `json:"acked_at,omitempty"`
}

// TestJob is an operator request for the engine to probe a set of
// inventory hosts using the named profile's credentials.
type TestJob struct {
	ID          uuid.UUID   `json:"id"`
	OrgID       uuid.UUID   `json:"org_id"`
	EngineID    uuid.UUID   `json:"engine_id"`
	ProfileID   uuid.UUID   `json:"profile_id"`
	HostIDs     []uuid.UUID `json:"host_ids"`
	Status      string      `json:"status"`
	Error       string      `json:"error,omitempty"`
	RequestedAt time.Time   `json:"requested_at"`
	ClaimedAt   *time.Time  `json:"claimed_at,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
}

// TestResult is the per-host outcome of a TestJob probe.
type TestResult struct {
	TestID    uuid.UUID `json:"test_id"`
	HostID    uuid.UUID `json:"host_id"`
	Success   bool      `json:"success"`
	LatencyMs int       `json:"latency_ms"`
	Error     string    `json:"error,omitempty"`
	ProbedAt  time.Time `json:"probed_at"`
}

// HostSummary has moved to pkg/server/hostmatch to break a potential
// import cycle between credentials handlers (which need inventory) and
// inventory's ListHostSummaries (which returns the projection). Callers
// should import hostmatch.HostSummary directly.
