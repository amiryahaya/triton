package engine

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// Status values for the engines.status column.
const (
	StatusEnrolled = "enrolled"
	StatusOnline   = "online"
	StatusOffline  = "offline"
	StatusRevoked  = "revoked"
)

// Engine represents a single enrolled scanning engine. It is created
// at bundle-issuance time (status=enrolled) and transitions to online
// on the first successful heartbeat. Revocation is admin-driven.
type Engine struct {
	ID              uuid.UUID  `json:"id"`
	OrgID           uuid.UUID  `json:"org_id"`
	Label           string     `json:"label"`
	PublicIP        net.IP     `json:"public_ip,omitempty"`
	CertFingerprint string     `json:"cert_fingerprint"`
	BundleIssuedAt  time.Time  `json:"bundle_issued_at"`
	FirstSeenAt     *time.Time `json:"first_seen_at,omitempty"`
	LastPollAt      *time.Time `json:"last_poll_at,omitempty"`
	Status          string     `json:"status"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

// BundleManifest is the JSON payload bundled into the engine zip
// alongside the cert/key/CA bundle. Engines read it on startup to
// learn their identity, the report-server URL, and which org they
// are enrolled into.
type BundleManifest struct {
	EngineID        uuid.UUID `json:"engine_id"`
	OrgID           uuid.UUID `json:"org_id"`
	Label           string    `json:"label"`
	ReportServerURL string    `json:"report_server_url"`
	IssuedAt        time.Time `json:"issued_at"`
	BundleVersion   int       `json:"bundle_version"`
}
