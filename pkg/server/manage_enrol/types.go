// Package manage_enrol owns the Report-side registry of enrolled Manage
// Server instances. An enrolment is the hand-off that mints an mTLS client
// leaf signed by Report's engine CA and hands Manage a bundle containing
// that leaf, the CA cert, and the deployment's public Report URL.
//
// Once enrolled, a Manage instance authenticates every upstream scan-result
// POST with its client cert. The engine MTLSMiddleware recognises the
// `manage:<licenseHash>:<instanceID>` CN prefix and resolves the row via
// Store.GetByCertSerial.
package manage_enrol

import (
	"time"

	"github.com/google/uuid"
)

// Status values for the manage_instances.status column.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// ManageInstance is one row of the manage_instances table: the durable
// record of a successful Manage enrolment.
type ManageInstance struct {
	ID                uuid.UUID
	LicenseKeyHash    string
	CertSerial        string
	TenantAttribution string
	EnrolledAt        time.Time
	Status            string
}
