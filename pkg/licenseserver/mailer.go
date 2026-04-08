package licenseserver

import (
	"github.com/amiryahaya/triton/internal/mailer"
)

// Mailer and InviteEmailData are re-exported from internal/mailer as
// package-level type aliases so existing pkg/licenseserver callers
// (handlers, tests, cmd wiring) continue to compile unchanged after
// the Phase 5 Sprint 2 extraction. New code should import
// internal/mailer directly.
type (
	Mailer          = mailer.Mailer
	InviteEmailData = mailer.InviteEmailData
	ResendMailer    = mailer.ResendMailer
)

// NewResendMailer constructs a Resend-backed Mailer. Thin re-export of
// the canonical constructor in internal/mailer.
func NewResendMailer(apiKey, fromEmail, fromName string) *ResendMailer {
	return mailer.NewResendMailer(apiKey, fromEmail, fromName)
}
