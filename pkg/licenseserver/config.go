package licenseserver

import (
	"crypto/ed25519"

	"github.com/amiryahaya/triton/internal/auth"
)

// Config holds license server configuration.
type Config struct {
	ListenAddr  string
	DBUrl       string
	AdminKeys   []string
	TLSCert     string
	TLSKey      string
	SigningKey  ed25519.PrivateKey // Ed25519 private key for signing tokens
	PublicKey   ed25519.PublicKey  // Corresponding public key
	BinariesDir string             // Directory for uploaded binary files

	// ReportServerURL is the base URL of the report server to push org
	// provisioning events to (e.g., "https://reports.example.com").
	// If empty, handleCreateOrg skips report server provisioning — the
	// org will exist in the license server but not in the report server.
	ReportServerURL string
	// ReportServerServiceKey is the shared secret used as the
	// X-Triton-Service-Key header when calling the report server's
	// admin API. Required alongside ReportServerURL.
	ReportServerServiceKey string

	// Mailer, if non-nil, is used to send admin-invite emails after
	// successful org provisioning. Typically a *ResendMailer built from
	// the RESEND_API_KEY env var. If nil, handlers fall back to
	// returning credentials in the API response for out-of-band delivery.
	Mailer Mailer
	// ReportServerInviteURL is included as the login link in invite
	// emails. Typically "https://reports.example.com/login".
	ReportServerInviteURL string

	// LoginRateLimiterConfig tunes the per-email login rate limit. When
	// zero, DefaultLoginRateLimiterConfig (5 attempts per 15min window,
	// 15min lockout) applies. Tests inject a fast-cycle config here to
	// exercise lockout behavior without 15-minute sleeps.
	LoginRateLimiterConfig *auth.LoginRateLimiterConfig
}
