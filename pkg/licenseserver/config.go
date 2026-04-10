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

	// ReportServerURL is the base URL the LICENSE SERVER uses to
	// reach the report server from its own process. In a compose
	// deployment this is usually the service-network hostname
	// (e.g., "http://triton:8080") — NOT a URL a customer's agent
	// can resolve. Used for cross-server provisioning calls only.
	ReportServerURL string
	// ReportServerPublicURL is the URL customer AGENTS use to
	// reach the report server from the outside world (e.g.,
	// "https://reports.example.com"). When empty, handlers that
	// need to emit a customer-facing URL (the agent.yaml
	// download, invite emails) fall back to ReportServerURL.
	// Keep these separate because ReportServerURL may live on an
	// internal network hostname that is meaningless to an
	// end-user agent.
	ReportServerPublicURL string
	// ReportServerServiceKey is the shared secret used as the
	// X-Triton-Service-Key header when calling the report server's
	// admin API. Required alongside ReportServerURL.
	ReportServerServiceKey string

	// PublicURL is the customer-facing URL of this license server
	// itself (e.g., "https://license.example.com"). Used by install
	// scripts that call back to download binaries and agent.yaml.
	// When empty, install-token features are disabled (the admin UI
	// hides the "Copy install command" button).
	PublicURL string

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
