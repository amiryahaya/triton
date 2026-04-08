package licenseserver

import "crypto/ed25519"

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
}
