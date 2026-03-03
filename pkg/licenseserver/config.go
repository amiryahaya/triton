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
}
