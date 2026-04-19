package manageserver

import (
	"crypto/ed25519"
	"time"
)

// Config wires the Manage Server runtime.
type Config struct {
	Listen        string            // admin HTTP listener; e.g. ":8082"
	DBUrl         string            // postgres DSN
	JWTSigningKey []byte            // HS256 secret; ≥32 bytes
	PublicKey     ed25519.PublicKey // License Server public key (for parsing signed tokens)
	InstanceID    string            // UUID for this Manage instance
	SessionTTL    time.Duration     // default 24h

	// Parallelism is the scan-orchestrator worker count (Batch E).
	// Zero defaults to 10 inside NewOrchestrator; negative is clamped
	// there too. Capped at 50 to bound Postgres connection usage.
	Parallelism int

	// GatewayListen is the :8443 mTLS listener address for agent
	// phone-home + scan ingestion (Batch F). Default ":8443".
	GatewayListen string

	// GatewayHostname is the DNS name or IP that admins publish to
	// agents — becomes the CN + SAN of the gateway's server leaf. For
	// local tests this is typically "127.0.0.1" or "localhost".
	GatewayHostname string

	// ManageGatewayURL is the URL enrolled agents dial (baked into the
	// bundle's config.yaml). If empty, Server.Run derives it from
	// GatewayHostname + GatewayListen.
	ManageGatewayURL string

	// Reserved for B2 — unused here, but config carries them so B2 is a drop-in.
	ReportServer string //nolint:unused // wired in B2
}
