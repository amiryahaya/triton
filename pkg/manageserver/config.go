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

	// GatewayRetryInterval is how often gatewayRetryLoop polls caStore.Load
	// when CA is not yet bootstrapped. Default 5s; tests override to shorter
	// for deterministic fast-path coverage.
	GatewayRetryInterval time.Duration

	// ReportServer is the base URL Manage calls to auto-enrol via
	// /api/v1/admin/enrol/manage during /setup/license. Empty = skip
	// auto-enrol (best-effort; admin can re-trigger later). Batch G.
	ReportServer string

	// ReportServiceKey is the shared secret sent as the
	// X-Triton-Service-Key header on the auto-enrol POST. Must match the
	// ServiceKey configured on the Report server's admin API. Empty skips
	// auto-enrol even when ReportServer is set. Batch G.
	ReportServiceKey string

	// WatcherTickInterval is the polling interval for the pending-deactivation
	// watcher goroutine. Zero defaults to 10s. Tests set this to ~100ms for
	// deterministic fast-path coverage.
	WatcherTickInterval time.Duration

	// HostIP and HostHostname override auto-detection in the "Register this
	// machine" (POST /hosts/self) endpoint. Required when the server runs
	// inside a container — set to the host's real LAN IP/hostname so the
	// inventory entry reflects the physical machine, not the container.
	// Controlled via TRITON_MANAGE_HOST_IP / TRITON_MANAGE_HOST_HOSTNAME.
	HostIP       string
	HostHostname string
}
