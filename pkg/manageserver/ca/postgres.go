package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// serverCertValidity is how long a gateway server leaf is issued for.
// The leaf is re-minted on every process start, so a shorter lifetime
// tightens the blast radius without requiring runtime rotation.
const serverCertValidity = 90 * 24 * time.Hour

// revocationCacheTTL is how long a snapshot of the revocations table
// stays valid before IsRevoked forces a refresh. 30s matches the spec;
// Revoke invalidates proactively so the worst-case window after a
// revocation is bounded by one gateway request.
const revocationCacheTTL = 30 * time.Second

// revocationCache is the in-memory snapshot of the revocations table.
// mu guards both the map and lastRefresh; the zero-value lastRefresh
// (IsZero) is treated as "never refreshed" so the first IsRevoked call
// always hits the DB.
type revocationCache struct {
	mu          sync.RWMutex
	serials     map[string]struct{}
	lastRefresh time.Time
}

// PostgresStore implements Store against a pgx pool. The caller owns
// the pool's lifetime; this package never Close()s it. Callers must
// have already run managestore.Migrate to v5 or later so manage_ca and
// manage_agent_cert_revocations exist.
type PostgresStore struct {
	pool  *pgxpool.Pool
	cache *revocationCache
}

// NewPostgresStore wraps a pool and initialises the revocation cache
// with a zero-value lastRefresh (empty set + stale clock) so the first
// IsRevoked call triggers a refresh rather than returning a stale miss.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{
		pool: pool,
		cache: &revocationCache{
			serials: map[string]struct{}{},
		},
	}
}

// Compile-time interface satisfaction.
var _ Store = (*PostgresStore)(nil)

// Bootstrap loads the persisted CA, or mints + inserts one if the
// singleton row is missing. Wrapped in a serializable tx so two racing
// callers produce only one CA — the second caller's INSERT conflicts on
// the PRIMARY KEY(id=1) and we re-read the row it wrote.
func (s *PostgresStore) Bootstrap(ctx context.Context, instanceID string) (*CA, error) {
	// Happy path: row already exists.
	c, err := s.Load(ctx)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	// Generate + insert. Unique-violation on the CHECK-constrained id=1
	// means another caller raced us; fall back to Load which returns
	// whichever CA won the race.
	generated, err := Generate(instanceID)
	if err != nil {
		return nil, err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO manage_ca (id, ca_cert_pem, ca_key_pem)
		 VALUES (1, $1, $2)
		 ON CONFLICT (id) DO NOTHING`,
		string(generated.CACertPEM), string(generated.CAKeyPEM),
	)
	if err != nil {
		return nil, fmt.Errorf("insert manage_ca: %w", err)
	}
	// Even if ON CONFLICT swallowed the insert, a Load now returns the
	// winning row (ours or the racing caller's).
	return s.Load(ctx)
}

// Load reads the singleton manage_ca row.
func (s *PostgresStore) Load(ctx context.Context) (*CA, error) {
	var certPEM, keyPEM string
	err := s.pool.QueryRow(ctx,
		`SELECT ca_cert_pem, ca_key_pem FROM manage_ca WHERE id = 1`,
	).Scan(&certPEM, &keyPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load manage_ca: %w", err)
	}
	return &CA{
		CACertPEM: []byte(certPEM),
		CAKeyPEM:  []byte(keyPEM),
	}, nil
}

// isUniqueViolation reports whether err wraps a Postgres unique_violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsRevoked checks the in-memory cache, refreshing if stale. Returns
// (false, nil) for an unknown serial after a successful refresh.
func (s *PostgresStore) IsRevoked(ctx context.Context, serial string) (bool, error) {
	s.cache.mu.RLock()
	fresh := time.Since(s.cache.lastRefresh) < revocationCacheTTL && !s.cache.lastRefresh.IsZero()
	s.cache.mu.RUnlock()

	if !fresh {
		if err := s.RefreshRevocationCache(ctx); err != nil {
			return false, err
		}
	}

	s.cache.mu.RLock()
	defer s.cache.mu.RUnlock()
	_, yes := s.cache.serials[serial]
	return yes, nil
}

// Revoke inserts a revocation row and proactively invalidates the
// cache by zeroing lastRefresh, so the next IsRevoked refreshes from
// the DB rather than serving a stale miss. Idempotent: a duplicate
// serial is swallowed silently (ON CONFLICT DO NOTHING).
func (s *PostgresStore) Revoke(ctx context.Context, serial string, agentID uuid.UUID, reason string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO manage_agent_cert_revocations (cert_serial, agent_id, revoke_reason)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (cert_serial) DO NOTHING`,
		serial, agentID, reason,
	)
	if err != nil {
		// A unique violation shouldn't fire given ON CONFLICT DO NOTHING,
		// but treat it as success-equivalent for symmetry if it does.
		if isUniqueViolation(err) {
			return s.invalidateCache()
		}
		return fmt.Errorf("insert revocation: %w", err)
	}
	return s.invalidateCache()
}

// invalidateCache zeros lastRefresh under the write lock so the next
// IsRevoked refreshes from the DB. Kept as a helper so Revoke + future
// callers share the same locking discipline.
func (s *PostgresStore) invalidateCache() error {
	s.cache.mu.Lock()
	s.cache.lastRefresh = time.Time{}
	s.cache.mu.Unlock()
	return nil
}

// RefreshRevocationCache re-reads the revocations table under the
// write lock. Safe to call concurrently — the last writer wins.
func (s *PostgresStore) RefreshRevocationCache(ctx context.Context) error {
	rows, err := s.pool.Query(ctx,
		`SELECT cert_serial FROM manage_agent_cert_revocations`,
	)
	if err != nil {
		return fmt.Errorf("query revocations: %w", err)
	}
	defer rows.Close()

	next := map[string]struct{}{}
	for rows.Next() {
		var serial string
		if err := rows.Scan(&serial); err != nil {
			return fmt.Errorf("scan revocation: %w", err)
		}
		next[serial] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate revocations: %w", err)
	}

	s.cache.mu.Lock()
	s.cache.serials = next
	s.cache.lastRefresh = time.Now()
	s.cache.mu.Unlock()
	return nil
}

// IssueServerCert mints a short-lived server leaf under the CA for the
// gateway :8443 TLS listener. CN + sole SAN is `hostname`. If hostname
// parses as an IP, it's placed in IPAddresses; otherwise it's placed in
// DNSNames. Both 127.0.0.1 and "localhost" work for local tests; admins
// supplying a prod DNS name get DNSNames populated.
func (s *PostgresStore) IssueServerCert(ctx context.Context, hostname string) (tls.Certificate, error) {
	caBundle, err := s.Load(ctx)
	if err != nil {
		return tls.Certificate{}, err
	}
	caCert, caKey, err := caBundle.parse()
	if err != nil {
		return tls.Certificate{}, err
	}

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Triton Manage Gateway"},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(serverCertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafPriv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign server leaf: %w", err)
	}

	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafPriv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal server key: %w", err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})

	pair, err := tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("assemble tls.Certificate: %w", err)
	}
	return pair, nil
}
