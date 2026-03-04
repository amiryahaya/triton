package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// ldapConn abstracts *ldap.Conn for testability.
type ldapConn interface {
	StartTLS(config *tls.Config) error
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// ldapDialFunc is the function signature for LDAP connection establishment.
type ldapDialFunc func(addr string) (ldapConn, error)

// ldapTarget holds parsed LDAP connection parameters.
type ldapTarget struct {
	scheme   string // "ldap" or "ldaps"
	host     string // host:port
	baseDN   string
	startTLS bool
}

// LDAPModule scans LDAP directories for certificates stored in
// userCertificate;binary and cACertificate;binary attributes.
type LDAPModule struct {
	config *config.Config
	dialFn ldapDialFunc
}

// NewLDAPModule creates a new LDAPModule with production LDAP dialer.
func NewLDAPModule(cfg *config.Config) *LDAPModule {
	return &LDAPModule{
		config: cfg,
		dialFn: defaultLDAPDial,
	}
}

func (m *LDAPModule) Name() string                         { return "ldap" }
func (m *LDAPModule) Category() model.ModuleCategory       { return model.CategoryActiveNetwork }
func (m *LDAPModule) ScanTargetType() model.ScanTargetType { return model.TargetLDAP }

// Scan connects to an LDAP server and extracts certificates.
func (m *LDAPModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	lt, err := parseLDAPTarget(target.Value)
	if err != nil {
		return nil // Skip invalid targets
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	conn, err := m.dialFn(lt.host)
	if err != nil {
		return nil // Connection failed — non-fatal
	}
	defer func() { _ = conn.Close() }()

	// Upgrade to TLS if needed
	if lt.startTLS {
		// InsecureSkipVerify: we're scanning/probing, not validating trust
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			return nil
		}
	}

	// Bind (anonymous or authenticated)
	bindDN, bindPW := ldapBindCreds()
	if bindDN != "" {
		if err := conn.Bind(bindDN, bindPW); err != nil {
			return nil
		}
	}

	// Search for user certificates
	m.searchCerts(ctx, conn, lt, "userCertificate;binary", "LDAP user certificate", findings)

	// Search for CA certificates
	m.searchCerts(ctx, conn, lt, "cACertificate;binary", "LDAP CA certificate", findings)

	return nil
}

// searchCerts searches LDAP for entries with the given binary certificate attribute.
func (m *LDAPModule) searchCerts(ctx context.Context, conn ldapConn, lt ldapTarget, attr, function string, findings chan<- *model.Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	filter := fmt.Sprintf("(%s=*)", attr)
	searchReq := ldap.NewSearchRequest(
		lt.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1000, // size limit to prevent memory pressure on large directories
		30,   // time limit (seconds)
		false,
		filter,
		[]string{attr, "dn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return
	}

	for _, entry := range result.Entries {
		select {
		case <-ctx.Done():
			return
		default:
		}

		for _, certBytes := range entry.GetRawAttributeValues(attr) {
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				continue
			}

			algoName, keySize := certPublicKeyInfo(cert)

			notBefore := cert.NotBefore
			notAfter := cert.NotAfter

			asset := &model.CryptoAsset{
				ID:           uuid.New().String(),
				Function:     function,
				Algorithm:    algoName,
				KeySize:      keySize,
				Subject:      cert.Subject.String(),
				Issuer:       cert.Issuer.String(),
				SerialNumber: cert.SerialNumber.String(),
				NotBefore:    &notBefore,
				NotAfter:     &notAfter,
				IsCA:         cert.IsCA,
				Purpose:      fmt.Sprintf("Certificate from LDAP entry %s", entry.DN),
			}
			crypto.ClassifyCryptoAsset(asset)

			finding := &model.Finding{
				ID:       uuid.New().String(),
				Category: 3,
				Source: model.FindingSource{
					Type:            "ldap",
					Endpoint:        fmt.Sprintf("%s://%s", lt.scheme, lt.host),
					DetectionMethod: "configuration",
				},
				CryptoAsset: asset,
				Confidence:  0.95,
				Module:      "ldap",
				Timestamp:   time.Now(),
			}

			select {
			case findings <- finding:
			case <-ctx.Done():
				return
			}
		}
	}
}

// parseLDAPTarget parses an LDAP target URL into its components.
// Format: ldap://host:port/baseDN or ldaps://host:port/baseDN or ldap://host:port/baseDN?starttls
func parseLDAPTarget(target string) (ldapTarget, error) {
	if target == "" {
		return ldapTarget{}, fmt.Errorf("empty target")
	}

	// Input validation
	if strings.HasPrefix(target, "-") {
		return ldapTarget{}, fmt.Errorf("invalid target: starts with dash")
	}
	if strings.ContainsAny(target, "\n\r\x00") {
		return ldapTarget{}, fmt.Errorf("invalid target: contains control characters")
	}

	u, err := url.Parse(target)
	if err != nil {
		return ldapTarget{}, fmt.Errorf("invalid URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "ldap" && scheme != "ldaps" {
		return ldapTarget{}, fmt.Errorf("unsupported scheme: %s", scheme)
	}

	host := u.Host
	if host == "" {
		return ldapTarget{}, fmt.Errorf("missing host")
	}

	// Validate host
	hostname := u.Hostname()
	if strings.HasPrefix(hostname, "-") {
		return ldapTarget{}, fmt.Errorf("invalid host: starts with dash")
	}

	// Add default port if not specified
	if u.Port() == "" {
		if scheme == "ldaps" {
			host += ":636"
		} else {
			host += ":389"
		}
	}

	baseDN := strings.TrimPrefix(u.Path, "/")
	if baseDN == "" {
		return ldapTarget{}, fmt.Errorf("missing base DN")
	}

	startTLS := u.RawQuery == "starttls"

	return ldapTarget{
		scheme:   scheme,
		host:     host,
		baseDN:   baseDN,
		startTLS: startTLS,
	}, nil
}

// defaultLDAPDial connects to an LDAP server using the go-ldap library with a 10s timeout.
func defaultLDAPDial(addr string) (ldapConn, error) {
	conn, err := ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ldapBindCreds returns bind credentials from environment variables.
// Set TRITON_LDAP_BIND_DN and TRITON_LDAP_BIND_PW for authenticated binds.
// Returns empty strings for anonymous bind when env vars are not set.
func ldapBindCreds() (dn, pw string) {
	return os.Getenv("TRITON_LDAP_BIND_DN"), os.Getenv("TRITON_LDAP_BIND_PW")
}
