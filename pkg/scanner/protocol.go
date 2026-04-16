package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/tlsutil"
)

const defaultProbeTimeout = 5 * time.Second

// newDialer creates a net.Dialer with a timeout, respecting the context deadline.
func newDialer(ctx context.Context) *net.Dialer {
	timeout := defaultProbeTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	return &net.Dialer{Timeout: timeout}
}

// revocationHTTPTimeout is the max time for OCSP/CRL HTTP requests.
const revocationHTTPTimeout = 5 * time.Second

// ProtocolModule performs active TLS handshake probing to extract cipher suites
// and certificate information from network endpoints.
type ProtocolModule struct {
	config     *scannerconfig.Config
	httpClient *http.Client // injectable for testing
}

func NewProtocolModule(cfg *scannerconfig.Config) *ProtocolModule {
	return &ProtocolModule{
		config: cfg,
		httpClient: &http.Client{
			Timeout: revocationHTTPTimeout,
		},
	}
}

func (m *ProtocolModule) Name() string {
	return "protocol"
}

func (m *ProtocolModule) Category() model.ModuleCategory {
	return model.CategoryActiveNetwork
}

func (m *ProtocolModule) ScanTargetType() model.ScanTargetType {
	return model.TargetNetwork
}

// Scan probes a network target with a TLS handshake and extracts crypto information.
// The target.Value should be a host:port address (e.g., "192.168.1.1:443").
func (m *ProtocolModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	addr := target.Value
	if addr == "" {
		return nil
	}

	return m.probeTLS(ctx, addr, findings)
}

// emitFinding creates and sends a protocol finding with standard fields.
func (m *ProtocolModule) emitFinding(ctx context.Context, addr string, asset *model.CryptoAsset, findings chan<- *model.Finding) error {
	crypto.ClassifyCryptoAsset(asset)

	select {
	case findings <- &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 9,
		Source: model.FindingSource{
			Type:     "network",
			Endpoint: addr,
		},
		CryptoAsset: asset,
		Confidence:  0.90,
		Module:      "protocol",
		Timestamp:   time.Now(),
	}:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// tlsGroupToAsset converts a negotiated TLS named group (from
// tls.ConnectionState.CurveID) into a CryptoAsset. Returns nil if the group
// is not in the registry — unknown groups are skipped to avoid emitting
// findings without classification.
func tlsGroupToAsset(id tls.CurveID) *model.CryptoAsset {
	g, ok := crypto.LookupTLSGroup(uint16(id))
	if !ok {
		return nil
	}
	return &model.CryptoAsset{
		Algorithm:           g.Name,
		Function:            "Key agreement",
		KeySize:             g.KeySize,
		PQCStatus:           string(g.Status),
		IsHybrid:            g.IsHybrid,
		ComponentAlgorithms: g.ComponentAlgorithms,
	}
}

// probeTLS performs a TLS handshake and extracts cipher suite and certificate info.
func (m *ProtocolModule) probeTLS(ctx context.Context, addr string, findings chan<- *model.Finding) error {
	dialer := newDialer(ctx)

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,                     // We're probing, not validating trust
		MinVersion:         tls.VersionTLS10,         // Accept deprecated versions to detect them
		CipherSuites:       allTLS12CipherSuiteIDs(), // Offer all ciphers for audit discovery
	})
	if err != nil {
		return nil // Connection failed — not a TLS service or unreachable
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()

	// Extract cipher suite
	cipherAlgo := cipherSuiteAlgorithm(state.CipherSuite)
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	tlsVersion := tlsVersionName(state.Version)

	kx, pfs := cipherSuiteKeyExchange(cipherName)

	if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
		ID:             uuid.Must(uuid.NewV7()).String(),
		Function:       "TLS cipher suite",
		Algorithm:      cipherAlgo,
		Library:        cipherName,
		Purpose:        fmt.Sprintf("Negotiated cipher for %s (%s)", addr, tlsVersion),
		KeyExchange:    kx,
		ForwardSecrecy: pfs,
	}, findings); err != nil {
		return err
	}

	// Emit warning for deprecated TLS versions
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "TLS protocol version",
			Algorithm: tlsVersion,
			Purpose:   fmt.Sprintf("Deprecated TLS version negotiated by %s", addr),
		}, findings); err != nil {
			return err
		}
	}

	// Extract certificate info from peer certificates with chain position labels
	chainLen := len(state.PeerCertificates)
	for i, cert := range state.PeerCertificates {
		algoName, keySize := certPublicKeyInfo(cert)

		position, function := chainPosition(i, chainLen, cert)

		notBefore := cert.NotBefore
		notAfter := cert.NotAfter

		// Extract OCSP and CRL endpoints from certificate extensions
		var ocspResponder string
		if len(cert.OCSPServer) > 0 {
			ocspResponder = cert.OCSPServer[0]
		}

		if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
			ID:            uuid.Must(uuid.NewV7()).String(),
			Function:      function,
			Algorithm:     algoName,
			KeySize:       keySize,
			Subject:       cert.Subject.String(),
			Issuer:        cert.Issuer.String(),
			SerialNumber:  cert.SerialNumber.String(),
			NotBefore:     &notBefore,
			NotAfter:      &notAfter,
			IsCA:          cert.IsCA,
			Purpose:       fmt.Sprintf("Certificate presented by %s", addr),
			ChainPosition: position,
			ChainDepth:    chainLen,
			OCSPResponder: ocspResponder,
			CRLDistPoints: cert.CRLDistributionPoints,
		}, findings); err != nil {
			return err
		}
	}

	// Emit negotiated TLS named group (key agreement) finding, including hybrid PQC.
	if state.CurveID != 0 {
		if groupAsset := tlsGroupToAsset(state.CurveID); groupAsset != nil {
			groupAsset.ID = uuid.Must(uuid.NewV7()).String()
			groupAsset.Purpose = fmt.Sprintf("Negotiated TLS named group for %s (%s)", addr, tlsVersion)
			if err := m.emitFinding(ctx, addr, groupAsset, findings); err != nil {
				return err
			}
		}
	}

	// Enhanced certificate chain validation (weak sig, expiry, SANs)
	if err := m.enhancedChainValidation(ctx, addr, state.PeerCertificates, findings); err != nil {
		return err
	}

	// Check revocation status via OCSP/CRL
	m.checkRevocation(ctx, addr, state.PeerCertificates, findings)

	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Validate certificate chain against system roots
	m.validateCertChain(ctx, addr, state, findings)

	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Detect session resumption support
	m.detectSessionResumption(ctx, addr, findings)

	if ctx.Err() != nil {
		return ctx.Err()
	}

	// TLS version range probing
	m.probeVersionRange(ctx, addr, findings)

	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Cipher enumeration (TLS 1.2 only)
	supported := m.enumerateSupportedCiphers(ctx, addr)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	m.emitSupportedCipherFindings(ctx, addr, supported, findings)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Cipher preference order
	m.probeCipherPreference(ctx, addr, supported, findings)

	return nil
}

// validateCertChain validates the peer certificate chain against the system root store.
func (m *ProtocolModule) validateCertChain(ctx context.Context, addr string, state tls.ConnectionState, findings chan<- *model.Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	if len(state.PeerCertificates) == 0 {
		return
	}

	leaf := state.PeerCertificates[0]

	roots, err := x509.SystemCertPool()
	if err != nil {
		// System cert pool unavailable — skip validation
		return
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}

	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       host,
	})
	if verifyErr != nil {
		algoName, _ := certPublicKeyInfo(leaf)

		_ = m.emitFinding(ctx, addr, &model.CryptoAsset{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Function:  "TLS certificate chain validation",
			Algorithm: algoName,
			Purpose:   fmt.Sprintf("Certificate chain validation failed for %s: %v", addr, verifyErr),
		}, findings)
	}
}

// probeVersionRange tests which TLS versions the server supports by attempting
// individual connections with each version. Emits a single summary finding.
func (m *ProtocolModule) probeVersionRange(ctx context.Context, addr string, findings chan<- *model.Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	versions := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	var supported []string
	for _, v := range versions {
		select {
		case <-ctx.Done():
			return
		default:
		}

		dialer := newDialer(ctx)

		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v.version,
			MaxVersion:         v.version,
			CipherSuites:       allTLS12CipherSuiteIDs(),
		})
		if err == nil {
			_ = conn.Close()
			supported = append(supported, v.name)
		}
	}

	if len(supported) == 0 {
		return
	}

	var rangeStr string
	if len(supported) == 1 {
		rangeStr = supported[0]
	} else {
		rangeStr = fmt.Sprintf("%s to %s", supported[0], supported[len(supported)-1])
	}
	_ = m.emitFinding(ctx, addr, &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "TLS version range",
		Algorithm: supported[len(supported)-1], // Highest supported version for PQC classification
		Library:   rangeStr,
		Purpose:   fmt.Sprintf("Supported versions: %s", strings.Join(supported, ", ")),
	}, findings)
}

// enumerateSupportedCiphers tests each TLS 1.2 cipher suite individually to determine
// which ones the server supports. Returns a slice of supported cipher suite IDs.
func (m *ProtocolModule) enumerateSupportedCiphers(ctx context.Context, addr string) []uint16 {
	var supported []uint16

	for _, id := range allTLS12CipherSuiteIDs() {
		select {
		case <-ctx.Done():
			return supported
		default:
		}

		dialer := newDialer(ctx)

		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{id},
		})
		if err == nil {
			_ = conn.Close()
			supported = append(supported, id)
		}
	}

	return supported
}

// emitSupportedCipherFindings emits a finding for each supported TLS 1.2 cipher suite.
func (m *ProtocolModule) emitSupportedCipherFindings(ctx context.Context, addr string, supported []uint16, findings chan<- *model.Finding) {
	for _, id := range supported {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cipherName := tls.CipherSuiteName(id)
		algo := cipherSuiteAlgorithm(id)
		kx, pfs := cipherSuiteKeyExchange(cipherName)

		if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
			ID:             uuid.Must(uuid.NewV7()).String(),
			Function:       "TLS supported cipher suite",
			Algorithm:      algo,
			Library:        cipherName,
			KeyExchange:    kx,
			ForwardSecrecy: pfs,
			Purpose:        fmt.Sprintf("Server supports %s", cipherName),
		}, findings); err != nil {
			return
		}
	}
}

// probeCipherPreference determines the server's cipher preference order using
// iterative removal: offer all supported ciphers, note which the server picks,
// remove it, repeat.
func (m *ProtocolModule) probeCipherPreference(ctx context.Context, addr string, supported []uint16, findings chan<- *model.Finding) {
	if len(supported) == 0 {
		return
	}

	remaining := make([]uint16, len(supported))
	copy(remaining, supported)

	var ordered []string

	for len(remaining) > 0 {
		select {
		case <-ctx.Done():
			return
		default:
		}

		dialer := newDialer(ctx)

		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       remaining,
		})
		if err != nil {
			break
		}

		negotiated := conn.ConnectionState().CipherSuite
		_ = conn.Close()

		ordered = append(ordered, tls.CipherSuiteName(negotiated))

		// Remove the negotiated cipher from remaining
		var next []uint16
		for _, id := range remaining {
			if id != negotiated {
				next = append(next, id)
			}
		}
		remaining = next
	}

	if len(ordered) == 0 {
		return
	}

	topAlgo := cipherSuiteAlgorithm(supported[0]) // Get algo from first supported
	// Find the actual first ordered cipher's algorithm
	for _, id := range supported {
		if tls.CipherSuiteName(id) == ordered[0] {
			topAlgo = cipherSuiteAlgorithm(id)
			break
		}
	}

	_ = m.emitFinding(ctx, addr, &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "TLS cipher preference order",
		Algorithm: topAlgo,
		Library:   strings.Join(ordered, " > "),
		Purpose:   fmt.Sprintf("Server cipher preference order (%d ciphers)", len(ordered)),
	}, findings)
}

// enhancedChainValidation inspects peer certificates for weak signatures,
// upcoming expiry, and extracts SANs from the leaf certificate.
// Chain analysis is delegated to tlsutil.WalkCertChain; this method is
// responsible only for emitting findings.
func (m *ProtocolModule) enhancedChainValidation(ctx context.Context, addr string, certs []*x509.Certificate, findings chan<- *model.Finding) error {
	chainLen := len(certs)
	entries := tlsutil.WalkCertChain(certs)

	for _, e := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Weak signature algorithm detection.
		if e.WeakSignature {
			if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
				ID:            uuid.Must(uuid.NewV7()).String(),
				Function:      "Weak certificate signature algorithm",
				Algorithm:     e.WeakSigAlgo,
				Subject:       e.Cert.Subject.String(),
				Issuer:        e.Cert.Issuer.String(),
				ChainPosition: e.Position,
				ChainDepth:    chainLen,
				Purpose:       fmt.Sprintf("Certificate uses weak signature algorithm %s", e.Cert.SignatureAlgorithm),
			}, findings); err != nil {
				return err
			}
		}

		// Certificate expiry warning (within 30 days, but not yet expired).
		if e.ExpiryWarning {
			notAfter := e.Cert.NotAfter
			if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
				ID:            uuid.Must(uuid.NewV7()).String(),
				Function:      "Certificate expiry warning",
				Algorithm:     tlsutil.CertAlgoName(e.Cert),
				Subject:       e.Cert.Subject.String(),
				NotAfter:      &notAfter,
				ChainPosition: e.Position,
				ChainDepth:    chainLen,
				Purpose:       fmt.Sprintf("Certificate expires in %d days", e.DaysRemaining),
			}, findings); err != nil {
				return err
			}
		}

		// SAN extraction (leaf only).
		if len(e.SANs) > 0 {
			if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
				ID:            uuid.Must(uuid.NewV7()).String(),
				Function:      "TLS certificate SANs",
				Algorithm:     tlsutil.CertAlgoName(e.Cert),
				Subject:       e.Cert.Subject.String(),
				SANs:          e.SANs,
				ChainPosition: e.Position,
				ChainDepth:    chainLen,
				Purpose:       fmt.Sprintf("Certificate has %d SANs", len(e.SANs)),
			}, findings); err != nil {
				return err
			}
		}
	}
	return nil
}

// detectSessionResumption checks whether the server supports TLS session resumption.
func (m *ProtocolModule) detectSessionResumption(ctx context.Context, addr string, findings chan<- *model.Finding) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	dialer := newDialer(ctx)

	cache := tls.NewLRUClientSessionCache(1)

	// First connection — populate session cache
	conn1, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		ClientSessionCache: cache,
	})
	if err != nil {
		return
	}
	_ = conn1.Close()

	// Second connection — attempt resumption
	conn2, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		ClientSessionCache: cache,
	})
	if err != nil {
		return
	}
	state := conn2.ConnectionState()
	_ = conn2.Close()

	mechanism := "not supported"
	if state.DidResume {
		mechanism = "session ticket"
	}

	_ = m.emitFinding(ctx, addr, &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "TLS session resumption",
		Algorithm: "TLS Session Resumption",
		Purpose:   fmt.Sprintf("Session resumption %s for %s", mechanism, addr),
	}, findings)
}

// checkRevocation checks OCSP/CRL revocation status for each certificate in the chain.
func (m *ProtocolModule) checkRevocation(ctx context.Context, addr string, certs []*x509.Certificate, findings chan<- *model.Finding) {
	for i, cert := range certs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Skip certs with no revocation endpoints
		if len(cert.OCSPServer) == 0 && len(cert.CRLDistributionPoints) == 0 {
			continue
		}

		issuer := findIssuer(cert, certs, i)

		status := m.checkOCSP(ctx, cert, issuer)
		if status == "" {
			status = m.checkCRL(ctx, cert)
		}
		if status == "" {
			status = "UNKNOWN"
		}

		position, _ := chainPosition(i, len(certs), cert)
		algoName := certAlgoName(cert)

		_ = m.emitFinding(ctx, addr, &model.CryptoAsset{
			ID:               uuid.Must(uuid.NewV7()).String(),
			Function:         "Certificate revocation status",
			Algorithm:        algoName,
			Subject:          cert.Subject.String(),
			Issuer:           cert.Issuer.String(),
			SerialNumber:     cert.SerialNumber.String(),
			RevocationStatus: status,
			ChainPosition:    position,
			Purpose:          fmt.Sprintf("Revocation status: %s for %s certificate", status, position),
		}, findings)
	}
}

// findIssuer finds the issuer certificate within the chain.
func findIssuer(cert *x509.Certificate, chain []*x509.Certificate, certIndex int) *x509.Certificate {
	for i, candidate := range chain {
		if i == certIndex {
			continue
		}
		if err := cert.CheckSignatureFrom(candidate); err == nil {
			return candidate
		}
	}
	return nil
}

// checkOCSP sends an OCSP request and returns the revocation status string.
// Returns "" if OCSP checking is unavailable or fails.
func (m *ProtocolModule) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate) string {
	if len(cert.OCSPServer) == 0 || issuer == nil {
		return ""
	}

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return ""
	}

	responderURL := cert.OCSPServer[0]
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, responderURL, bytes.NewReader(ocspReq))
	if err != nil {
		return ""
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return "ERROR"
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "ERROR"
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB max
	if err != nil {
		return "ERROR"
	}

	ocspResp, err := ocsp.ParseResponse(respBody, issuer)
	if err != nil {
		return "ERROR"
	}

	switch ocspResp.Status {
	case ocsp.Good:
		return "GOOD"
	case ocsp.Revoked:
		return "REVOKED"
	default:
		return "UNKNOWN"
	}
}

// checkCRL fetches the CRL and checks if the certificate's serial is revoked.
// Returns "" if CRL checking is unavailable or fails.
func (m *ProtocolModule) checkCRL(ctx context.Context, cert *x509.Certificate) string {
	if len(cert.CRLDistributionPoints) == 0 {
		return ""
	}

	crlURL := cert.CRLDistributionPoints[0]
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, http.NoBody)
	if err != nil {
		return ""
	}

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return "ERROR"
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "ERROR"
	}

	crlBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
	if err != nil {
		return "ERROR"
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return "ERROR"
	}

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return "REVOKED"
		}
	}

	return "GOOD"
}

// certAlgoName extracts the algorithm name from a certificate's public key.
// It delegates to the shared certPublicKeyInfo helper.
func certAlgoName(cert *x509.Certificate) string {
	name, _ := certPublicKeyInfo(cert)
	return name
}

// cipherSuiteAlgorithm extracts the primary symmetric algorithm from a TLS cipher suite.
func cipherSuiteAlgorithm(suite uint16) string {
	name := tls.CipherSuiteName(suite)
	upper := strings.ToUpper(name)

	switch {
	case strings.Contains(upper, "AES_256_GCM"):
		return "AES-256-GCM"
	case strings.Contains(upper, "AES_128_GCM"):
		return "AES-128-GCM"
	case strings.Contains(upper, "AES_256_CBC"):
		return "AES-256-CBC"
	case strings.Contains(upper, "AES_128_CBC"):
		return "AES-128-CBC"
	case strings.Contains(upper, "CHACHA20"):
		return "ChaCha20-Poly1305"
	case strings.Contains(upper, "3DES"):
		return "3DES"
	case strings.Contains(upper, "RC4"):
		return "RC4"
	default:
		return "TLS"
	}
}

// chainPosition determines the chain position label and function name for a cert.
func chainPosition(index, chainLen int, cert *x509.Certificate) (position, function string) {
	switch {
	case index == 0:
		position = "leaf"
		function = "TLS leaf certificate"
	case index == chainLen-1 && cert.IsCA && isSelfSigned(cert):
		position = "root"
		function = "TLS root certificate"
	default:
		position = "intermediate"
		function = "TLS intermediate certificate"
	}
	return position, function
}

// isSelfSigned checks if a certificate is self-signed by comparing raw issuer and subject bytes.
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

// cipherSuiteKeyExchange parses a TLS cipher suite name and returns the key exchange
// mechanism and whether it provides forward secrecy.
func cipherSuiteKeyExchange(suiteName string) (keyExchange string, pfs bool) {
	upper := strings.ToUpper(suiteName)
	switch {
	case strings.HasPrefix(upper, "TLS_AES_") || strings.HasPrefix(upper, "TLS_CHACHA20_"):
		return "TLS13", true
	case strings.Contains(upper, "_ECDHE_"):
		return "ECDHE", true
	case strings.Contains(upper, "_DHE_"):
		return "DHE", true
	default:
		return "RSA", false
	}
}


// allTLS12CipherSuiteIDs returns a combined list of all TLS 1.2 cipher suite IDs
// from both secure and insecure suites.
func allTLS12CipherSuiteIDs() []uint16 {
	secure := tls.CipherSuites()
	insecure := tls.InsecureCipherSuites()
	ids := make([]uint16, 0, len(secure)+len(insecure))
	for _, s := range secure {
		ids = append(ids, s.ID)
	}
	for _, s := range insecure {
		ids = append(ids, s.ID)
	}
	return ids
}

// tlsVersionName returns a human-readable TLS version string.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}
