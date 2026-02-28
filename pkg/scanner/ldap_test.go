package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// Compile-time interface check
var _ Module = (*LDAPModule)(nil)

func TestLDAPModule_Name(t *testing.T) {
	m := NewLDAPModule(&config.Config{})
	assert.Equal(t, "ldap", m.Name())
}

func TestLDAPModule_Category(t *testing.T) {
	m := NewLDAPModule(&config.Config{})
	assert.Equal(t, model.CategoryActiveNetwork, m.Category())
}

func TestLDAPModule_ScanTargetType(t *testing.T) {
	m := NewLDAPModule(&config.Config{})
	assert.Equal(t, model.TargetLDAP, m.ScanTargetType())
}

func TestLDAPModule_ParseTarget(t *testing.T) {
	lt, err := parseLDAPTarget("ldap://ldap.example.com:389/dc=example,dc=com")
	require.NoError(t, err)
	assert.Equal(t, "ldap", lt.scheme)
	assert.Equal(t, "ldap.example.com:389", lt.host)
	assert.Equal(t, "dc=example,dc=com", lt.baseDN)
	assert.False(t, lt.startTLS)
}

func TestLDAPModule_ParseTarget_LDAPS(t *testing.T) {
	lt, err := parseLDAPTarget("ldaps://ldap.example.com:636/dc=example,dc=com")
	require.NoError(t, err)
	assert.Equal(t, "ldaps", lt.scheme)
	assert.Equal(t, "ldap.example.com:636", lt.host)
	assert.Equal(t, "dc=example,dc=com", lt.baseDN)
}

func TestLDAPModule_ParseTarget_DefaultPort(t *testing.T) {
	lt, err := parseLDAPTarget("ldap://ldap.example.com/dc=example,dc=com")
	require.NoError(t, err)
	assert.Equal(t, "ldap.example.com:389", lt.host)

	lt, err = parseLDAPTarget("ldaps://ldap.example.com/dc=example,dc=com")
	require.NoError(t, err)
	assert.Equal(t, "ldap.example.com:636", lt.host)
}

func TestLDAPModule_ParseTarget_StartTLS(t *testing.T) {
	lt, err := parseLDAPTarget("ldap://ldap.example.com:389/dc=example,dc=com?starttls")
	require.NoError(t, err)
	assert.True(t, lt.startTLS)
}

func TestLDAPModule_ParseTarget_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"empty", ""},
		{"dash prefix", "-ldap://host/dc=example"},
		{"control chars", "ldap://host\n/dc=example"},
		{"bad scheme", "ftp://host/dc=example"},
		{"missing host", "ldap:///dc=example"},
		{"missing baseDN", "ldap://host"},
		{"dash host", "ldap://-host/dc=example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseLDAPTarget(tt.target)
			assert.Error(t, err)
		})
	}
}

// mockLDAPConn implements ldapConn for testing.
type mockLDAPConn struct {
	searchResult *ldap.SearchResult
	searchErr    error
	bindErr      error
	startTLSErr  error
	closed       bool
}

func (m *mockLDAPConn) StartTLS(config *tls.Config) error    { return m.startTLSErr }
func (m *mockLDAPConn) Bind(username, password string) error { return m.bindErr }
func (m *mockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return m.searchResult, m.searchErr
}
func (m *mockLDAPConn) Close() error {
	m.closed = true
	return nil
}

func generateTestCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ldap-cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER
}

func TestLDAPModule_ScanWithMockCerts(t *testing.T) {
	certDER := generateTestCertDER(t)

	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "cn=user1,dc=example,dc=com",
					Attributes: []*ldap.EntryAttribute{
						{
							Name:       "userCertificate;binary",
							ByteValues: [][]byte{certDER},
						},
					},
				},
			},
		},
	}

	m := &LDAPModule{
		config: &config.Config{},
		dialFn: func(addr string) (ldapConn, error) { return mock, nil },
	}

	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetLDAP, Value: "ldap://localhost:389/dc=example,dc=com"}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected)
	f := collected[0]
	assert.Equal(t, 3, f.Category)
	assert.Equal(t, "ldap", f.Source.Type)
	assert.Equal(t, "ldap", f.Module)
	assert.Equal(t, 0.95, f.Confidence)
	assert.Equal(t, "LDAP user certificate", f.CryptoAsset.Function)
	assert.Contains(t, f.CryptoAsset.Algorithm, "ECDSA")
	assert.NotEmpty(t, f.CryptoAsset.Subject)
	assert.NotEmpty(t, f.CryptoAsset.PQCStatus)
}

func TestLDAPModule_ScanCACerts(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// First call (userCertificate) returns empty, second call (cACertificate) returns CA cert
	m := &LDAPModule{
		config: &config.Config{},
		dialFn: func(addr string) (ldapConn, error) {
			// Return a mock that changes behavior per search
			return &dynamicMockLDAPConn{
				responses: map[string]*ldap.SearchResult{
					"(userCertificate;binary=*)": {Entries: []*ldap.Entry{}},
					"(cACertificate;binary=*)": {
						Entries: []*ldap.Entry{
							{
								DN: "cn=TestCA,dc=example,dc=com",
								Attributes: []*ldap.EntryAttribute{
									{
										Name:       "cACertificate;binary",
										ByteValues: [][]byte{caDER},
									},
								},
							},
						},
					},
				},
			}, nil
		},
	}
	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetLDAP, Value: "ldap://localhost:389/dc=example,dc=com"}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected)
	assert.Equal(t, "LDAP CA certificate", collected[0].CryptoAsset.Function)
	assert.True(t, collected[0].CryptoAsset.IsCA)
}

// dynamicMockLDAPConn returns different results based on search filter.
type dynamicMockLDAPConn struct {
	responses map[string]*ldap.SearchResult
}

func (m *dynamicMockLDAPConn) StartTLS(config *tls.Config) error    { return nil }
func (m *dynamicMockLDAPConn) Bind(username, password string) error { return nil }
func (m *dynamicMockLDAPConn) Close() error                         { return nil }
func (m *dynamicMockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if result, ok := m.responses[req.Filter]; ok {
		return result, nil
	}
	return &ldap.SearchResult{}, nil
}

func TestLDAPModule_NoCertsFound(t *testing.T) {
	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{
			Entries: []*ldap.Entry{},
		},
	}

	m := &LDAPModule{
		config: &config.Config{},
		dialFn: func(addr string) (ldapConn, error) { return mock, nil },
	}

	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetLDAP, Value: "ldap://localhost:389/dc=example,dc=com"}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}
	assert.Empty(t, collected, "no certs should produce no findings")
}

func TestLDAPModule_ConnectionError(t *testing.T) {
	m := &LDAPModule{
		config: &config.Config{},
		dialFn: func(addr string) (ldapConn, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}

	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetLDAP, Value: "ldap://localhost:389/dc=example,dc=com"}

	err := m.Scan(context.Background(), target, findings)
	close(findings)

	assert.NoError(t, err, "connection error should be non-fatal")
}

func TestLDAPModule_ContextCancellation(t *testing.T) {
	m := &LDAPModule{
		config: &config.Config{},
		dialFn: func(addr string) (ldapConn, error) {
			return &mockLDAPConn{}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	findings := make(chan *model.Finding, 10)
	target := model.ScanTarget{Type: model.TargetLDAP, Value: "ldap://localhost:389/dc=example,dc=com"}

	err := m.Scan(ctx, target, findings)
	close(findings)

	assert.Equal(t, context.Canceled, err)
}

func TestLDAPModule_PQCClassification(t *testing.T) {
	// Create an RSA-2048 cert (should be TRANSITIONAL)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-2048-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	mock := &mockLDAPConn{
		searchResult: &ldap.SearchResult{
			Entries: []*ldap.Entry{
				{
					DN: "cn=user1,dc=example,dc=com",
					Attributes: []*ldap.EntryAttribute{
						{
							Name:       "userCertificate;binary",
							ByteValues: [][]byte{certDER},
						},
					},
				},
			},
		},
	}

	m := &LDAPModule{
		config: &config.Config{},
		dialFn: func(addr string) (ldapConn, error) { return mock, nil },
	}

	findings := make(chan *model.Finding, 20)
	target := model.ScanTarget{Type: model.TargetLDAP, Value: "ldap://localhost:389/dc=example,dc=com"}

	err = m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var collected []*model.Finding
	for f := range findings {
		collected = append(collected, f)
	}

	require.NotEmpty(t, collected)
	assert.Equal(t, "RSA-2048", collected[0].CryptoAsset.Algorithm)
	assert.Equal(t, "TRANSITIONAL", collected[0].CryptoAsset.PQCStatus)
}

func TestLDAPModule_InputValidation(t *testing.T) {
	m := NewLDAPModule(&config.Config{})

	tests := []struct {
		name   string
		target string
	}{
		{"dash prefix", "-ldap://host/dc=a"},
		{"null byte", "ldap://host\x00/dc=a"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := make(chan *model.Finding, 10)
			target := model.ScanTarget{Type: model.TargetLDAP, Value: tt.target}

			err := m.Scan(context.Background(), target, findings)
			close(findings)

			assert.NoError(t, err, "invalid input should be non-fatal")

			var collected []*model.Finding
			for f := range findings {
				collected = append(collected, f)
			}
			assert.Empty(t, collected)
		})
	}
}
