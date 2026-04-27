package scanrunner_test

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanrunner"
)

func TestToScanResult_TLSCertFinding(t *testing.T) {
	nb := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	findings := []scanrunner.Finding{
		{
			Port:    443,
			Service: "https",
			Banner:  "nginx/1.25",
			TLSCert: &scanrunner.TLSCertInfo{
				Subject:      "example.com",
				Issuer:       "Let's Encrypt",
				Algorithm:    "RSA",
				KeyBits:      2048,
				NotBefore:    nb,
				NotAfter:     na,
				SANs:         []string{"example.com", "www.example.com"},
				SerialNumber: "12345",
				IsSelfSigned: false,
			},
		},
	}

	result := scanrunner.ToScanResult("example.com", "192.168.1.1", "standard", findings)

	if result.ID == "" {
		t.Error("result ID should not be empty")
	}
	if result.Metadata.Hostname != "example.com" {
		t.Errorf("hostname: got %q, want %q", result.Metadata.Hostname, "example.com")
	}
	if result.Metadata.ScanProfile != "standard" {
		t.Errorf("profile: got %q, want %q", result.Metadata.ScanProfile, "standard")
	}
	// Expect 2 findings: TLS cert + service
	if len(result.Findings) != 2 {
		t.Fatalf("findings count: got %d, want 2", len(result.Findings))
	}
	tlsFinding := result.Findings[0]
	if tlsFinding.Source.Endpoint != "tcp://192.168.1.1:443" {
		t.Errorf("endpoint: got %q, want %q", tlsFinding.Source.Endpoint, "tcp://192.168.1.1:443")
	}
	if tlsFinding.Source.DetectionMethod != "tls-handshake" {
		t.Errorf("detection method: got %q", tlsFinding.Source.DetectionMethod)
	}
	asset := tlsFinding.CryptoAsset
	if asset == nil {
		t.Fatal("CryptoAsset should not be nil for TLS finding")
	}
	if asset.SerialNumber != "12345" {
		t.Errorf("serial number: got %q, want %q", asset.SerialNumber, "12345")
	}
	if asset.IsSelfSigned {
		t.Error("IsSelfSigned: got true, want false")
	}
}

func TestToScanResult_SelfSignedCert(t *testing.T) {
	nb := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	findings := []scanrunner.Finding{
		{
			Port: 8443,
			TLSCert: &scanrunner.TLSCertInfo{
				Subject:      "CN=myhost",
				Issuer:       "CN=myhost",
				Algorithm:    "ECDSA",
				KeyBits:      256,
				NotBefore:    nb,
				NotAfter:     na,
				SerialNumber: "deadbeef",
				IsSelfSigned: true,
			},
		},
	}
	result := scanrunner.ToScanResult("myhost", "10.0.0.2", "standard", findings)
	if len(result.Findings) != 1 {
		t.Fatalf("findings count: got %d, want 1", len(result.Findings))
	}
	asset := result.Findings[0].CryptoAsset
	if asset == nil {
		t.Fatal("CryptoAsset should not be nil")
	}
	if asset.SerialNumber != "deadbeef" {
		t.Errorf("serial number: got %q, want %q", asset.SerialNumber, "deadbeef")
	}
	if !asset.IsSelfSigned {
		t.Error("IsSelfSigned: got false, want true")
	}
}

func TestToScanResult_SSHFinding(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 22, Service: "ssh", Banner: "OpenSSH_9.3"},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "quick", findings)
	if len(result.Findings) != 1 {
		t.Fatalf("findings count: got %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.CryptoAsset == nil {
		t.Fatal("CryptoAsset should not be nil for SSH finding")
	}
	if f.CryptoAsset.Algorithm != "SSH" {
		t.Errorf("algorithm: got %q, want SSH", f.CryptoAsset.Algorithm)
	}
	if f.CryptoAsset.Subject != "OpenSSH_9.3" {
		t.Errorf("subject: got %q, want OpenSSH_9.3", f.CryptoAsset.Subject)
	}
}

func TestToScanResult_NoFindings(t *testing.T) {
	result := scanrunner.ToScanResult("host", "10.0.0.1", "quick", nil)
	if result == nil {
		t.Fatal("result should not be nil even with no findings")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestToScanResult_HTTPWithoutBannerSkipped(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 80, Service: "http", Banner: ""}, // no banner → skip service finding
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for http with empty banner, got %d", len(result.Findings))
	}
}

func TestClassifyKeySize_RSA(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 443, TLSCert: &scanrunner.TLSCertInfo{Algorithm: "RSA", KeyBits: 1024}},
	}
	result := scanrunner.ToScanResult("h", "1.2.3.4", "quick", findings)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].CryptoAsset.PQCStatus != model.PQCStatusDeprecated {
		t.Errorf("RSA-1024 should be DEPRECATED, got %s", result.Findings[0].CryptoAsset.PQCStatus)
	}
}

func TestToScanResult_FindingCategory(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 443, Service: "https", Banner: "nginx", TLSCert: &scanrunner.TLSCertInfo{Algorithm: "RSA", KeyBits: 2048}},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) < 1 {
		t.Fatal("no findings generated")
	}
	if result.Findings[0].Category != int(model.CategoryActiveNetwork) {
		t.Errorf("category: got %d, want %d", result.Findings[0].Category, int(model.CategoryActiveNetwork))
	}
}

func TestToScanResult_FindingConfidence(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 443, TLSCert: &scanrunner.TLSCertInfo{Algorithm: "RSA", KeyBits: 2048}},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) < 1 {
		t.Fatal("no findings generated")
	}
	// TLS cert finding should have higher confidence than service banner
	if result.Findings[0].Confidence != 0.95 {
		t.Errorf("TLS cert confidence: got %f, want 0.95", result.Findings[0].Confidence)
	}
}

func TestToScanResult_SANs(t *testing.T) {
	nb := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	findings := []scanrunner.Finding{
		{
			Port:    443,
			Service: "https",
			Banner:  "nginx",
			TLSCert: &scanrunner.TLSCertInfo{
				Algorithm: "ECDSA",
				KeyBits:   256,
				NotBefore: nb,
				NotAfter:  na,
				SANs:      []string{"example.com", "www.example.com", "api.example.com"},
			},
		},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) < 1 {
		t.Fatal("no findings generated")
	}
	if len(result.Findings[0].CryptoAsset.SANs) != 3 {
		t.Errorf("SANs count: got %d, want 3", len(result.Findings[0].CryptoAsset.SANs))
	}
}

func TestToScanResult_State(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 443, TLSCert: &scanrunner.TLSCertInfo{Algorithm: "RSA", KeyBits: 2048}},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) < 1 {
		t.Fatal("no findings generated")
	}
	if result.Findings[0].CryptoAsset.State != "IN_TRANSIT" {
		t.Errorf("state: got %q, want IN_TRANSIT", result.Findings[0].CryptoAsset.State)
	}
}

func TestToScanResult_ECDSA(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 443, TLSCert: &scanrunner.TLSCertInfo{Algorithm: "ECDSA", KeyBits: 256}},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) < 1 {
		t.Fatal("no findings generated")
	}
	if result.Findings[0].CryptoAsset.PQCStatus != model.PQCStatusTransitional {
		t.Errorf("ECDSA-256 should be TRANSITIONAL, got %s", result.Findings[0].CryptoAsset.PQCStatus)
	}
}

func TestToScanResult_ECDSAWeakKeySize(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 443, TLSCert: &scanrunner.TLSCertInfo{Algorithm: "EC", KeyBits: 160}},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) < 1 {
		t.Fatal("no findings generated")
	}
	if result.Findings[0].CryptoAsset.PQCStatus != model.PQCStatusDeprecated {
		t.Errorf("EC-160 should be DEPRECATED, got %s", result.Findings[0].CryptoAsset.PQCStatus)
	}
}

func TestToScanResult_ServiceBannerConfidence(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 22, Service: "ssh", Banner: "OpenSSH_9.3"},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) < 1 {
		t.Fatal("no findings generated")
	}
	if result.Findings[0].Confidence != 0.85 {
		t.Errorf("service banner confidence: got %f, want 0.85", result.Findings[0].Confidence)
	}
}

func TestToScanResult_Module(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 443, TLSCert: &scanrunner.TLSCertInfo{Algorithm: "RSA", KeyBits: 2048}},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) < 1 {
		t.Fatal("no findings generated")
	}
	if result.Findings[0].Module != "port_survey" {
		t.Errorf("module: got %q, want port_survey", result.Findings[0].Module)
	}
}

func TestToScanResult_UnknownServiceWithBanner(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 25, Service: "smtp", Banner: "Postfix smtpd"},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for smtp+banner, got %d", len(result.Findings))
	}
	if result.Findings[0].CryptoAsset.Algorithm != "SMTP" {
		t.Errorf("algorithm: got %q, want SMTP", result.Findings[0].CryptoAsset.Algorithm)
	}
	if result.Findings[0].CryptoAsset.Function != "network" {
		t.Errorf("function: got %q, want network", result.Findings[0].CryptoAsset.Function)
	}
}

func TestToScanResult_UnknownServiceNoBanner(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 21, Service: "ftp", Banner: ""},
	}
	result := scanrunner.ToScanResult("host", "10.0.0.1", "standard", findings)
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for ftp with no banner, got %d", len(result.Findings))
	}
}

func TestClassifyKeySize_UnknownAlgo(t *testing.T) {
	findings := []scanrunner.Finding{
		{Port: 443, TLSCert: &scanrunner.TLSCertInfo{Algorithm: "Ed25519", KeyBits: 0}},
	}
	result := scanrunner.ToScanResult("h", "1.2.3.4", "quick", findings)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].CryptoAsset.PQCStatus != "TRANSITIONAL" {
		t.Errorf("unknown algo should be TRANSITIONAL, got %s", result.Findings[0].CryptoAsset.PQCStatus)
	}
}
