package agility

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestAssessAll_EmptyInput(t *testing.T) {
	if got := AssessAll(nil); got != nil {
		t.Errorf("AssessAll(nil) = %v, want nil", got)
	}
	if got := AssessAll(&model.ScanResult{}); got != nil {
		t.Errorf("AssessAll(empty) = %v, want nil", got)
	}
}

func TestAssessAll_WeightsSumToOne(t *testing.T) {
	sum := weightPQCCoverage + weightProtocolAgility + weightConfigFlexibility + weightOperational
	if sum < 0.999 || sum > 1.001 {
		t.Errorf("weights sum = %f, want 1.0", sum)
	}
}

func TestAssessAll_HighAgilityHost(t *testing.T) {
	now := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "host-hi"},
		Findings: []model.Finding{
			// PQC: 2/2 safe
			findingWithAsset("ML-KEM-768", model.PQCStatusSafe, false),
			findingWithAsset("AES-256", model.PQCStatusSafe, false),
			// Protocol: TLS 1.3 + 4 groups + hybrid
			protoFinding("protocol", "TLS 1.3", false),
			protoFinding("protocol", "X25519MLKEM768", true),
			protoFinding("protocol", "X25519", false),
			protoFinding("protocol", "secp256r1", false),
			protoFinding("protocol", "secp384r1", false),
			// Config: all config
			modFinding("configs"),
			modFinding("web_server"),
			// Operational: short rotation + automation
			{Module: "certificates", CryptoAsset: &model.CryptoAsset{
				Algorithm: "RSA-2048",
				NotAfter:  ptrTime(now.AddDate(0, 0, 60)),
			}},
			{Module: "packages", Source: model.FindingSource{Evidence: "cert-manager"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
		},
	}
	scores := AssessAll(result)
	if len(scores) != 1 {
		t.Fatalf("len(scores) = %d, want 1", len(scores))
	}
	s := scores[0]
	if s.Hostname != "host-hi" {
		t.Errorf("Hostname = %q, want host-hi", s.Hostname)
	}
	if s.Overall < 85 {
		t.Errorf("Overall = %d, want >= 85", s.Overall)
	}
	if len(s.Dimensions) != 4 {
		t.Errorf("len(Dimensions) = %d, want 4", len(s.Dimensions))
	}
}

func TestAssessAll_LowAgilityHost(t *testing.T) {
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "host-lo"},
		Findings: []model.Finding{
			findingWithAsset("MD5", model.PQCStatusUnsafe, false),
			findingWithAsset("RSA-1024", model.PQCStatusUnsafe, false),
			protoFinding("protocol", "TLS 1.0", false),
			modFinding("binaries"),
			modFinding("asn1_oid"),
		},
	}
	scores := AssessAll(result)
	if len(scores) != 1 {
		t.Fatalf("len(scores) = %d, want 1", len(scores))
	}
	if scores[0].Overall > 25 {
		t.Errorf("Overall = %d, want <= 25", scores[0].Overall)
	}
}

func TestAssessAll_MultiHostGrouping(t *testing.T) {
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "fallback"},
		Findings: []model.Finding{
			{
				Module:      "protocol",
				Source:      model.FindingSource{Endpoint: "a.example.com:443"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "TLS 1.3"},
			},
			{
				Module:      "protocol",
				Source:      model.FindingSource{Endpoint: "b.example.com:443"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "TLS 1.2"},
			},
			// falls back to metadata hostname
			findingWithAsset("RSA-2048", model.PQCStatusTransitional, false),
		},
	}
	scores := AssessAll(result)
	if len(scores) != 3 {
		t.Fatalf("len(scores) = %d, want 3 (a, b, fallback)", len(scores))
	}
	// Must be sorted by hostname deterministically
	want := []string{"a.example.com:443", "b.example.com:443", "fallback"}
	for i, s := range scores {
		if s.Hostname != want[i] {
			t.Errorf("scores[%d].Hostname = %q, want %q", i, s.Hostname, want[i])
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
