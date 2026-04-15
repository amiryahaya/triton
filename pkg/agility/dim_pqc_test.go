package agility

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

func findingWithAsset(algo, status string, hybrid bool) model.Finding {
	return model.Finding{
		Module:    "test",
		Timestamp: time.Unix(0, 0),
		CryptoAsset: &model.CryptoAsset{
			Algorithm: algo,
			PQCStatus: status,
			IsHybrid:  hybrid,
		},
	}
}

func TestScorePQCCoverage_AllSafe(t *testing.T) {
	fs := []model.Finding{
		findingWithAsset("ML-KEM-768", model.PQCStatusSafe, false),
		findingWithAsset("AES-256", model.PQCStatusSafe, false),
	}
	d := scorePQCCoverage(fs)
	if d.Score != 100 {
		t.Errorf("Score = %d, want 100", d.Score)
	}
	if d.Name != DimPQCCoverage {
		t.Errorf("Name = %q, want %q", d.Name, DimPQCCoverage)
	}
}

func TestScorePQCCoverage_AllUnsafe(t *testing.T) {
	fs := []model.Finding{
		findingWithAsset("RSA-2048", model.PQCStatusTransitional, false),
		findingWithAsset("MD5", model.PQCStatusUnsafe, false),
	}
	d := scorePQCCoverage(fs)
	if d.Score != 0 {
		t.Errorf("Score = %d, want 0", d.Score)
	}
}

func TestScorePQCCoverage_Mixed(t *testing.T) {
	fs := []model.Finding{
		findingWithAsset("ML-KEM-768", model.PQCStatusSafe, false),
		findingWithAsset("RSA-2048", model.PQCStatusTransitional, false),
		findingWithAsset("MD5", model.PQCStatusUnsafe, false),
		findingWithAsset("AES-256", model.PQCStatusSafe, false),
	}
	d := scorePQCCoverage(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (2/4)", d.Score)
	}
}

func TestScorePQCCoverage_HybridCountsAsSafe(t *testing.T) {
	fs := []model.Finding{
		// Hybrid with classical label should still credit coverage.
		findingWithAsset("X25519MLKEM768", model.PQCStatusTransitional, true),
		findingWithAsset("RSA-2048", model.PQCStatusTransitional, false),
	}
	d := scorePQCCoverage(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50", d.Score)
	}
}

func TestScorePQCCoverage_NoAssets(t *testing.T) {
	fs := []model.Finding{{Module: "noop"}}
	d := scorePQCCoverage(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (neutral)", d.Score)
	}
}
