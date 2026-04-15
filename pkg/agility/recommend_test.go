package agility

import (
	"strings"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestGenerateRecommendations_LowPQCWithJava(t *testing.T) {
	s := Score{Dimensions: []Dimension{
		{Name: DimPQCCoverage, Score: 10},
		{Name: DimProtocolAgility, Score: 80},
		{Name: DimConfigFlexibility, Score: 80},
		{Name: DimOperationalReady, Score: 80},
	}}
	findings := []model.Finding{
		{Module: "java_bytecode", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
	}
	recs := generateRecommendations(s, findings)
	if len(recs) == 0 {
		t.Fatal("want at least 1 recommendation")
	}
	found := false
	for _, r := range recs {
		if r.Dimension == DimPQCCoverage && strings.Contains(r.Action, "BouncyCastle") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected BouncyCastle recommendation, got %v", recs)
	}
}

func TestGenerateRecommendations_SkipWhenAboveThreshold(t *testing.T) {
	s := Score{Dimensions: []Dimension{
		{Name: DimPQCCoverage, Score: 90},
		{Name: DimProtocolAgility, Score: 90},
		{Name: DimConfigFlexibility, Score: 90},
		{Name: DimOperationalReady, Score: 90},
	}}
	recs := generateRecommendations(s, nil)
	if len(recs) != 0 {
		t.Errorf("want 0 recommendations, got %d", len(recs))
	}
}

func TestGenerateRecommendations_CapAtThreePerDim(t *testing.T) {
	s := Score{Dimensions: []Dimension{
		{Name: DimOperationalReady, Score: 10},
	}}
	now := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)
	longCert := now.AddDate(2, 0, 0)
	findings := []model.Finding{
		{Module: "certificates", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048", NotAfter: &longCert}},
		// no HSM, no automation → all three ops rules should fire, but capped at 3
	}
	recs := generateRecommendations(s, findings)
	count := 0
	for _, r := range recs {
		if r.Dimension == DimOperationalReady {
			count++
		}
	}
	if count > 3 {
		t.Errorf("recommendations for DimOperationalReady = %d, want <= 3", count)
	}
	if count < 1 {
		t.Errorf("recommendations for DimOperationalReady = 0, want >= 1")
	}
}

func TestGenerateRecommendations_OrderedByImpact(t *testing.T) {
	s := Score{Dimensions: []Dimension{{Name: DimPQCCoverage, Score: 10}}}
	findings := []model.Finding{
		{Module: "java_bytecode", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
		{Module: "web_server", CryptoAsset: &model.CryptoAsset{Algorithm: "TLS 1.3"}},
	}
	recs := generateRecommendations(s, findings)
	for i := 1; i < len(recs); i++ {
		if recs[i-1].Dimension == recs[i].Dimension && recs[i-1].Impact < recs[i].Impact {
			t.Errorf("recs not sorted by Impact desc within dimension: %+v", recs)
		}
	}
}
