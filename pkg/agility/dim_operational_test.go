package agility

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

var refNow = time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

func certFinding(daysToExpiry int) model.Finding {
	exp := refNow.AddDate(0, 0, daysToExpiry)
	return model.Finding{
		Module:    "certificates",
		Timestamp: refNow,
		CryptoAsset: &model.CryptoAsset{
			Algorithm: "RSA-2048",
			NotAfter:  &exp,
		},
	}
}

func TestScoreOperational_ShortRotationsOnly(t *testing.T) {
	fs := []model.Finding{certFinding(30), certFinding(60), certFinding(80)}
	d := scoreOperationalReadiness(fs, refNow)
	// Median 60 → 100 (cert), HSM 0, automation 0 → avg = 33
	if d.Score != 33 {
		t.Errorf("Score = %d, want 33", d.Score)
	}
}

func TestScoreOperational_HSMPresent(t *testing.T) {
	fs := []model.Finding{
		{Module: "hsm", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-3072"}},
	}
	d := scoreOperationalReadiness(fs, refNow)
	// No certs → cert skipped. HSM 100, automation 0 → avg = 50
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50", d.Score)
	}
}

func TestScoreOperational_AutomationDetected(t *testing.T) {
	f := model.Finding{
		Module:      "packages",
		Source:      model.FindingSource{Path: "/usr/bin/certbot"},
		CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"},
	}
	d := scoreOperationalReadiness([]model.Finding{f}, refNow)
	// No certs → cert skipped. HSM 0, automation 100 → avg = 50
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50", d.Score)
	}
}

func TestScoreOperational_LongRotations(t *testing.T) {
	fs := []model.Finding{certFinding(800), certFinding(900)}
	d := scoreOperationalReadiness(fs, refNow)
	// Median 850 → 0. HSM 0, automation 0 → 0
	if d.Score != 0 {
		t.Errorf("Score = %d, want 0", d.Score)
	}
}

func TestScoreOperational_EvenLengthMedianAverages(t *testing.T) {
	// 30d + 400d → median should be 215, scoring 50 (≤365 band), not 400 → 25.
	fs := []model.Finding{certFinding(30), certFinding(400)}
	d := scoreOperationalReadiness(fs, refNow)
	// cert 50, HSM 0, automation 0 → avg = 16
	if d.Score != 16 {
		t.Errorf("Score = %d, want 16 (cert=50)", d.Score)
	}
}

func TestScoreOperational_AllThreeFire(t *testing.T) {
	fs := []model.Finding{
		certFinding(60),
		{Module: "hsm", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-3072"}},
		{Module: "packages", Source: model.FindingSource{Evidence: "cert-manager installed"},
			CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
	}
	d := scoreOperationalReadiness(fs, refNow)
	// 100+100+100 / 3 = 100
	if d.Score != 100 {
		t.Errorf("Score = %d, want 100", d.Score)
	}
}
