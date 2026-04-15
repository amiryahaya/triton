package agility

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

func protoFinding(module, algo string, hybrid bool) model.Finding {
	return model.Finding{
		Module:    module,
		Timestamp: time.Unix(0, 0),
		CryptoAsset: &model.CryptoAsset{
			Algorithm: algo,
			IsHybrid:  hybrid,
		},
	}
}

func TestScoreProtocolAgility_TLS13AndHybrid(t *testing.T) {
	fs := []model.Finding{
		protoFinding("protocol", "TLS 1.3", false),
		protoFinding("protocol", "X25519MLKEM768", true),
		protoFinding("protocol", "secp256r1", false),
		protoFinding("protocol", "X25519", false),
		protoFinding("protocol", "secp384r1", false),
	}
	d := scoreProtocolAgility(fs)
	// TLS ceiling 100, diversity 100 (4 groups), hybrid 100 → 100
	if d.Score != 100 {
		t.Errorf("Score = %d, want 100", d.Score)
	}
}

func TestScoreProtocolAgility_LegacyTLSOnly(t *testing.T) {
	fs := []model.Finding{
		protoFinding("protocol", "TLS 1.0", false),
		protoFinding("protocol", "secp256r1", false),
	}
	d := scoreProtocolAgility(fs)
	// ceiling 0, diversity 25, hybrid signal omitted (no hybrid observed,
	// no double-penalty for legacy TLS — ceiling already encodes it).
	// (0+25)/2 = 12.
	if d.Score != 12 {
		t.Errorf("Score = %d, want 12", d.Score)
	}
}

func TestScoreProtocolAgility_HybridSignalOmittedWhenNotPresent(t *testing.T) {
	// Modern TLS without hybrid groups: hybrid signal must NOT fire (no double-penalty).
	fs := []model.Finding{
		protoFinding("protocol", "TLS 1.3", false),
		protoFinding("protocol", "X25519", false),
	}
	d := scoreProtocolAgility(fs)
	for _, s := range d.Signals {
		if s.Name == "hybrid_group_present" {
			t.Errorf("hybrid_group_present signal should be omitted when no hybrid observed; got %+v", s)
		}
	}
	// ceiling 100, diversity 25 (1 group), no hybrid → (100+25)/2 = 62
	if d.Score != 62 {
		t.Errorf("Score = %d, want 62", d.Score)
	}
}

func TestScoreProtocolAgility_NoProtocolFindings(t *testing.T) {
	fs := []model.Finding{
		{Module: "certificates", CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"}},
	}
	d := scoreProtocolAgility(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (neutral)", d.Score)
	}
}

func TestIsNamedGroup_RejectsCipherSuiteStrings(t *testing.T) {
	cases := map[string]bool{
		"X25519":                                true,
		"secp256r1":                             true,
		"X25519MLKEM768":                        true,
		"TLS 1.3":                               false,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": false,
		"ECDHE-RSA-AES128-GCM-SHA256":           false,
		"ECDHE-ECDSA-CHACHA20-POLY1305":         false,
		"":                                      false,
	}
	for in, want := range cases {
		if got := isNamedGroup(in); got != want {
			t.Errorf("isNamedGroup(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestScoreProtocolAgility_WebServerContributes(t *testing.T) {
	fs := []model.Finding{
		protoFinding("web_server", "TLS 1.2", false),
		protoFinding("web_server", "X25519", false),
		protoFinding("web_server", "secp256r1", false),
	}
	d := scoreProtocolAgility(fs)
	// ceiling 60, diversity 50 (2 groups), no hybrid → avg = 55
	if d.Score != 55 {
		t.Errorf("Score = %d, want 55", d.Score)
	}
}
