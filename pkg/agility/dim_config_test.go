package agility

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

func modFinding(module string) model.Finding {
	return model.Finding{
		Module:      module,
		Timestamp:   time.Unix(0, 0),
		CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"},
	}
}

func TestScoreConfigFlexibility_AllConfig(t *testing.T) {
	fs := []model.Finding{
		modFinding("configs"),
		modFinding("web_server"),
		modFinding("vpn_config"),
	}
	d := scoreConfigFlexibility(fs)
	if d.Score != 100 {
		t.Errorf("Score = %d, want 100", d.Score)
	}
}

func TestScoreConfigFlexibility_AllHardcoded(t *testing.T) {
	fs := []model.Finding{
		modFinding("binaries"),
		modFinding("asn1_oid"),
		modFinding("java_bytecode"),
	}
	d := scoreConfigFlexibility(fs)
	if d.Score != 0 {
		t.Errorf("Score = %d, want 0", d.Score)
	}
}

func TestScoreConfigFlexibility_Mixed(t *testing.T) {
	fs := []model.Finding{
		modFinding("configs"),
		modFinding("configs"),
		modFinding("binaries"),
		modFinding("asn1_oid"),
	}
	d := scoreConfigFlexibility(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (2/4)", d.Score)
	}
}

func TestScoreConfigFlexibility_Neutral(t *testing.T) {
	fs := []model.Finding{
		modFinding("certificates"),
		modFinding("packages"),
	}
	d := scoreConfigFlexibility(fs)
	if d.Score != 50 {
		t.Errorf("Score = %d, want 50 (neutral)", d.Score)
	}
}
