package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// TestHybridGroup_SurvivesClassification verifies that a hybrid TLS group
// asset keeps SAFE status + IsHybrid + ComponentAlgorithms after
// crypto.ClassifyCryptoAsset runs (i.e., the hybrid name is registered in
// the algorithm registry, not silently downgraded to UNKNOWN).
func TestHybridGroup_SurvivesClassification(t *testing.T) {
	asset := &model.CryptoAsset{
		Algorithm:           "X25519MLKEM768",
		KeySize:             256,
		IsHybrid:            true,
		ComponentAlgorithms: []string{"X25519", "ML-KEM-768"},
		PQCStatus:           string(crypto.SAFE),
	}
	crypto.ClassifyCryptoAsset(asset)
	if asset.PQCStatus != string(crypto.SAFE) {
		t.Errorf("PQCStatus: got %q, want SAFE (hybrid downgraded by classifier)", asset.PQCStatus)
	}
	if !asset.IsHybrid {
		t.Error("IsHybrid lost after classification")
	}
	if len(asset.ComponentAlgorithms) != 2 {
		t.Errorf("ComponentAlgorithms lost: %v", asset.ComponentAlgorithms)
	}
}
