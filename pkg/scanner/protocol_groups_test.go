package scanner

import (
	"crypto/tls"
	"testing"

	"github.com/amiryahaya/triton/pkg/crypto"
)

func TestTLSGroupToAsset_Hybrid(t *testing.T) {
	// CurveID 0x11EC = X25519MLKEM768 (hybrid)
	asset := tlsGroupToAsset(tls.CurveID(0x11EC))
	if asset == nil {
		t.Fatal("expected non-nil asset for known hybrid group")
	}
	if asset.Algorithm != "X25519MLKEM768" {
		t.Errorf("algorithm: got %q, want X25519MLKEM768", asset.Algorithm)
	}
	if !asset.IsHybrid {
		t.Error("expected IsHybrid=true")
	}
	if len(asset.ComponentAlgorithms) != 2 {
		t.Errorf("ComponentAlgorithms: got %v, want 2 components", asset.ComponentAlgorithms)
	}
	if asset.PQCStatus != string(crypto.SAFE) {
		t.Errorf("PQCStatus: got %q, want SAFE", asset.PQCStatus)
	}
}

func TestTLSGroupToAsset_Classical(t *testing.T) {
	asset := tlsGroupToAsset(tls.CurveID(0x001D)) // x25519
	if asset == nil {
		t.Fatal("expected non-nil asset for x25519")
	}
	if asset.IsHybrid {
		t.Error("classical group should not be marked hybrid")
	}
	if asset.Algorithm != "x25519" {
		t.Errorf("algorithm: got %q, want x25519", asset.Algorithm)
	}
}

func TestTLSGroupToAsset_Unknown(t *testing.T) {
	if a := tlsGroupToAsset(tls.CurveID(0xFFFF)); a != nil {
		t.Errorf("expected nil for unknown group, got %+v", a)
	}
}
