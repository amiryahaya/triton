package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
)

func TestASN1OIDModule_RegisteredInComprehensive(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	e := New(cfg)
	e.RegisterDefaultModules()

	found := false
	for _, m := range e.modules {
		if m.Name() == "asn1_oid" {
			found = true
			break
		}
	}
	if !found {
		t.Error("asn1_oid module not registered under comprehensive profile")
	}
}

func TestASN1OIDModule_NotRegisteredInQuick(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "quick"}
	e := New(cfg)
	e.RegisterDefaultModules()

	for _, m := range e.modules {
		if m.Name() == "asn1_oid" {
			t.Error("asn1_oid module should NOT be registered under quick profile")
		}
	}
}
