package portscan_test

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/manageserver/portscan"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

func TestPortListSizes(t *testing.T) {
	quick := portscan.Ports(scanjobs.ProfileQuick)
	standard := portscan.Ports(scanjobs.ProfileStandard)
	comprehensive := portscan.Ports(scanjobs.ProfileComprehensive)

	if len(quick) == 0 {
		t.Error("quick port list is empty")
	}
	if len(standard) <= len(quick) {
		t.Errorf("standard (%d) should be larger than quick (%d)", len(standard), len(quick))
	}
	if len(comprehensive) <= len(standard) {
		t.Errorf("comprehensive (%d) should be larger than standard (%d)", len(comprehensive), len(standard))
	}
	if len(quick) > 100 {
		t.Errorf("quick port list too large: %d", len(quick))
	}
	if len(standard) > 1000 {
		t.Errorf("standard port list too large: %d", len(standard))
	}
	if len(comprehensive) > 10000 {
		t.Errorf("comprehensive port list too large: %d", len(comprehensive))
	}
}
