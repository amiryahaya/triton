package license

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

func TestGuard_HasFeature_V2TakesPrecedence(t *testing.T) {
	g := &Guard{
		license: &License{
			Features: licensestore.Features{Report: true, DiffTrend: true},
		},
		tier: TierFree, // tier alone would say no diff_trend
	}
	if !g.HasFeature("report") || !g.HasFeature("diff_trend") {
		t.Errorf("v2 features should win: %+v", g)
	}
	if g.HasFeature("manage") {
		t.Errorf("manage should be false")
	}
}

func TestGuard_HasFeature_CompatFallback_Pro(t *testing.T) {
	// Legacy pro token — no v2 features, tier=pro.
	g := &Guard{
		license: &License{Tier: TierPro}, // empty Features
		tier:    TierPro,
	}
	if !g.HasFeature("diff_trend") {
		t.Errorf("pro compat should grant diff_trend")
	}
	if g.HasFeature("manage") {
		t.Errorf("pro compat should not grant manage")
	}
}

func TestGuard_HasFeature_CompatFallback_Enterprise(t *testing.T) {
	g := &Guard{license: &License{Tier: TierEnterprise}, tier: TierEnterprise}
	for _, f := range []string{"report", "manage", "comprehensive_profile", "diff_trend", "custom_policy", "sso"} {
		if !g.HasFeature(f) {
			t.Errorf("enterprise compat should grant %s", f)
		}
	}
}

func TestGuard_HasFeature_NilSafe(t *testing.T) {
	var g *Guard
	if g.HasFeature("report") {
		t.Errorf("nil guard should not grant features")
	}
	g = &Guard{tier: TierFree}
	if g.HasFeature("manage") {
		t.Errorf("free tier should not grant manage")
	}
}

func TestGuard_LimitCap_V2(t *testing.T) {
	g := &Guard{
		license: &License{
			Limits: licensestore.Limits{
				{Metric: "seats", Window: "total", Cap: 100},
				{Metric: "scans", Window: "monthly", Cap: 10000},
			},
		},
	}
	if cap := g.LimitCap("seats", "total"); cap != 100 {
		t.Errorf("seats cap: want 100, got %d", cap)
	}
	if cap := g.LimitCap("scans", "monthly"); cap != 10000 {
		t.Errorf("scans cap: want 10000, got %d", cap)
	}
	if cap := g.LimitCap("hosts", "total"); cap != -1 {
		t.Errorf("unlimited should return -1, got %d", cap)
	}
}

func TestGuard_LimitCap_CompatFallback(t *testing.T) {
	g := &Guard{license: &License{Tier: TierPro}, tier: TierPro}
	if cap := g.LimitCap("seats", "total"); cap != 50 {
		t.Errorf("pro compat seats: want 50, got %d", cap)
	}
}

func TestGuard_SoftBufferCeiling(t *testing.T) {
	g := &Guard{
		license: &License{
			Limits: licensestore.Limits{
				{Metric: "scans", Window: "monthly", Cap: 1000},
			},
			SoftBufferPct: 10,
		},
	}
	if ceil := g.SoftBufferCeiling("scans", "monthly"); ceil != 1100 {
		t.Errorf("ceiling: want 1100, got %d", ceil)
	}
	// Unlimited metric → -1
	if ceil := g.SoftBufferCeiling("hosts", "total"); ceil != -1 {
		t.Errorf("unlimited ceiling: want -1, got %d", ceil)
	}
}

func TestGuard_SoftBufferCeiling_DefaultPct(t *testing.T) {
	// If SoftBufferPct is 0, default to 10%.
	g := &Guard{
		license: &License{
			Limits: licensestore.Limits{
				{Metric: "scans", Window: "total", Cap: 500},
			},
			SoftBufferPct: 0,
		},
	}
	if ceil := g.SoftBufferCeiling("scans", "total"); ceil != 550 {
		t.Errorf("default 10%% buffer: want 550, got %d", ceil)
	}
}

func TestGuard_AllowsFormat_V2AllowlistRespected(t *testing.T) {
	g := &Guard{
		license: &License{
			Features: licensestore.Features{
				Report:        true,
				ExportFormats: []string{"html", "pdf"},
			},
		},
	}
	if !g.AllowsFormat("html") || !g.AllowsFormat("pdf") {
		t.Errorf("allowed formats should pass")
	}
	if g.AllowsFormat("csv") || g.AllowsFormat("json") {
		t.Errorf("disallowed formats should be rejected")
	}
}

func TestGuard_AllowsFormat_CompatFallback(t *testing.T) {
	// Free tier compat allows only json.
	g := &Guard{license: &License{Tier: TierFree}, tier: TierFree}
	if !g.AllowsFormat("json") {
		t.Errorf("free tier should allow json")
	}
	if g.AllowsFormat("pdf") {
		t.Errorf("free tier should not allow pdf")
	}
}
