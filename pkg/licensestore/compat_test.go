package licensestore

import "testing"

func TestCompatFeatures(t *testing.T) {
	cases := []struct {
		tier              string
		wantReport        bool
		wantManage        bool
		wantDiffTrend     bool
		wantComprehensive bool
		wantCustomPolicy  bool
	}{
		{"free", true, false, false, false, false},
		{"pro", true, false, true, true, false},
		{"enterprise", true, true, true, true, true},
		{"unknown", false, false, false, false, false},
	}
	for _, tt := range cases {
		f := CompatFeatures(tt.tier)
		if f.Report != tt.wantReport {
			t.Errorf("%s: Report=%v want=%v", tt.tier, f.Report, tt.wantReport)
		}
		if f.Manage != tt.wantManage {
			t.Errorf("%s: Manage=%v want=%v", tt.tier, f.Manage, tt.wantManage)
		}
		if f.DiffTrend != tt.wantDiffTrend {
			t.Errorf("%s: DiffTrend=%v want=%v", tt.tier, f.DiffTrend, tt.wantDiffTrend)
		}
		if f.ComprehensiveProfile != tt.wantComprehensive {
			t.Errorf("%s: CompProf=%v want=%v", tt.tier, f.ComprehensiveProfile, tt.wantComprehensive)
		}
		if f.CustomPolicy != tt.wantCustomPolicy {
			t.Errorf("%s: CustomPolicy=%v want=%v", tt.tier, f.CustomPolicy, tt.wantCustomPolicy)
		}
	}
}

func TestCompatLimits(t *testing.T) {
	tests := []struct {
		tier       string
		seatCap    int64
		wantExtras int // count of non-seat entries
	}{
		{"free", 5, 0},
		{"pro", 50, 0},
		{"enterprise", 500, 1}, // + tenants
		{"unknown", 0, 0},
	}
	for _, tt := range tests {
		ls := CompatLimits(tt.tier)
		if tt.tier == "unknown" {
			if len(ls) != 0 {
				t.Errorf("unknown tier should yield no limits, got %d", len(ls))
			}
			continue
		}
		e := ls.Find("seats", "total")
		if e == nil || e.Cap != tt.seatCap {
			t.Errorf("%s seats cap: want %d, got %+v", tt.tier, tt.seatCap, e)
		}
	}
}

func TestResolveFeatures_V2TakesPrecedence(t *testing.T) {
	// License has both v2 features AND a legacy tier — v2 wins.
	lic := &LicenseRecord{
		Tier: "free", // would map to report-only
		Features: Features{
			Report:    true,
			Manage:    true, // v2 gives manage which free-tier wouldn't
			DiffTrend: true,
		},
	}
	got := ResolveFeatures(lic)
	if !got.Manage {
		t.Errorf("v2 features should take precedence, expected Manage=true")
	}
}

func TestResolveFeatures_FallsBackToTier(t *testing.T) {
	// License has no v2 features (all-false, empty) — fall back to tier.
	lic := &LicenseRecord{Tier: "enterprise"}
	got := ResolveFeatures(lic)
	if !got.Manage || !got.CustomPolicy {
		t.Errorf("enterprise compat: want Manage+CustomPolicy, got %+v", got)
	}
}

func TestResolveLimits_V2TakesPrecedence(t *testing.T) {
	lic := &LicenseRecord{
		Tier: "enterprise", // would give 500 seats compat
		Limits: Limits{
			{Metric: "seats", Window: "total", Cap: 2000}, // v2 override
		},
	}
	got := ResolveLimits(lic)
	if e := got.Find("seats", "total"); e == nil || e.Cap != 2000 {
		t.Errorf("v2 limits should take precedence, got %+v", e)
	}
}

func TestResolveLimits_FallsBackToTier(t *testing.T) {
	lic := &LicenseRecord{Tier: "pro"}
	got := ResolveLimits(lic)
	if e := got.Find("seats", "total"); e == nil || e.Cap != 50 {
		t.Errorf("pro compat: want 50 seats, got %+v", e)
	}
}
