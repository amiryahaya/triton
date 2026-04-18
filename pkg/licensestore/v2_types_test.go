package licensestore

import (
	"encoding/json"
	"testing"
)

func TestFeatures_MarshalUnmarshal(t *testing.T) {
	f := Features{
		Report:               true,
		Manage:               true,
		ComprehensiveProfile: true,
		DiffTrend:            false,
		CustomPolicy:         false,
		SSO:                  false,
		ExportFormats:        []string{"html", "pdf", "csv"},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var f2 Features
	if err := json.Unmarshal(b, &f2); err != nil {
		t.Fatal(err)
	}
	if f2.Report != f.Report || len(f2.ExportFormats) != 3 {
		t.Fatalf("roundtrip mismatch: %+v", f2)
	}
}

func TestFeatures_Has(t *testing.T) {
	f := Features{Report: true, DiffTrend: true}
	if !f.Has("report") || !f.Has("diff_trend") {
		t.Errorf("enabled features not reported as present")
	}
	if f.Has("manage") || f.Has("sso") || f.Has("bogus") {
		t.Errorf("disabled/unknown features reported as present")
	}
}

func TestFeatures_AllowsFormat(t *testing.T) {
	empty := Features{}
	if !empty.AllowsFormat("anything") {
		t.Errorf("empty ExportFormats should allow any format")
	}
	f := Features{ExportFormats: []string{"html", "pdf"}}
	if !f.AllowsFormat("html") || !f.AllowsFormat("pdf") {
		t.Errorf("listed formats should be allowed")
	}
	if f.AllowsFormat("json") {
		t.Errorf("unlisted format should be rejected")
	}
}

func TestLimitEntry_Validate(t *testing.T) {
	good := LimitEntry{Metric: "scans", Window: "monthly", Cap: 1000}
	if err := good.Validate(); err != nil {
		t.Fatalf("good entry failed: %v", err)
	}

	bad := []LimitEntry{
		{Metric: "unknown", Window: "total", Cap: 1},
		{Metric: "scans", Window: "yearly", Cap: 1},
		{Metric: "scans", Window: "monthly", Cap: -1},
		{Metric: "retention_days", Window: "daily", Cap: 30},
	}
	for i, e := range bad {
		if err := e.Validate(); err == nil {
			t.Errorf("bad[%d]: expected error for %+v", i, e)
		}
	}
}

func TestLimits_Find(t *testing.T) {
	ls := Limits{
		{Metric: "scans", Window: "total", Cap: 1000000},
		{Metric: "scans", Window: "monthly", Cap: 10000},
		{Metric: "hosts", Window: "total", Cap: 500},
	}
	if e := ls.Find("scans", "monthly"); e == nil || e.Cap != 10000 {
		t.Errorf("scans/monthly: want 10000, got %+v", e)
	}
	if e := ls.Find("hosts", "daily"); e != nil {
		t.Errorf("hosts/daily: want nil, got %+v", e)
	}
}

func TestLimitEntry_BufferCeiling(t *testing.T) {
	cases := []struct {
		cap, pct int
		want     int64
	}{
		{100, 10, 110},
		{1000, 10, 1100},
		{0, 10, 0},
		{50, 0, 50},
		{3, 10, 3}, // floor(3 * 10 / 100) = 0; 3 + 0 = 3 (effectively hard cap)
	}
	for _, c := range cases {
		got := LimitEntry{Cap: int64(c.cap)}.BufferCeiling(c.pct)
		if got != c.want {
			t.Errorf("cap=%d pct=%d: want %d got %d", c.cap, c.pct, c.want, got)
		}
	}
}

func TestLimits_MarshalJSON_NilIsEmptyArray(t *testing.T) {
	var ls Limits
	b, err := json.Marshal(ls)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `[]` {
		t.Errorf("nil Limits should marshal to [], got %q", b)
	}
}

func TestFeatures_ScanValue_RoundTrip(t *testing.T) {
	orig := Features{Report: true, ExportFormats: []string{"html"}}
	v, err := orig.Value()
	if err != nil {
		t.Fatal(err)
	}
	var restored Features
	if err := restored.Scan(v); err != nil {
		t.Fatal(err)
	}
	if restored.Report != orig.Report || len(restored.ExportFormats) != 1 {
		t.Errorf("Value/Scan round-trip mismatch: %+v", restored)
	}

	// Scanning nil should produce zero value.
	var empty Features
	if err := empty.Scan(nil); err != nil {
		t.Fatal(err)
	}
	if empty.Report {
		t.Errorf("nil scan should produce zero Features")
	}
}

func TestLimits_ScanValue_RoundTrip(t *testing.T) {
	orig := Limits{{Metric: "seats", Window: "total", Cap: 50}}
	v, err := orig.Value()
	if err != nil {
		t.Fatal(err)
	}
	var restored Limits
	if err := restored.Scan(v); err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0].Cap != 50 {
		t.Errorf("Limits Value/Scan round-trip mismatch: %+v", restored)
	}
}
