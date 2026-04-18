package license

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

func TestLicense_V2Claims_EncodeParse(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	orig := &License{
		ID:        "test-id",
		Tier:      TierEnterprise,
		Org:       "ACME",
		Seats:     50,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
		Features: licensestore.Features{
			Report:               true,
			Manage:               true,
			ComprehensiveProfile: true,
			DiffTrend:            true,
			ExportFormats:        []string{"html", "pdf", "csv"},
		},
		Limits: licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 50},
			{Metric: "scans", Window: "monthly", Cap: 10000},
		},
		SoftBufferPct: 10,
		ProductScope:  "bundle",
	}
	tok, err := Encode(orig, priv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(tok, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Features.Report || !parsed.Features.Manage {
		t.Errorf("features not round-tripped: %+v", parsed.Features)
	}
	if e := parsed.Limits.Find("scans", "monthly"); e == nil || e.Cap != 10000 {
		t.Errorf("limits not round-tripped: %+v", e)
	}
	if parsed.SoftBufferPct != 10 || parsed.ProductScope != "bundle" {
		t.Errorf("v2 scalars not round-tripped: sbp=%d ps=%q", parsed.SoftBufferPct, parsed.ProductScope)
	}
}

func TestLicense_V1LegacyToken_ParsesWithEmptyV2(t *testing.T) {
	// A v1 legacy licence without any v2 fields parses cleanly and
	// has zero-value Features/Limits.
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	legacy := &License{
		ID:        "legacy-id",
		Tier:      TierPro,
		Org:       "ACME",
		Seats:     25,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	tok, err := Encode(legacy, priv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(tok, pub)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Features.Report || parsed.Features.Manage {
		t.Errorf("legacy token should have empty features")
	}
	if len(parsed.Limits) != 0 {
		t.Errorf("legacy token should have empty limits")
	}
}

func TestLicense_V2Claims_AllFeatures(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	orig := &License{
		ID:        "ent-id",
		Tier:      TierEnterprise,
		Org:       "Corp",
		Seats:     500,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features: licensestore.Features{
			Report:               true,
			Manage:               true,
			ComprehensiveProfile: true,
			DiffTrend:            true,
			CustomPolicy:         true,
			SSO:                  true,
			ExportFormats:        []string{"html", "pdf", "csv", "json", "sarif"},
		},
		Limits: licensestore.Limits{
			{Metric: "seats", Window: "total", Cap: 500},
			{Metric: "tenants", Window: "total", Cap: 10},
			{Metric: "scans", Window: "monthly", Cap: 100000},
		},
		SoftBufferPct: 5,
		ProductScope:  "enterprise",
	}
	tok, err := Encode(orig, priv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(tok, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Features.SSO || !parsed.Features.CustomPolicy {
		t.Errorf("enterprise features not round-tripped: %+v", parsed.Features)
	}
	if e := parsed.Limits.Find("tenants", "total"); e == nil || e.Cap != 10 {
		t.Errorf("tenants limit not round-tripped")
	}
	if parsed.SoftBufferPct != 5 {
		t.Errorf("soft_buffer_pct not round-tripped: got %d", parsed.SoftBufferPct)
	}
}
