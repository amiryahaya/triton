package licensestore

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"slices"
)

// Features is the set of product + capability entitlements a licence
// carries. Stored in the `features` JSONB column on the licenses table.
//
// Agent entitlement is implicit whenever any licence exists and is not
// represented here.
type Features struct {
	Report               bool     `json:"report"`
	Manage               bool     `json:"manage"`
	ComprehensiveProfile bool     `json:"comprehensive_profile"`
	DiffTrend            bool     `json:"diff_trend"`
	CustomPolicy         bool     `json:"custom_policy"`
	SSO                  bool     `json:"sso"`
	ExportFormats        []string `json:"export_formats,omitempty"`
}

// Has returns true if the named feature is enabled. Unknown names return false.
func (f Features) Has(name string) bool {
	switch name {
	case "report":
		return f.Report
	case "manage":
		return f.Manage
	case "comprehensive_profile":
		return f.ComprehensiveProfile
	case "diff_trend":
		return f.DiffTrend
	case "custom_policy":
		return f.CustomPolicy
	case "sso":
		return f.SSO
	default:
		return false
	}
}

// AllowsFormat returns true if the format is listed in ExportFormats.
// Empty ExportFormats means "no gating" — all formats allowed.
func (f Features) AllowsFormat(format string) bool {
	if len(f.ExportFormats) == 0 {
		return true
	}
	return slices.Contains(f.ExportFormats, format)
}

// Scan implements sql.Scanner for pgx JSONB columns.
func (f *Features) Scan(src any) error {
	switch v := src.(type) {
	case []byte:
		return json.Unmarshal(v, f)
	case string:
		return json.Unmarshal([]byte(v), f)
	case nil:
		*f = Features{}
		return nil
	default:
		return fmt.Errorf("cannot scan %T into Features", src)
	}
}

// Value implements driver.Valuer for pgx JSONB columns.
func (f Features) Value() (driver.Value, error) {
	return json.Marshal(f)
}

// LimitEntry is a single per-metric cap in the `limits` JSONB array.
type LimitEntry struct {
	Metric string `json:"metric"`
	Window string `json:"window"`
	Cap    int64  `json:"cap"`
}

var validMetrics = map[string]bool{
	"seats":             true,
	"tenants":           true,
	"hosts":             true,
	"scans":             true,
	"reports_generated": true,
	"report_downloads":  true,
	"retention_days":    true,
}

var validWindows = map[string]bool{
	"total":   true,
	"daily":   true,
	"monthly": true,
}

// Validate checks metric, window, and cap constraints.
func (e LimitEntry) Validate() error {
	if !validMetrics[e.Metric] {
		return fmt.Errorf("unknown metric %q", e.Metric)
	}
	if !validWindows[e.Window] {
		return fmt.Errorf("unknown window %q", e.Window)
	}
	if e.Cap < 0 {
		return fmt.Errorf("cap must be >= 0 (got %d)", e.Cap)
	}
	if e.Metric == "retention_days" && e.Window != "total" {
		return fmt.Errorf("retention_days only supports window=total")
	}
	return nil
}

// BufferCeiling returns cap + floor(cap * pct / 100) — the hard ceiling
// above which soft-enforced metrics reject new work.
func (e LimitEntry) BufferCeiling(softBufferPct int) int64 {
	return e.Cap + (e.Cap*int64(softBufferPct))/100
}

// Limits is the array of LimitEntry stored in licenses.limits.
type Limits []LimitEntry

// Find returns the matching entry, or nil if absent (unlimited).
func (ls Limits) Find(metric, window string) *LimitEntry {
	for i := range ls {
		if ls[i].Metric == metric && ls[i].Window == window {
			return &ls[i]
		}
	}
	return nil
}

// Validate runs each entry's Validate and returns the first error.
func (ls Limits) Validate() error {
	for i, e := range ls {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("limits[%d]: %w", i, err)
		}
	}
	return nil
}

// MarshalJSON ensures nil Limits serialise as `[]`, not `null`, so JSONB
// columns never receive NULL when the Go value is an empty slice.
func (ls Limits) MarshalJSON() ([]byte, error) {
	if ls == nil {
		return []byte(`[]`), nil
	}
	return json.Marshal([]LimitEntry(ls))
}

// Scan implements sql.Scanner.
func (ls *Limits) Scan(src any) error {
	switch v := src.(type) {
	case []byte:
		return json.Unmarshal(v, ls)
	case string:
		return json.Unmarshal([]byte(v), ls)
	case nil:
		*ls = Limits{}
		return nil
	default:
		return fmt.Errorf("cannot scan %T into Limits", src)
	}
}

// Value implements driver.Valuer.
func (ls Limits) Value() (driver.Value, error) {
	if ls == nil {
		return []byte(`[]`), nil
	}
	return json.Marshal([]LimitEntry(ls))
}
