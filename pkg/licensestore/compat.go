package licensestore

// CompatFeatures maps a legacy tier to the v2 Features it implies.
// Used when a licence row has empty features (i.e. issued pre-v2) — preserves
// existing customer behaviour until the licence is re-issued in v2 form.
func CompatFeatures(tier string) Features {
	switch tier {
	case "free":
		return Features{
			Report:        true,
			ExportFormats: []string{"json"},
		}
	case "pro":
		return Features{
			Report:               true,
			ComprehensiveProfile: true,
			DiffTrend:            true,
			ExportFormats:        []string{"html", "pdf", "csv", "json"},
		}
	case "enterprise":
		return Features{
			Report:               true,
			Manage:               true,
			ComprehensiveProfile: true,
			DiffTrend:            true,
			CustomPolicy:         true,
			SSO:                  true,
			ExportFormats:        []string{"html", "pdf", "csv", "json", "sarif"},
		}
	default:
		return Features{}
	}
}

// CompatLimits maps a legacy tier to the per-metric caps it implied.
func CompatLimits(tier string) Limits {
	switch tier {
	case "free":
		return Limits{{Metric: "seats", Window: "total", Cap: 5}}
	case "pro":
		return Limits{{Metric: "seats", Window: "total", Cap: 50}}
	case "enterprise":
		return Limits{
			{Metric: "seats", Window: "total", Cap: 500},
			{Metric: "tenants", Window: "total", Cap: 10},
		}
	default:
		return Limits{}
	}
}

// ResolveFeatures returns the licence's effective feature set. If the licence
// has any v2 feature set, that takes precedence; otherwise the legacy-tier
// compatibility mapping is applied.
func ResolveFeatures(l *LicenseRecord) Features {
	if featuresAnySet(l.Features) {
		return l.Features
	}
	return CompatFeatures(l.Tier)
}

// ResolveLimits returns the licence's effective limit set, with the same
// precedence rule as ResolveFeatures.
func ResolveLimits(l *LicenseRecord) Limits {
	if len(l.Limits) > 0 {
		return l.Limits
	}
	return CompatLimits(l.Tier)
}

func featuresAnySet(f Features) bool {
	return f.Report || f.Manage || f.ComprehensiveProfile || f.DiffTrend ||
		f.CustomPolicy || f.SSO || len(f.ExportFormats) > 0
}
