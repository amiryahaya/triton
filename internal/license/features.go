package license

import "github.com/amiryahaya/triton/pkg/licensestore"

// HasFeature returns whether the current licence enables the named feature.
//
// Consults the v2 Features set if any v2 flag is set on the token; falls back
// to a legacy-tier compatibility mapping otherwise. This lets pre-v2 tokens
// (issued with only tier=pro etc.) behave correctly during the v2 rollout.
//
// Unknown feature names return false.
func (g *Guard) HasFeature(name string) bool {
	if g == nil || g.license == nil {
		// No licence → free tier behaviour (no features beyond compat mapping).
		// Nil guard (no token at all) grants nothing; a guard with an explicit
		// free-tier licence gets the compat set via the fallback path below.
		return false
	}
	if featuresAnySet(g.license.Features) {
		return g.license.Features.Has(name)
	}
	return licensestore.CompatFeatures(string(g.tier)).Has(name)
}

// LimitCap returns the cap for the given metric/window combination, or -1
// if no cap is set (unlimited). Falls back to the legacy-tier compat mapping
// when the licence carries no v2 limits.
func (g *Guard) LimitCap(metric, window string) int64 {
	if g == nil || g.license == nil {
		if e := licensestore.CompatLimits(string(TierFree)).Find(metric, window); e != nil {
			return e.Cap
		}
		return -1
	}
	limits := g.license.Limits
	if len(limits) == 0 {
		limits = licensestore.CompatLimits(string(g.tier))
	}
	if e := limits.Find(metric, window); e != nil {
		return e.Cap
	}
	return -1
}

// SoftBufferCeiling returns cap + floor(cap * soft_buffer_pct / 100) — the
// hard ceiling for soft-enforced metrics. Returns -1 if the metric has no cap.
func (g *Guard) SoftBufferCeiling(metric, window string) int64 {
	limitCap := g.LimitCap(metric, window)
	if limitCap < 0 {
		return -1
	}
	pct := 10 // default
	if g != nil && g.license != nil && g.license.SoftBufferPct > 0 {
		pct = g.license.SoftBufferPct
	}
	return limitCap + (limitCap*int64(pct))/100
}

// CurrentUsage returns the current usage the licence server most
// recently acknowledged for the given metric / window, or 0 when no
// acknowledgement is on record. Intended as the "used" half of the
// soft-buffer cap formula (used + expected > SoftBufferCeiling).
//
// The Guard keeps usage in an in-memory map that the consumer-side
// UsagePusher hooks update via RecordPushAck — Manage Server does not
// keep a separate shadow copy. Pre-Batch-H Guards have no ack
// callback wired, so this method returns 0 until the first successful
// usage push.
//
// The returned value lags reality by up to one pusher tick (default
// 60 s). Admins who need stricter enforcement can tighten the pusher
// interval via UsagePusherConfig.Interval.
func (g *Guard) CurrentUsage(metric, window string) int64 {
	if g == nil {
		return 0
	}
	g.usageMu.RLock()
	defer g.usageMu.RUnlock()
	return g.usage[metric+"/"+window]
}

// RecordUsage stashes the ack'd usage count for the given metric /
// window. Called by the UsagePusher's OnPushSuccess hook when the LS
// response includes remaining-cap information. Safe to call
// concurrently; the map is guarded by usageMu.
//
// Overwrites whatever was previously stashed for (metric, window) —
// we trust the most recent LS ack. A ≤-zero count is stored as 0 so
// downstream arithmetic stays positive.
func (g *Guard) RecordUsage(metric, window string, used int64) {
	if g == nil {
		return
	}
	if used < 0 {
		used = 0
	}
	g.usageMu.Lock()
	defer g.usageMu.Unlock()
	if g.usage == nil {
		g.usage = map[string]int64{}
	}
	g.usage[metric+"/"+window] = used
}

// AllowsFormat returns whether the given report format is permitted by the
// licence's export-formats allowlist. Falls back to the legacy-tier compat
// mapping for pre-v2 tokens.
func (g *Guard) AllowsFormat(format string) bool {
	if g == nil || g.license == nil {
		// No licence or nil guard: use free-tier compat mapping.
		tier := TierFree
		if g != nil {
			tier = g.tier
		}
		return licensestore.CompatFeatures(string(tier)).AllowsFormat(format)
	}
	if featuresAnySet(g.license.Features) {
		return g.license.Features.AllowsFormat(format)
	}
	return licensestore.CompatFeatures(string(g.tier)).AllowsFormat(format)
}

// featuresAnySet returns true if any v2 feature flag is set.
func featuresAnySet(f licensestore.Features) bool {
	return f.Report || f.Manage || f.ComprehensiveProfile || f.DiffTrend ||
		f.CustomPolicy || f.SSO || len(f.ExportFormats) > 0
}
