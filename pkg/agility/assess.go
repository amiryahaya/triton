package agility

import (
	"math"
	"sort"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// AssessAll returns one Score per host observed in the scan result, sorted by
// hostname. Returns nil when result is nil or has no findings.
func AssessAll(result *model.ScanResult) []Score {
	if result == nil || len(result.Findings) == 0 {
		return nil
	}
	fallback := result.Metadata.Hostname
	if fallback == "" {
		fallback = "unknown"
	}
	groups := groupFindingsByHost(result.Findings, fallback)
	now := time.Now().UTC()

	hosts := make([]string, 0, len(groups))
	for h := range groups {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	scores := make([]Score, 0, len(hosts))
	for _, h := range hosts {
		scores = append(scores, scoreHost(h, groups[h], now))
	}
	return scores
}

func groupFindingsByHost(findings []model.Finding, fallback string) map[string][]model.Finding {
	out := make(map[string][]model.Finding)
	for i := range findings {
		h := findings[i].Source.Endpoint
		if h == "" {
			h = fallback
		}
		out[h] = append(out[h], findings[i])
	}
	return out
}

func scoreHost(host string, findings []model.Finding, now time.Time) Score {
	dims := []Dimension{
		scorePQCCoverage(findings),
		scoreProtocolAgility(findings),
		scoreConfigFlexibility(findings),
		scoreOperationalReadiness(findings, now),
	}
	var weighted float64
	for _, d := range dims {
		weighted += float64(d.Score) * d.Weight
	}
	s := Score{
		Hostname:    host,
		Overall:     int(math.Round(weighted)),
		Dimensions:  dims,
		GeneratedAt: now,
	}
	// Recommendations are wired in Task 7.
	return s
}
