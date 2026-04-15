package agility

import (
	"fmt"
	"sort"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

const weightProtocolAgility = 0.25

var protocolModules = map[string]bool{
	"protocol":   true,
	"web_server": true,
	"vpn_config": true,
}

func scoreProtocolAgility(findings []model.Finding) Dimension {
	d := Dimension{Name: DimProtocolAgility, Weight: weightProtocolAgility}

	maxTLS := -1 // -1 = not observed
	groups := make(map[string]bool)
	hasHybrid := false
	protocolFindings := 0

	for i := range findings {
		f := &findings[i]
		if !protocolModules[f.Module] || f.CryptoAsset == nil {
			continue
		}
		protocolFindings++
		algo := f.CryptoAsset.Algorithm
		if v := tlsVersionScore(algo); v >= 0 && v > maxTLS {
			maxTLS = v
		}
		if isNamedGroup(algo) {
			groups[algo] = true
		}
		if f.CryptoAsset.IsHybrid {
			hasHybrid = true
		}
	}

	if protocolFindings == 0 {
		d.Score = 50
		d.Explanation = "No TLS/VPN protocol findings; cannot assess protocol agility."
		return d
	}

	var sum, fired int
	if maxTLS >= 0 {
		sum += maxTLS
		fired++
		d.Signals = append(d.Signals, Signal{Name: "tls_version_ceiling", Value: tlsVersionLabel(maxTLS), Contributes: maxTLS})
	}
	divScore := diversityScore(len(groups))
	if len(groups) > 0 {
		sum += divScore
		fired++
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		d.Signals = append(d.Signals, Signal{Name: "named_group_diversity", Value: strings.Join(keys, ","), Contributes: divScore})
	}
	// Hybrid signal fires only when a hybrid group is actually observed.
	// Legacy TLS is already penalised via the version ceiling; firing this
	// signal on its absence would double-penalise the same condition.
	if hasHybrid {
		sum += 100
		fired++
		d.Signals = append(d.Signals, Signal{Name: "hybrid_group_present", Value: "true", Contributes: 100})
	}

	if fired == 0 {
		d.Score = 50
	} else {
		d.Score = sum / fired
	}
	d.Explanation = fmt.Sprintf("TLS ceiling %s, %d distinct groups, hybrid=%t.",
		tlsVersionLabel(maxTLS), len(groups), hasHybrid)
	return d
}

func tlsVersionScore(algo string) int {
	switch strings.TrimSpace(algo) {
	case "TLS 1.3":
		return 100
	case "TLS 1.2":
		return 60
	case "TLS 1.1":
		return 20
	case "TLS 1.0":
		return 0
	}
	return -1
}

func tlsVersionLabel(score int) string {
	switch score {
	case 100:
		return "TLS 1.3"
	case 60:
		return "TLS 1.2"
	case 20:
		return "TLS 1.1"
	case 0:
		return "TLS 1.0"
	}
	return "n/a"
}

func diversityScore(n int) int {
	switch {
	case n >= 4:
		return 100
	case n == 3:
		return 75
	case n == 2:
		return 50
	case n == 1:
		return 25
	}
	return 0
}

// isNamedGroup is a coarse heuristic: TLS group algorithm names tend to match
// IANA registry tokens. We treat anything non-empty that isn't a TLS version
// label and isn't a cipher suite string as a group.
func isNamedGroup(algo string) bool {
	if algo == "" {
		return false
	}
	if tlsVersionScore(algo) >= 0 {
		return false
	}
	// Reject IANA-style cipher suites (e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).
	if strings.Contains(algo, "_WITH_") {
		return false
	}
	// Reject OpenSSL-style cipher suite tokens (e.g. ECDHE-RSA-AES128-GCM-SHA256).
	upper := strings.ToUpper(algo)
	for _, marker := range []string{"-AES", "-GCM", "-SHA", "-RSA-", "-ECDHE-", "-CHACHA"} {
		if strings.Contains(upper, marker) {
			return false
		}
	}
	return true
}
