package agility

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

const weightOperational = 0.20

var automationNeedles = []string{"cert-manager", "certbot", "acme", "lego", "hashicorp-vault"}

func scoreOperationalReadiness(findings []model.Finding, now time.Time) Dimension {
	d := Dimension{Name: DimOperationalReady, Weight: weightOperational}

	certScore, certFired := certRotationScore(findings, now)
	hasHSM := false
	hasAutomation := false
	for i := range findings {
		f := &findings[i]
		if f.Module == "hsm" {
			hasHSM = true
		}
		hay := strings.ToLower(f.Source.Path + " " + f.Source.Evidence)
		for _, n := range automationNeedles {
			if strings.Contains(hay, n) {
				hasAutomation = true
				break
			}
		}
	}

	var sum, fired int
	if certFired {
		sum += certScore
		fired++
		d.Signals = append(d.Signals, Signal{Name: "cert_rotation_cadence", Value: fmt.Sprintf("%d", certScore), Contributes: certScore})
	}
	hsmScore := 0
	if hasHSM {
		hsmScore = 100
	}
	sum += hsmScore
	fired++
	d.Signals = append(d.Signals, Signal{Name: "hsm_present", Value: fmt.Sprintf("%t", hasHSM), Contributes: hsmScore})

	autoScore := 0
	if hasAutomation {
		autoScore = 100
	}
	sum += autoScore
	fired++
	d.Signals = append(d.Signals, Signal{Name: "automation_tool", Value: fmt.Sprintf("%t", hasAutomation), Contributes: autoScore})

	if fired == 0 {
		d.Score = 50
	} else {
		d.Score = sum / fired
	}
	d.Explanation = fmt.Sprintf("HSM=%t, automation=%t, cert-rotation-score=%d.", hasHSM, hasAutomation, certScore)
	return d
}

// certRotationScore returns (score, fired). fired=false when no cert findings.
func certRotationScore(findings []model.Finding, now time.Time) (int, bool) {
	var days []int
	for i := range findings {
		f := &findings[i]
		if f.Module != "certificates" || f.CryptoAsset == nil || f.CryptoAsset.NotAfter == nil {
			continue
		}
		delta := int(f.CryptoAsset.NotAfter.Sub(now).Hours() / 24)
		if delta < 0 {
			delta = 0 // already expired = urgent rotation window
		}
		days = append(days, delta)
	}
	if len(days) == 0 {
		return 0, false
	}
	sort.Ints(days)
	med := days[len(days)/2]
	switch {
	case med <= 90:
		return 100, true
	case med <= 180:
		return 75, true
	case med <= 365:
		return 50, true
	case med <= 730:
		return 25, true
	}
	return 0, true
}
