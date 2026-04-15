package agility

import (
	"fmt"

	"github.com/amiryahaya/triton/pkg/model"
)

const weightConfigFlexibility = 0.20

var configModules = map[string]bool{
	"configs":              true,
	"web_server":           true,
	"vpn_config":           true,
	"certstore":            true,
	"container_signatures": true,
}

var hardcodedModules = map[string]bool{
	"binaries":      true,
	"asn1_oid":      true,
	"java_bytecode": true,
	"kernel":        true,
	"codesign":      true,
}

func scoreConfigFlexibility(findings []model.Finding) Dimension {
	d := Dimension{Name: DimConfigFlexibility, Weight: weightConfigFlexibility}

	var cfg, hard int
	for i := range findings {
		m := findings[i].Module
		switch {
		case configModules[m]:
			cfg++
		case hardcodedModules[m]:
			hard++
		}
	}
	total := cfg + hard
	if total == 0 {
		d.Score = 50
		d.Explanation = "No config-vs-hardcoded signal; neutral score."
		return d
	}
	d.Score = (cfg * 100) / total
	d.Signals = []Signal{
		{Name: "config_referenced", Value: fmt.Sprintf("%d", cfg), Contributes: d.Score},
		{Name: "hardcoded", Value: fmt.Sprintf("%d", hard), Contributes: -((hard * 100) / total)},
	}
	d.Explanation = fmt.Sprintf("%d config-referenced vs %d hardcoded crypto findings.", cfg, hard)
	return d
}
