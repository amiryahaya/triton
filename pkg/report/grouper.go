package report

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/google/uuid"
)

// GroupFindingsIntoSystems maps raw scan findings into System entities for Jadual 1.
// Grouping heuristics:
//   - Network findings: group by endpoint (host:port)
//   - Process findings: group by process basename
//   - File findings: group by parent directory
func GroupFindingsIntoSystems(findings []model.Finding) []model.System {
	if len(findings) == 0 {
		return nil
	}

	// Group findings by system key
	groups := make(map[string]*systemBuilder)
	var groupOrder []string

	for _, f := range findings {
		if f.CryptoAsset == nil {
			continue
		}

		key := systemKey(f)
		builder, exists := groups[key]
		if !exists {
			builder = &systemBuilder{
				name: systemName(f),
			}
			groups[key] = builder
			groupOrder = append(groupOrder, key)
		}
		builder.findings = append(builder.findings, f)
	}

	// Build systems in order
	cbomCounter := 1
	var systems []model.System

	for _, key := range groupOrder {
		builder := groups[key]
		sys := builder.buildSystem(&cbomCounter)
		systems = append(systems, sys)
	}

	return systems
}

// systemKey returns a grouping key for a finding.
func systemKey(f model.Finding) string {
	switch f.Source.Type {
	case "network":
		// Group by endpoint host:port
		return "net:" + f.Source.Endpoint
	case "process":
		// Group by process basename
		cmd := f.Source.Path
		if fields := strings.Fields(cmd); len(fields) > 0 {
			return "proc:" + filepath.Base(fields[0])
		}
		return "proc:unknown"
	default:
		// File findings: group by parent directory
		dir := filepath.Dir(f.Source.Path)
		return "file:" + dir
	}
}

// systemName derives a human-readable system name from a finding.
func systemName(f model.Finding) string {
	switch f.Source.Type {
	case "network":
		ep := f.Source.Endpoint
		if f.CryptoAsset != nil && f.CryptoAsset.Function != "" {
			fn := f.CryptoAsset.Function
			if strings.Contains(fn, "TLS") {
				return fmt.Sprintf("TLS Service (%s)", ep)
			}
			if strings.Contains(fn, "SSH") {
				return fmt.Sprintf("SSH Service (%s)", ep)
			}
		}
		return fmt.Sprintf("Network Service (%s)", ep)
	case "process":
		cmd := f.Source.Path
		if fields := strings.Fields(cmd); len(fields) > 0 {
			base := filepath.Base(fields[0])
			return fmt.Sprintf("%s (process)", base)
		}
		return "Unknown Process"
	default:
		dir := filepath.Dir(f.Source.Path)
		return fmt.Sprintf("Files in %s", dir)
	}
}

type systemBuilder struct {
	name     string
	findings []model.Finding
}

func (b *systemBuilder) buildSystem(cbomCounter *int) model.System {
	sys := model.System{
		ID:   uuid.New().String(),
		Name: b.name,
		InUse: true,
	}

	// Collect crypto assets and assign CBOM refs
	var components []string
	var libraries []string
	componentSet := make(map[string]bool)
	librarySet := make(map[string]bool)

	startCBOM := *cbomCounter

	for _, f := range b.findings {
		if f.CryptoAsset == nil {
			continue
		}

		asset := *f.CryptoAsset
		asset.SystemName = sys.Name

		// Assign crypto-agility assessment per asset
		asset.CryptoAgility = crypto.AssessAssetAgility(&asset)

		sys.CryptoAssets = append(sys.CryptoAssets, asset)
		*cbomCounter++

		// Collect components and libraries
		if f.CryptoAsset.Library != "" && !librarySet[f.CryptoAsset.Library] {
			libraries = append(libraries, f.CryptoAsset.Library)
			librarySet[f.CryptoAsset.Library] = true
		}

		comp := f.CryptoAsset.Algorithm
		if comp != "" && !componentSet[comp] {
			components = append(components, comp)
			componentSet[comp] = true
		}
	}

	endCBOM := *cbomCounter - 1
	sys.Components = components
	sys.ThirdPartyModules = libraries

	// Derive purpose from findings
	sys.Purpose = b.derivePurpose()

	// Derive URL for network services
	sys.URL = b.deriveURL()

	// Derive criticality from worst PQC status
	sys.CriticalityLevel = b.deriveCriticality()

	// Format CBOM link range
	if startCBOM == endCBOM {
		sys.CBOMRefs = []string{fmt.Sprintf("CBOM #%d", startCBOM)}
	} else {
		sys.CBOMRefs = []string{fmt.Sprintf("CBOM #%d - CBOM #%d", startCBOM, endCBOM)}
	}

	return sys
}

func (b *systemBuilder) derivePurpose() string {
	for _, f := range b.findings {
		if f.CryptoAsset != nil && f.CryptoAsset.Purpose != "" {
			return f.CryptoAsset.Purpose
		}
	}
	return "Cryptographic operations"
}

func (b *systemBuilder) deriveURL() string {
	for _, f := range b.findings {
		if f.Source.Type == "network" && f.Source.Endpoint != "" {
			return f.Source.Endpoint
		}
	}
	return ""
}

func (b *systemBuilder) deriveCriticality() string {
	worstPriority := 0
	for _, f := range b.findings {
		if f.CryptoAsset == nil {
			continue
		}
		if f.CryptoAsset.MigrationPriority > worstPriority {
			worstPriority = f.CryptoAsset.MigrationPriority
		}
	}

	switch {
	case worstPriority >= 75:
		return "Sangat Tinggi"
	case worstPriority >= 50:
		return "Tinggi"
	case worstPriority >= 25:
		return "Sederhana"
	default:
		return "Rendah"
	}
}
