package model

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// AgilityFunc computes a crypto-agility label for a single asset.
// Callers that need the label (e.g. pkg/report) should supply this via
// GroupFindingsIntoSystemsWithAgility; GroupFindingsIntoSystems leaves
// CryptoAgility empty to avoid an import cycle with pkg/crypto.
type AgilityFunc func(asset *CryptoAsset) string

// GroupFindingsIntoSystems maps raw scan findings into System entities for Jadual 1.
// Grouping heuristics:
//   - Network findings: group by endpoint (host:port)
//   - Process findings: group by process basename
//   - File findings: group by parent directory
//
// CryptoAgility fields are left empty. Use GroupFindingsIntoSystemsWithAgility
// when agility assessment is required.
func GroupFindingsIntoSystems(findings []Finding) []System {
	return GroupFindingsIntoSystemsWithAgility(findings, nil)
}

// GroupFindingsIntoSystemsWithAgility is like GroupFindingsIntoSystems but
// calls agilityFn (if non-nil) to populate CryptoAgility on each asset.
func GroupFindingsIntoSystemsWithAgility(findings []Finding, agilityFn AgilityFunc) []System {
	if len(findings) == 0 {
		return nil
	}

	// Group findings by system key
	groups := make(map[string]*systemBuilder)
	var groupOrder []string

	for i := range findings {
		if findings[i].CryptoAsset == nil {
			continue
		}

		key := systemKey(findings[i])
		builder, exists := groups[key]
		if !exists {
			builder = &systemBuilder{
				name:      systemName(findings[i]),
				agilityFn: agilityFn,
			}
			groups[key] = builder
			groupOrder = append(groupOrder, key)
		}
		builder.findings = append(builder.findings, findings[i])
	}

	// Build systems in order
	cbomCounter := 1
	systems := make([]System, 0, len(groupOrder))

	for _, key := range groupOrder {
		builder := groups[key]
		sys := builder.buildSystem(&cbomCounter)
		systems = append(systems, sys)
	}

	return systems
}

// systemKey returns a grouping key for a finding.
func systemKey(f Finding) string {
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
func systemName(f Finding) string {
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
	name      string
	findings  []Finding
	agilityFn AgilityFunc
}

func (b *systemBuilder) buildSystem(cbomCounter *int) System {
	sys := System{
		ID:    uuid.Must(uuid.NewV7()).String(),
		Name:  b.name,
		InUse: true,
	}

	// Collect crypto assets and assign CBOM refs
	var components []string
	var libraries []string
	componentSet := make(map[string]bool)
	librarySet := make(map[string]bool)

	startCBOM := *cbomCounter

	for i := range b.findings {
		if b.findings[i].CryptoAsset == nil {
			continue
		}

		asset := *b.findings[i].CryptoAsset
		asset.SystemName = sys.Name

		// Assign crypto-agility assessment per asset (if agility function provided).
		if b.agilityFn != nil {
			asset.CryptoAgility = b.agilityFn(&asset)
		}

		sys.CryptoAssets = append(sys.CryptoAssets, asset)
		*cbomCounter++

		// Collect components and libraries
		if b.findings[i].CryptoAsset.Library != "" && !librarySet[b.findings[i].CryptoAsset.Library] {
			libraries = append(libraries, b.findings[i].CryptoAsset.Library)
			librarySet[b.findings[i].CryptoAsset.Library] = true
		}

		comp := b.findings[i].CryptoAsset.Algorithm
		if comp != "" && !componentSet[comp] {
			components = append(components, comp)
			componentSet[comp] = true
		}
	}

	endCBOM := *cbomCounter - 1
	sys.Components = components
	sys.ThirdPartyModules = libraries
	sys.ExternalAPIs = b.deriveExternalAPIs()

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
	for i := range b.findings {
		if b.findings[i].CryptoAsset != nil && b.findings[i].CryptoAsset.Purpose != "" {
			return b.findings[i].CryptoAsset.Purpose
		}
	}
	return "Cryptographic operations"
}

func (b *systemBuilder) deriveURL() string {
	for i := range b.findings {
		if b.findings[i].Source.Type == "network" && b.findings[i].Source.Endpoint != "" {
			return b.findings[i].Source.Endpoint
		}
	}
	return ""
}

// deriveExternalAPIs extracts application or service names from findings.
func (b *systemBuilder) deriveExternalAPIs() []string {
	apiSet := make(map[string]bool)

	for i := range b.findings {
		switch b.findings[i].Source.Type {
		case "network":
			// Command name from lsof output (e.g., "httpd", "sshd")
			if b.findings[i].Source.Path != "" {
				fields := strings.Fields(b.findings[i].Source.Path)
				if len(fields) > 0 {
					apiSet[filepath.Base(fields[0])] = true
				}
			}
		case "process":
			// Process command name
			if b.findings[i].Source.Path != "" {
				fields := strings.Fields(b.findings[i].Source.Path)
				if len(fields) > 0 {
					apiSet[filepath.Base(fields[0])] = true
				}
			}
		default:
			app := DeriveAppFromPath(b.findings[i].Source.Path)
			if app != "" {
				apiSet[app] = true
			}
		}
	}

	if len(apiSet) == 0 {
		return []string{"N/A"}
	}

	apis := make([]string, 0, len(apiSet))
	for api := range apiSet {
		apis = append(apis, api)
	}
	sort.Strings(apis)
	return apis
}

// DeriveAppFromPath extracts an application or program name from a filesystem path.
// Works across macOS, Linux, and Windows by recognising platform-specific
// installation patterns (app bundles, package dirs, Program Files, etc.).
func DeriveAppFromPath(path string) string {
	// --- macOS ---

	// .app bundle: /Applications/Rider.app/Contents/...
	if idx := strings.Index(path, ".app/"); idx != -1 {
		start := strings.LastIndex(path[:idx], "/")
		if start == -1 {
			start = 0
		} else {
			start++
		}
		return path[start:idx]
	}

	// .framework bundle: .../Security.framework/...
	if idx := strings.Index(path, ".framework/"); idx != -1 {
		start := strings.LastIndex(path[:idx], "/")
		if start == -1 {
			start = 0
		} else {
			start++
		}
		return path[start:idx]
	}

	// --- Cross-platform (Homebrew works on macOS + Linux) ---

	// Homebrew Cellar: /usr/local/Cellar/openssl@3/3.1.0/...
	if idx := strings.Index(path, "/Cellar/"); idx != -1 {
		rest := path[idx+8:]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			return rest[:slashIdx]
		}
		return rest
	}

	// --- Windows ---

	// Program Files: C:\Program Files\Vendor\App\... or C:\Program Files (x86)\...
	if idx := indexFold(path, `\Program Files`); idx != -1 {
		return extractWindowsAppName(path[idx:])
	}

	// ProgramData: C:\ProgramData\App\...
	if idx := indexFold(path, `\ProgramData\`); idx != -1 {
		rest := path[idx+13:]
		if name := firstPathComponent(rest, `\`); name != "" {
			return name
		}
	}

	// --- Linux ---

	// Snap packages: /snap/<package>/<revision>/...
	if strings.HasPrefix(path, "/snap/") {
		rest := path[6:]
		if name := firstPathComponent(rest, "/"); name != "" {
			return name
		}
	}

	// Flatpak: /var/lib/flatpak/app/<app-id>/...
	if idx := strings.Index(path, "/flatpak/app/"); idx != -1 {
		rest := path[idx+13:]
		if name := firstPathComponent(rest, "/"); name != "" {
			return name
		}
	}

	// dpkg/apt doc dir: /usr/share/doc/<package>/...
	if strings.HasPrefix(path, "/usr/share/doc/") {
		rest := path[15:]
		if name := firstPathComponent(rest, "/"); name != "" {
			return name
		}
	}

	// /opt/<package>/... (common for third-party Linux software + Homebrew opt on macOS)
	if idx := strings.Index(path, "/opt/"); idx != -1 {
		rest := path[idx+5:]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 && slashIdx < 40 {
			pkg := rest[:slashIdx]
			// Filter out dirs that aren't package names
			if pkg != "homebrew" && pkg != "local" && pkg != "X11" {
				return pkg
			}
		}
	}

	// /usr/lib/<package>/... (Linux library packages)
	for _, prefix := range []string{"/usr/lib/", "/usr/lib64/"} {
		if strings.HasPrefix(path, prefix) {
			rest := path[len(prefix):]
			// Skip arch triplet dirs (e.g., x86_64-linux-gnu)
			if name := firstPathComponent(rest, "/"); name != "" {
				if strings.Contains(name, "-linux-") || strings.Contains(name, "-gnu") {
					// Skip triplet, take next component
					if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
						rest2 := rest[slashIdx+1:]
						if name2 := firstPathComponent(rest2, "/"); name2 != "" {
							return name2
						}
					}
				} else {
					return name
				}
			}
		}
	}

	return ""
}

// extractWindowsAppName extracts the application name from a Windows Program Files path.
// Input starts at "\Program Files..." portion.
func extractWindowsAppName(path string) string {
	// Skip "\Program Files" or "\Program Files (x86)"
	rest := path[len(`\Program Files`):]
	rest = strings.TrimPrefix(rest, " (x86)")
	if rest == "" || rest[0] != '\\' {
		return ""
	}
	rest = rest[1:] // skip leading backslash

	// First component is typically vendor or app name
	name := firstPathComponent(rest, `\`)
	if name == "" {
		return ""
	}

	// If there's a second component and first looks like a vendor, use "Vendor App"
	afterFirst := rest[len(name):]
	if len(afterFirst) > 1 && afterFirst[0] == '\\' {
		sub := firstPathComponent(afterFirst[1:], `\`)
		if sub != "" && !strings.EqualFold(sub, "bin") && !strings.EqualFold(sub, "lib") &&
			!strings.EqualFold(sub, "etc") && !strings.EqualFold(sub, "share") &&
			!strings.EqualFold(sub, "usr") && !strings.EqualFold(sub, "var") {
			return name + " " + sub
		}
	}
	return name
}

// firstPathComponent returns the first component of a path split by sep.
func firstPathComponent(path, sep string) string {
	if path == "" {
		return ""
	}
	idx := strings.Index(path, sep)
	if idx <= 0 {
		return ""
	}
	return path[:idx]
}

// indexFold returns the index of the first case-insensitive occurrence of substr in s.
func indexFold(s, substr string) int {
	lower := strings.ToLower(s)
	return strings.Index(lower, strings.ToLower(substr))
}

func (b *systemBuilder) deriveCriticality() string {
	worstPriority := 0
	for i := range b.findings {
		if b.findings[i].CryptoAsset == nil {
			continue
		}
		if b.findings[i].CryptoAsset.MigrationPriority > worstPriority {
			worstPriority = b.findings[i].CryptoAsset.MigrationPriority
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
