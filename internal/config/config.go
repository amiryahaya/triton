package config

import (
	"runtime"

	"github.com/amiryahaya/triton/pkg/model"
)

type Config struct {
	Profile         string
	Modules         []string
	OutputFormat    string
	OutputFile      string
	MaxDepth        int
	FollowSymlinks  bool
	IncludePatterns []string
	ExcludePatterns []string
	MaxFileSize     int64
	Workers         int
	ScanTargets     []model.ScanTarget
	Metrics         bool
	DBUrl           string
	Incremental     bool
}

// DefaultDBUrl returns the default PostgreSQL connection URL.
func DefaultDBUrl() string {
	return "postgres://triton:triton@localhost:5434/triton?sslmode=disable"
}

type ScanProfile struct {
	Name        string
	Description string
	Modules     []string
	Depth       int
	Workers     int
}

var profiles = map[string]ScanProfile{
	"quick": {
		Name:        "quick",
		Description: "Fast scan of critical areas only",
		Modules:     []string{"certificates", "keys", "packages"},
		Depth:       3,
		Workers:     4,
	},
	"standard": {
		Name:        "standard",
		Description: "Balanced scan of system",
		// Sprint A1/A3 — web_server and vpn join the standard
		// profile because TLS posture and VPN crypto are
		// expected coverage for any compliance-driven scan,
		// not deep-dive territory.
		//
		// Fast Wins sprint — password_hash joins standard
		// because /etc/shadow and pg_hba.conf are the #1
		// compliance-audit targets after certificates. Auth
		// material stays in comprehensive only (Kerberos /
		// GPG / Tor / DNSSEC are niche per host).
		//
		// Enterprise sprint — deps_ecosystems joins standard
		// because multi-language dep reachability is the
		// defining enterprise pitch; mail_server joins because
		// email infrastructure is on every Linux host and nobody
		// else scans it. service_mesh and xml_dsig stay in
		// comprehensive only — they're niche per host and cheap
		// to skip when not present.
		Modules: []string{"certificates", "keys", "packages", "libraries", "binaries", "scripts", "webapp", "configs", "containers", "certstore", "database", "deps", "web_server", "vpn", "password_hash", "deps_ecosystems", "mail_server"},
		Depth:   10,
		Workers: 8,
	},
	"comprehensive": {
		Name:        "comprehensive",
		Description: "Deep scan of entire system",
		// Sprint A1/A3/C1 — web_server, vpn, and the new
		// container_signatures supply-chain scanner extend the
		// comprehensive profile. Codesign already runs here
		// and now picks up Authenticode (.exe/.dll/.msi) and
		// JAR (.jar/.war/.ear) artifacts via the C2 extension.
		//
		// Fast Wins sprint — password_hash + auth_material
		// cover every remaining canonical auth-material surface
		// on Linux/BSD hosts.
		Modules: []string{"certificates", "keys", "packages", "libraries", "binaries", "kernel", "scripts", "webapp", "configs", "processes", "network", "protocol", "containers", "certstore", "database", "hsm", "ldap", "codesign", "deps", "web_server", "vpn", "container_signatures", "password_hash", "auth_material", "deps_ecosystems", "service_mesh", "xml_dsig", "mail_server"},
		Depth:   -1, // unlimited
		Workers: 16,
	},
}

// GetProfile returns the scan profile for the given name.
// Returns the profile and true if found, or zero value and false otherwise.
func GetProfile(name string) (ScanProfile, bool) {
	p, ok := profiles[name]
	return p, ok
}

func Load(profile string) *Config {
	p, ok := profiles[profile]
	if !ok {
		p = profiles["standard"]
	}

	workers := p.Workers
	if workers > runtime.NumCPU() {
		workers = runtime.NumCPU()
	}

	targets := defaultScanTargets(p.Depth)

	// Add process and network targets for modules that need them
	for _, mod := range p.Modules {
		switch mod {
		case "processes":
			targets = append(targets, model.ScanTarget{Type: model.TargetProcess, Value: "local"})
		case "network", "protocol":
			// Add network target only once
			hasNetwork := false
			for _, t := range targets {
				if t.Type == model.TargetNetwork {
					hasNetwork = true
					break
				}
			}
			if !hasNetwork {
				targets = append(targets, model.ScanTarget{Type: model.TargetNetwork, Value: "local"})
			}
		case "database":
			targets = append(targets, model.ScanTarget{Type: model.TargetDatabase, Value: "auto"})
		case "hsm":
			targets = append(targets, model.ScanTarget{Type: model.TargetHSM, Value: "auto"})
		case "ldap":
			// No auto-discovery for LDAP — requires explicit target via --target flag
		}
	}

	return &Config{
		Profile:         p.Name,
		Modules:         p.Modules,
		OutputFormat:    "cyclonedx",
		OutputFile:      "triton-report.json",
		MaxDepth:        p.Depth,
		FollowSymlinks:  false,
		IncludePatterns: defaultIncludePatterns(),
		ExcludePatterns: defaultExcludePatterns(),
		MaxFileSize:     100 * 1024 * 1024, // 100MB
		Workers:         workers,
		ScanTargets:     targets,
	}
}

func defaultScanTargets(depth int) []model.ScanTarget {
	var targets []model.ScanTarget

	switch runtime.GOOS {
	case "darwin":
		targets = []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: "/Applications", Depth: depth},
			{Type: model.TargetFilesystem, Value: "/System/Library", Depth: depth},
			{Type: model.TargetFilesystem, Value: "/usr/local", Depth: depth},
			{Type: model.TargetFilesystem, Value: "/etc", Depth: depth},
		}
	case "linux":
		targets = []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: "/usr", Depth: depth},
			{Type: model.TargetFilesystem, Value: "/etc", Depth: depth},
			{Type: model.TargetFilesystem, Value: "/opt", Depth: depth},
		}
	case "windows":
		targets = []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: `C:\Program Files`, Depth: depth},
			{Type: model.TargetFilesystem, Value: `C:\ProgramData`, Depth: depth},
			{Type: model.TargetFilesystem, Value: `C:\Windows\System32`, Depth: depth},
		}
	default:
		targets = []model.ScanTarget{
			{Type: model.TargetFilesystem, Value: ".", Depth: depth},
		}
	}

	return targets
}

func defaultIncludePatterns() []string {
	return []string{
		"*.pem", "*.crt", "*.cer", "*.key",
		"*.p12", "*.pfx", "*.jks",
		"*.conf", "*.config", "*.yaml", "*.yml",
		"*.json", "*.xml",
	}
}

func defaultExcludePatterns() []string {
	return []string{
		"/proc", "/sys", "/dev",
		"/tmp", "/var/tmp",
		"*.log", "*.tmp",
		".git", "node_modules", "vendor",
	}
}
