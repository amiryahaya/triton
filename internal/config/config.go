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
}

type ScanProfile struct {
	Name        string
	Description string
	Modules     []string
	Depth       int
	Workers     int
}

var Profiles = map[string]ScanProfile{
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
		Modules:     []string{"certificates", "keys", "packages", "libraries", "binaries", "scripts", "webapp"},
		Depth:       10,
		Workers:     8,
	},
	"comprehensive": {
		Name:        "comprehensive",
		Description: "Deep scan of entire system",
		Modules:     []string{"certificates", "keys", "packages", "libraries", "binaries", "kernel", "scripts", "webapp", "processes", "network", "protocol"},
		Depth:       -1, // unlimited
		Workers:     16,
	},
}

func Load(profile string) *Config {
	p, ok := Profiles[profile]
	if !ok {
		p = Profiles["standard"]
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
