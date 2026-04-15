package scannerconfig

import (
	"fmt"
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
	Credentials     ScanCredentials
	K8sNamespace    string   // namespace filter for k8s_live; empty means all namespaces
	DNSSECZones     []string // zones to query via dig for active DNSSEC probing
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
		Modules: []string{"certificates", "keys", "packages", "libraries", "binaries", "scripts", "webapp", "configs", "containers", "certstore", "database", "deps", "web_server", "vpn", "password_hash", "deps_ecosystems", "mail_server", "dnssec", "netinfra", "messaging", "db_atrest"},
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
		//
		// Wave 0 — OCI image scanning module for pulling and
		// analyzing container images (requires explicit --image flag).
		Modules: []string{"certificates", "keys", "packages", "libraries", "binaries", "kernel", "scripts", "webapp", "configs", "processes", "network", "protocol", "containers", "certstore", "database", "hsm", "ldap", "codesign", "deps", "web_server", "vpn", "container_signatures", "password_hash", "auth_material", "deps_ecosystems", "service_mesh", "xml_dsig", "mail_server", "oci_image", "dnssec", "vpn_runtime", "netinfra", "firmware", "messaging", "db_atrest", "secrets_mgr", "supply_chain", "kerberos_runtime", "enrollment", "fido2", "blockchain", "helm_chart", "asn1_oid", "java_bytecode", "dotnet_il"},
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

// BuildOptions captures the CLI-visible inputs that drive BuildConfig.
// Keeps config construction in one place rather than scattered field
// assignments across cmd/root.go.
type BuildOptions struct {
	Profile       string
	Modules       []string // explicit --modules override; empty means "use profile"
	ImageRefs     []string
	Kubeconfig    string
	K8sContext    string
	K8sNamespace  string // namespace filter for k8s_live; empty means all namespaces
	RegistryAuth  string
	RegistryUser  string
	RegistryPass  string
	DBUrl         string
	Metrics       bool
	Incremental   bool
	OIDCEndpoints []string
	DNSSECZones   []string // zones to query via dig (active DNSSEC probing)
}

// BuildConfig is the canonical constructor for scannerconfig.Config given
// a resolved set of CLI flags. It handles target injection (filesystem
// defaults from profile, plus image/kubernetes targets from flags) and
// enforces the filesystem-default suppression rule: if any image or
// kubeconfig is supplied, the profile's filesystem defaults are NOT
// appended to ScanTargets.
func BuildConfig(opts BuildOptions) (*Config, error) {
	imageMode := len(opts.ImageRefs) > 0
	k8sMode := opts.Kubeconfig != ""

	if imageMode && k8sMode {
		return nil, fmt.Errorf(
			"cannot mix --image and --kubeconfig in a single scan; " +
				"run triton separately for each target type")
	}

	cfg := Load(opts.Profile)

	if len(opts.Modules) > 0 {
		cfg.Modules = append([]string{}, opts.Modules...)
	}
	cfg.Metrics = opts.Metrics
	cfg.Incremental = opts.Incremental
	if opts.DBUrl != "" {
		cfg.DBUrl = opts.DBUrl
	}

	cfg.Credentials = ScanCredentials{
		RegistryAuthFile: opts.RegistryAuth,
		RegistryUsername: opts.RegistryUser,
		RegistryPassword: opts.RegistryPass,
		Kubeconfig:       opts.Kubeconfig,
		K8sContext:       opts.K8sContext,
	}

	if imageMode || k8sMode {
		cfg.ScanTargets = stripFilesystemTargets(cfg.ScanTargets)

		for _, ref := range opts.ImageRefs {
			cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
				Type:  model.TargetOCIImage,
				Value: ref,
			})
		}
		if k8sMode {
			cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
				Type:  model.TargetKubernetesCluster,
				Value: opts.Kubeconfig,
			})
		}
	}

	// Ensure oci_image module is present whenever --image targets are provided.
	// Profiles other than "comprehensive" don't include oci_image by default,
	// so without this injection the image scan would be a silent no-op: the
	// engine's shouldRunModule check skips any module not listed in cfg.Modules.
	if imageMode && !containsModule(cfg.Modules, "oci_image") {
		cfg.Modules = append(cfg.Modules, "oci_image")
	}

	// Ensure k8s_live module is present whenever --kubeconfig is set.
	// No profile includes k8s_live by default (Enterprise-only, live cluster
	// access) so without this injection the k8s scan would be a silent no-op.
	if k8sMode && !containsModule(cfg.Modules, "k8s_live") {
		cfg.Modules = append(cfg.Modules, "k8s_live")
	}
	cfg.K8sNamespace = opts.K8sNamespace

	// Inject oidc_probe module and add TargetNetwork entries for each OIDC
	// endpoint supplied via --oidc-endpoint. Unlike --image, OIDC probing does
	// NOT suppress filesystem defaults: the caller still wants a full file-system
	// scan plus the additional OIDC discovery checks in the same run.
	if len(opts.OIDCEndpoints) > 0 {
		if !containsModule(cfg.Modules, "oidc_probe") {
			cfg.Modules = append(cfg.Modules, "oidc_probe")
		}
		for _, ep := range opts.OIDCEndpoints {
			cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
				Type:  model.TargetNetwork,
				Value: ep,
			})
		}
	}

	// Inject dnssec module and store zone names for active dig queries.
	// Like OIDC, this does NOT suppress filesystem defaults — both zone
	// file parsing and active dig queries run alongside the normal scan.
	if len(opts.DNSSECZones) > 0 {
		if !containsModule(cfg.Modules, "dnssec") {
			cfg.Modules = append(cfg.Modules, "dnssec")
		}
		cfg.DNSSECZones = opts.DNSSECZones
	}

	return cfg, nil
}

func stripFilesystemTargets(in []model.ScanTarget) []model.ScanTarget {
	out := make([]model.ScanTarget, 0, len(in))
	for _, t := range in {
		if t.Type != model.TargetFilesystem {
			out = append(out, t)
		}
	}
	return out
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

// containsModule reports whether name appears in the modules slice.
func containsModule(modules []string, name string) bool {
	for _, m := range modules {
		if m == name {
			return true
		}
	}
	return false
}
