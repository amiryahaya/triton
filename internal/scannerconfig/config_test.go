package scannerconfig

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestLoadQuickProfile(t *testing.T) {
	cfg := Load("quick")

	assert.Equal(t, "quick", cfg.Profile)
	assert.Equal(t, 3, cfg.MaxDepth)
	assert.Contains(t, cfg.Modules, "certificates")
	assert.Contains(t, cfg.Modules, "keys")
	assert.Contains(t, cfg.Modules, "packages")

	maxWorkers := 4
	if maxWorkers > runtime.NumCPU() {
		maxWorkers = runtime.NumCPU()
	}
	assert.Equal(t, maxWorkers, cfg.Workers)
}

func TestLoadStandardProfile(t *testing.T) {
	cfg := Load("standard")

	assert.Equal(t, "standard", cfg.Profile)
	assert.Equal(t, 10, cfg.MaxDepth)
	assert.Contains(t, cfg.Modules, "certificates")
	assert.Contains(t, cfg.Modules, "libraries")
	assert.Contains(t, cfg.Modules, "binaries")
	assert.Contains(t, cfg.Modules, "scripts")
	assert.Contains(t, cfg.Modules, "webapp")
	// Sprint A1/A3 — web_server and vpn graduate to standard.
	assert.Contains(t, cfg.Modules, "web_server")
	assert.Contains(t, cfg.Modules, "vpn")
	// Fast Wins sprint — password_hash joins standard.
	assert.Contains(t, cfg.Modules, "password_hash")
	// Enterprise sprint — deps_ecosystems + mail_server join standard.
	assert.Contains(t, cfg.Modules, "deps_ecosystems")
	assert.Contains(t, cfg.Modules, "mail_server")
}

func TestLoadComprehensiveProfile(t *testing.T) {
	cfg := Load("comprehensive")

	assert.Equal(t, "comprehensive", cfg.Profile)
	assert.Equal(t, -1, cfg.MaxDepth)
	assert.LessOrEqual(t, cfg.Workers, runtime.NumCPU())
	assert.Contains(t, cfg.Modules, "kernel")
	assert.Contains(t, cfg.Modules, "binaries")
	assert.Contains(t, cfg.Modules, "scripts")
	assert.Contains(t, cfg.Modules, "webapp")
	assert.Contains(t, cfg.Modules, "processes")
	assert.Contains(t, cfg.Modules, "network")
	assert.Contains(t, cfg.Modules, "protocol")
	// Sprint A1/A3/C1 — coverage + supply chain additions.
	assert.Contains(t, cfg.Modules, "web_server")
	assert.Contains(t, cfg.Modules, "vpn")
	assert.Contains(t, cfg.Modules, "container_signatures")
	// Fast Wins sprint — password_hash + auth_material.
	assert.Contains(t, cfg.Modules, "password_hash")
	assert.Contains(t, cfg.Modules, "auth_material")
	// Enterprise sprint — deps_ecosystems + service_mesh + xml_dsig + mail_server.
	assert.Contains(t, cfg.Modules, "deps_ecosystems")
	assert.Contains(t, cfg.Modules, "service_mesh")
	assert.Contains(t, cfg.Modules, "xml_dsig")
	assert.Contains(t, cfg.Modules, "mail_server")

	// Should have process and network targets
	hasProcess := false
	hasNetwork := false
	for _, t := range cfg.ScanTargets {
		if t.Type == model.TargetProcess {
			hasProcess = true
		}
		if t.Type == model.TargetNetwork {
			hasNetwork = true
		}
	}
	assert.True(t, hasProcess, "comprehensive profile should include process targets")
	assert.True(t, hasNetwork, "comprehensive profile should include network targets")
}

func TestLoadUnknownProfileFallback(t *testing.T) {
	cfg := Load("nonexistent")

	assert.Equal(t, "standard", cfg.Profile)
	assert.Equal(t, 10, cfg.MaxDepth)
}

func TestWorkersCappedByCPU(t *testing.T) {
	cfg := Load("comprehensive")
	assert.LessOrEqual(t, cfg.Workers, runtime.NumCPU())
}

func TestDefaultScanTargets(t *testing.T) {
	cfg := Load("quick")

	require.NotEmpty(t, cfg.ScanTargets)

	// All targets should be filesystem type
	for _, target := range cfg.ScanTargets {
		assert.Equal(t, model.TargetFilesystem, target.Type)
		assert.NotEmpty(t, target.Value)
	}
}

func TestDefaultExcludePatterns(t *testing.T) {
	patterns := defaultExcludePatterns()

	assert.Contains(t, patterns, "/proc")
	assert.Contains(t, patterns, "/sys")
	assert.Contains(t, patterns, ".git")
	assert.Contains(t, patterns, "node_modules")
}

func TestDefaultIncludePatterns(t *testing.T) {
	patterns := defaultIncludePatterns()

	assert.Contains(t, patterns, "*.pem")
	assert.Contains(t, patterns, "*.crt")
	assert.Contains(t, patterns, "*.key")
	assert.Contains(t, patterns, "*.cer")
}

func TestConfig_HasCredentialsField(t *testing.T) {
	cfg := &Config{}
	cfg.Credentials.RegistryUsername = "alice"
	assert.Equal(t, "alice", cfg.Credentials.RegistryUsername)
}

func TestBuildConfig_ImageSuppressesFilesystemDefaults(t *testing.T) {
	opts := BuildOptions{
		Profile:   "standard",
		ImageRefs: []string{"nginx:1.25"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	var fsCount, imageCount int
	for _, tgt := range cfg.ScanTargets {
		switch tgt.Type {
		case model.TargetFilesystem:
			fsCount++
		case model.TargetOCIImage:
			imageCount++
		}
	}
	assert.Equal(t, 0, fsCount, "filesystem defaults must be suppressed")
	assert.Equal(t, 1, imageCount)

	var imgTarget model.ScanTarget
	for _, t := range cfg.ScanTargets {
		if t.Type == model.TargetOCIImage {
			imgTarget = t
			break
		}
	}
	assert.Equal(t, "nginx:1.25", imgTarget.Value)
}

func TestBuildConfig_MultipleImages(t *testing.T) {
	opts := BuildOptions{
		Profile:   "standard",
		ImageRefs: []string{"nginx:1.25", "redis:7"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	var refs []string
	for _, tgt := range cfg.ScanTargets {
		if tgt.Type == model.TargetOCIImage {
			refs = append(refs, tgt.Value)
		}
	}
	assert.ElementsMatch(t, []string{"nginx:1.25", "redis:7"}, refs)
}

func TestBuildConfig_KubeconfigSuppressesFilesystemDefaults(t *testing.T) {
	opts := BuildOptions{
		Profile:    "standard",
		Kubeconfig: "/home/alice/.kube/config",
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	var fsCount, k8sCount int
	for _, tgt := range cfg.ScanTargets {
		switch tgt.Type {
		case model.TargetFilesystem:
			fsCount++
		case model.TargetKubernetesCluster:
			k8sCount++
		}
	}
	assert.Equal(t, 0, fsCount)
	assert.Equal(t, 1, k8sCount)
}

func TestBuildConfig_NoImageOrKubeconfigKeepsFilesystemDefaults(t *testing.T) {
	opts := BuildOptions{Profile: "standard"}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	var fsCount int
	for _, tgt := range cfg.ScanTargets {
		if tgt.Type == model.TargetFilesystem {
			fsCount++
		}
	}
	assert.Greater(t, fsCount, 0, "filesystem defaults should be present")
}

func TestBuildConfig_ImageAndKubeconfigError(t *testing.T) {
	opts := BuildOptions{
		Profile:    "standard",
		ImageRefs:  []string{"nginx:1.25"},
		Kubeconfig: "/home/alice/.kube/config",
	}
	_, err := BuildConfig(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot mix")
}

func TestBuildConfig_ImageInjectsOCIImageModule(t *testing.T) {
	// standard profile does not include oci_image; the module must be
	// injected automatically whenever --image is set so the scan is not
	// a silent no-op.
	opts := BuildOptions{
		Profile:   "standard",
		ImageRefs: []string{"nginx:1.25"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	var hasOCI bool
	for _, mod := range cfg.Modules {
		if mod == "oci_image" {
			hasOCI = true
			break
		}
	}
	assert.True(t, hasOCI, "oci_image must be injected into Modules when --image is set")
}

func TestBuildConfig_ImageInjectsOCIImageModule_ComprehensiveNoDuplicate(t *testing.T) {
	// comprehensive already lists oci_image; injection must not duplicate it.
	opts := BuildOptions{
		Profile:   "comprehensive",
		ImageRefs: []string{"alpine:3.19"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	count := 0
	for _, mod := range cfg.Modules {
		if mod == "oci_image" {
			count++
		}
	}
	assert.Equal(t, 1, count, "oci_image must appear exactly once even for comprehensive profile")
}

func TestBuildConfig_NoImageDoesNotInjectOCIImageModule(t *testing.T) {
	// Without --image, oci_image must not be injected into non-comprehensive profiles.
	opts := BuildOptions{Profile: "standard"}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	for _, mod := range cfg.Modules {
		assert.NotEqual(t, "oci_image", mod, "oci_image must not be present without --image flag")
	}
}

func TestBuildConfig_OIDCEndpointInjectsModule(t *testing.T) {
	opts := BuildOptions{
		Profile:       "standard",
		OIDCEndpoints: []string{"https://auth.example.com"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)
	assert.Contains(t, cfg.Modules, "oidc_probe")
}

func TestBuildConfig_OIDCEndpointAddsTarget(t *testing.T) {
	opts := BuildOptions{
		Profile:       "standard",
		OIDCEndpoints: []string{"https://auth.example.com"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	var found bool
	for _, tgt := range cfg.ScanTargets {
		if tgt.Type == model.TargetNetwork && tgt.Value == "https://auth.example.com" {
			found = true
		}
	}
	assert.True(t, found, "OIDC endpoint must appear as TargetNetwork")
}

func TestBuildConfig_OIDCDoesNotSuppressFilesystem(t *testing.T) {
	opts := BuildOptions{
		Profile:       "standard",
		OIDCEndpoints: []string{"https://auth.example.com"},
	}
	cfg, err := BuildConfig(opts)
	require.NoError(t, err)

	var fsCount int
	for _, tgt := range cfg.ScanTargets {
		if tgt.Type == model.TargetFilesystem {
			fsCount++
		}
	}
	assert.Greater(t, fsCount, 0, "filesystem defaults must be preserved with --oidc-endpoint")
}
