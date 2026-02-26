package report

import (
	"strings"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupFindingsIntoSystems(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 5, Module: "certificates",
			Source:      model.FindingSource{Type: "file", Path: "/etc/ssl/certs/server.pem"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "RSA-2048", Function: "TLS certificate", KeySize: 2048},
		},
		{
			ID: "f2", Category: 3, Module: "libraries",
			Source:      model.FindingSource{Type: "file", Path: "/usr/lib/libcrypto.so.3"},
			CryptoAsset: &model.CryptoAsset{ID: "c2", Algorithm: "OpenSSL", Function: "Crypto library"},
		},
		{
			ID: "f3", Category: 9, Module: "protocol",
			Source:      model.FindingSource{Type: "network", Endpoint: "192.168.1.1:443"},
			CryptoAsset: &model.CryptoAsset{ID: "c3", Algorithm: "AES-256-GCM", Function: "TLS cipher suite", KeySize: 256},
		},
		{
			ID: "f4", Category: 9, Module: "protocol",
			Source:      model.FindingSource{Type: "network", Endpoint: "192.168.1.1:443"},
			CryptoAsset: &model.CryptoAsset{ID: "c4", Algorithm: "ECDSA-P256", Function: "TLS server certificate", KeySize: 256},
		},
		{
			ID: "f5", Category: 1, Module: "processes",
			Source:      model.FindingSource{Type: "process", PID: 1234, Path: "/usr/sbin/sshd"},
			CryptoAsset: &model.CryptoAsset{ID: "c5", Algorithm: "SSH", Function: "SSH server authentication"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.NotEmpty(t, systems)

	// Network findings for the same endpoint should be in one system
	var networkSys *model.System
	for i := range systems {
		if strings.Contains(systems[i].Name, "192.168.1.1") {
			networkSys = &systems[i]
			break
		}
	}
	require.NotNil(t, networkSys, "expected a system for network endpoint 192.168.1.1")
	assert.True(t, len(networkSys.CryptoAssets) >= 2)

	// Each system should have an ID and name
	for _, sys := range systems {
		assert.NotEmpty(t, sys.ID)
		assert.NotEmpty(t, sys.Name)
	}
}

func TestGroupFindingsEmpty(t *testing.T) {
	systems := GroupFindingsIntoSystems(nil)
	assert.Empty(t, systems)
}

func TestGroupFindingsNetworkEndpoint(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 9, Module: "protocol",
			Source:      model.FindingSource{Type: "network", Endpoint: "10.0.0.1:443"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "AES-256-GCM", Function: "TLS cipher suite"},
		},
		{
			ID: "f2", Category: 9, Module: "protocol",
			Source:      model.FindingSource{Type: "network", Endpoint: "10.0.0.1:443"},
			CryptoAsset: &model.CryptoAsset{ID: "c2", Algorithm: "RSA-4096", Function: "TLS server certificate"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	// Same endpoint → same system
	require.Len(t, systems, 1)
	assert.Len(t, systems[0].CryptoAssets, 2)
}

func TestGroupFindingsProcessGrouping(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 1, Module: "processes",
			Source:      model.FindingSource{Type: "process", PID: 100, Path: "/usr/sbin/sshd"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "SSH"},
		},
		{
			ID: "f2", Category: 1, Module: "processes",
			Source:      model.FindingSource{Type: "process", PID: 200, Path: "/usr/sbin/sshd"},
			CryptoAsset: &model.CryptoAsset{ID: "c2", Algorithm: "SSH"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	// Same process name → same system
	require.Len(t, systems, 1)
	assert.Contains(t, systems[0].Name, "sshd")
}

func TestGroupFindingsFileGrouping(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 5, Module: "certificates",
			Source:      model.FindingSource{Type: "file", Path: "/etc/ssl/certs/server.pem"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "RSA-2048"},
		},
		{
			ID: "f2", Category: 5, Module: "certificates",
			Source:      model.FindingSource{Type: "file", Path: "/etc/ssl/certs/ca.pem"},
			CryptoAsset: &model.CryptoAsset{ID: "c2", Algorithm: "RSA-4096"},
		},
		{
			ID: "f3", Category: 6, Module: "scripts",
			Source:      model.FindingSource{Type: "file", Path: "/opt/myapp/deploy.sh"},
			CryptoAsset: &model.CryptoAsset{ID: "c3", Algorithm: "AES-256-CBC"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	// /etc/ssl/certs → one system, /opt/myapp → another
	require.True(t, len(systems) >= 2)
}

func TestCBOMRefsNumbering(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 5, Module: "certificates",
			Source:      model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "RSA-2048"},
		},
		{
			ID: "f2", Category: 5, Module: "certificates",
			Source:      model.FindingSource{Type: "file", Path: "/etc/ssl/key.pem"},
			CryptoAsset: &model.CryptoAsset{ID: "c2", Algorithm: "RSA-2048"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.NotEmpty(t, systems)

	// Verify CBOM refs are assigned (range format for multiple assets)
	for _, sys := range systems {
		require.NotEmpty(t, sys.CBOMRefs)
		for _, ref := range sys.CBOMRefs {
			assert.Contains(t, ref, "CBOM #")
		}
	}
	// Both findings are in /etc/ssl → one system with range "CBOM #1 - CBOM #2"
	require.Len(t, systems, 1)
	assert.Equal(t, "CBOM #1 - CBOM #2", systems[0].CBOMRefs[0])
}

func TestSystemFieldsPopulated(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 9, Module: "protocol",
			Source:      model.FindingSource{Type: "network", Endpoint: "192.168.1.1:443"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "AES-256-GCM", Function: "TLS cipher suite", Library: "TLS 1.3"},
			Timestamp:   time.Now(),
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.Len(t, systems, 1)

	sys := systems[0]
	assert.NotEmpty(t, sys.ID)
	assert.NotEmpty(t, sys.Name)
	assert.True(t, sys.InUse)
	assert.NotEmpty(t, sys.CriticalityLevel)
}

func TestDeriveAppFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		// macOS
		{"macOS app bundle", "/Applications/Rider.app/Contents/lib/libcrypto.dylib", "Rider"},
		{"macOS app with spaces", "/Applications/pgAdmin 4.app/Contents/Resources/cert.pem", "pgAdmin 4"},
		{"nested macOS app", "/Applications/Adobe Acrobat DC/Adobe Acrobat.app/Contents/Resources/cert.pem", "Adobe Acrobat"},
		{"macOS framework", "/System/Library/Frameworks/Security.framework/Versions/A/Security", "Security"},
		{"nested framework in app", "/Applications/Rider.app/Contents/Frameworks/Mono.framework/Versions/6.12/lib", "Rider"},
		{"standalone framework", "/Library/Frameworks/Mono.framework/Versions/6.12/lib/cert.pem", "Mono"},

		// Homebrew (macOS + Linux)
		{"homebrew cellar", "/usr/local/Cellar/openssl@3/3.1.0/lib/libcrypto.dylib", "openssl@3"},
		{"homebrew cellar linux", "/home/linuxbrew/.linuxbrew/Cellar/curl/8.4.0/lib/cert.pem", "curl"},
		{"homebrew opt", "/usr/local/opt/python@3.11/lib/libssl.dylib", "python@3.11"},

		// Windows
		{"windows program files", `C:\Program Files\OpenSSL-Win64\bin\libcrypto.dll`, "OpenSSL-Win64"},
		{"windows program files x86", `C:\Program Files (x86)\PuTTY\putty.exe`, "PuTTY"},
		{"windows vendor app", `C:\Program Files\Apache Software Foundation\Tomcat 9.0\lib\cert.pem`, "Apache Software Foundation Tomcat 9.0"},
		{"windows programdata", `C:\ProgramData\MySQL\certs\server-cert.pem`, "MySQL"},
		{"windows case insensitive", `c:\program files\Git\usr\ssl\cert.pem`, "Git"},

		// Linux
		{"linux dpkg doc", "/usr/share/doc/libssl3/copyright", "libssl3"},
		{"linux snap", "/snap/firefox/3416/usr/lib/firefox/cert9.db", "firefox"},
		{"linux flatpak", "/var/lib/flatpak/app/org.mozilla.firefox/current/cert.pem", "org.mozilla.firefox"},
		{"linux opt package", "/opt/google/chrome/cert.pem", "google"},
		{"linux usr lib package", "/usr/lib/openssh/ssh-keygen", "openssh"},
		{"linux usr lib arch triplet", "/usr/lib/x86_64-linux-gnu/openssl/engines/libcrypto.so", "openssl"},
		{"linux usr lib64", "/usr/lib64/nss/libnss3.so", "nss"},

		// No match
		{"plain system path", "/etc/ssl/certs/ca-certificates.crt", ""},
		{"empty path", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveAppFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExternalAPIsPopulatedForFiles(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 5, Module: "certificates",
			Source:      model.FindingSource{Type: "file", Path: "/Applications/Rider.app/Contents/lib/cert.pem"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "RSA-2048"},
		},
		{
			ID: "f2", Category: 5, Module: "certificates",
			Source:      model.FindingSource{Type: "file", Path: "/Applications/Rider.app/Contents/lib/key.pem"},
			CryptoAsset: &model.CryptoAsset{ID: "c2", Algorithm: "RSA-4096"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.Len(t, systems, 1)
	assert.Contains(t, systems[0].ExternalAPIs, "Rider")
}

func TestExternalAPIsPopulatedForNetwork(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 8, Module: "network",
			Source:      model.FindingSource{Type: "network", Path: "httpd", Endpoint: ":443/tcp"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "TLS", Function: "HTTPS server"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.Len(t, systems, 1)
	assert.Contains(t, systems[0].ExternalAPIs, "httpd")
}

func TestExternalAPIsPopulatedForProcess(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 1, Module: "processes",
			Source:      model.FindingSource{Type: "process", PID: 100, Path: "/usr/sbin/sshd -D"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "SSH"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.Len(t, systems, 1)
	assert.Contains(t, systems[0].ExternalAPIs, "sshd")
}

func TestExternalAPIsNAForUnknownPaths(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 5, Module: "certificates",
			Source:      model.FindingSource{Type: "file", Path: "/etc/ssl/certs/ca.pem"},
			CryptoAsset: &model.CryptoAsset{ID: "c1", Algorithm: "RSA-2048"},
		},
	}

	systems := GroupFindingsIntoSystems(findings)
	require.Len(t, systems, 1)
	assert.Equal(t, []string{"N/A"}, systems[0].ExternalAPIs)
}

func TestGroupFindingsNilCryptoAsset(t *testing.T) {
	findings := []model.Finding{
		{
			ID: "f1", Category: 5, Module: "certificates",
			Source:      model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
			CryptoAsset: nil, // No crypto asset
		},
	}

	// Should not panic and should skip findings with nil crypto assets
	systems := GroupFindingsIntoSystems(findings)
	assert.Empty(t, systems)
}
