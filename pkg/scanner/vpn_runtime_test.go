package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

// --- ipsec statusall parser tests ---

func TestParseIPsecStatusAll_StrongIKEv2(t *testing.T) {
	// Real-world `ipsec statusall` output from strongSwan with modern crypto.
	output := `Status of IKE charon daemon (strongSwan 5.9.11, Linux 6.1.0):
  uptime: 3 days, since Apr 09 12:30:00 2026
  worker threads: 8 idle of 16, job queue load: 0/0/0/0

Listening IP addresses:
  10.0.0.1
  192.168.1.1

Connections:
  site-to-site:  10.0.0.1...10.0.0.2  IKEv2
    local:  [10.0.0.1] uses pre-shared key authentication
    remote: [10.0.0.2] uses pre-shared key authentication
    child:  10.0.0.0/24 === 10.0.1.0/24 TUNNEL
Security Associations (1 up, 0 connecting):
  site-to-site[1]: ESTABLISHED 3 days ago, 10.0.0.1[10.0.0.1]...10.0.0.2[10.0.0.2]
  site-to-site[1]: IKEv2 SPIs: abc123def456_i abc789def012_r*, rekeying in 2 hours
  site-to-site[1]: IKE proposal: AES_CBC_256/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_384
  site-to-site{1}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c12345_i c67890_o
  site-to-site{1}:  AES_GCM_16_256/NO_EXT_SEQ, 4096 bytes_i, 2048 bytes_o, rekeying in 45 minutes
  site-to-site{1}:   10.0.0.0/24 === 10.0.1.0/24
`
	m := &VPNRuntimeModule{}
	findings := m.parseIPsecStatusAll([]byte(output))
	require.NotEmpty(t, findings)

	// Should find IKE proposal algorithms: AES_CBC_256, HMAC_SHA2_384, PRF_HMAC_SHA2_384, ECP_384
	// And ESP transform: AES_GCM_16_256
	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["AES-256"], "should find AES-256 from AES_CBC_256")
	assert.True(t, algoSet["SHA-384"], "should find SHA-384 from HMAC_SHA2_384")
	assert.True(t, algoSet["AES-256-GCM"], "should find AES-256-GCM from AES_GCM_16_256")

	// Check finding metadata
	for _, f := range findings {
		assert.Equal(t, "vpn_runtime", f.Module)
		assert.Equal(t, "process", f.Source.Type)
		assert.Equal(t, "ipsec-statusall", f.Source.DetectionMethod)
		assert.Equal(t, CategoryRuntime, f.Category)
	}
}

func TestParseIPsecStatusAll_WeakCrypto(t *testing.T) {
	output := `Security Associations (1 up, 0 connecting):
  legacy[1]: ESTABLISHED 1 hour ago, 10.0.0.1[10.0.0.1]...10.0.0.2[10.0.0.2]
  legacy[1]: IKE proposal: 3DES_CBC/HMAC_MD5_96/PRF_HMAC_MD5/MODP_1024
  legacy{1}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c12345_i c67890_o
  legacy{1}:  3DES_CBC/HMAC_SHA1_96/NO_EXT_SEQ, 1024 bytes_i, 512 bytes_o
`
	m := &VPNRuntimeModule{}
	findings := m.parseIPsecStatusAll([]byte(output))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["3DES"], "should find 3DES")
	assert.True(t, algoSet["MD5"], "should find MD5")
	assert.True(t, algoSet["SHA-1"], "should find SHA-1 from HMAC_SHA1")
	assert.True(t, algoSet["DH"], "should find DH from MODP_1024")
}

func TestParseIPsecStatusAll_NoSAs(t *testing.T) {
	output := `Status of IKE charon daemon (strongSwan 5.9.11):
Security Associations (0 up, 0 connecting):
`
	m := &VPNRuntimeModule{}
	findings := m.parseIPsecStatusAll([]byte(output))
	assert.Empty(t, findings)
}

func TestParseIPsecStatusAll_MultipleTunnels(t *testing.T) {
	output := `Security Associations (2 up, 0 connecting):
  tunnel-a[1]: ESTABLISHED 1 day ago, 10.0.0.1...10.0.0.2
  tunnel-a[1]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  tunnel-a{1}:  AES_CBC_128/HMAC_SHA1_96/NO_EXT_SEQ
  tunnel-b[2]: ESTABLISHED 2 hours ago, 10.0.0.1...10.0.0.3
  tunnel-b[2]: IKE proposal: AES_CBC_128/HMAC_SHA2_512_256/PRF_HMAC_SHA2_512/ECP_521
  tunnel-b{2}:  AES_GCM_16_128/NO_EXT_SEQ
`
	m := &VPNRuntimeModule{}
	findings := m.parseIPsecStatusAll([]byte(output))
	// Should have findings from both tunnels
	require.True(t, len(findings) >= 4, "expected findings from both tunnels, got %d", len(findings))
}

// --- wg show parser tests ---

func TestParseWgShow(t *testing.T) {
	// `wg show` output format
	output := `interface: wg0
  public key: gN65BkIKy1eCE9pP1wdc8ROUgdDyb=
  private key: (hidden)
  listening port: 51820

peer: aF76CmJLz2fDF0qQ2xed9SPVheFye=
  endpoint: 203.0.113.1:51820
  allowed ips: 10.0.0.0/24
  latest handshake: 42 seconds ago
  transfer: 92.01 MiB received, 12.34 MiB sent

peer: bG87DnKMa3gEG1rR3yfe0TQWifGzf=
  endpoint: 198.51.100.1:51820
  allowed ips: 10.0.1.0/24
  latest handshake: 3 minutes, 15 seconds ago
  transfer: 1.23 GiB received, 456.78 MiB sent
`
	m := &VPNRuntimeModule{}
	findings := m.parseWgShow([]byte(output))
	require.NotEmpty(t, findings)

	// WireGuard has a fixed crypto suite — should see:
	// X25519 (key exchange), ChaCha20-Poly1305 (AEAD), Blake2s (hash)
	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["X25519"])
	assert.True(t, algoSet["ChaCha20-Poly1305"])
	assert.True(t, algoSet["Blake2s"])

	// Should report per-interface (wg0)
	for _, f := range findings {
		assert.Contains(t, f.CryptoAsset.Purpose, "wg0")
		assert.Equal(t, "process", f.Source.Type)
		assert.Equal(t, "wg-show", f.Source.DetectionMethod)
	}
}

func TestParseWgShow_MultipleInterfaces(t *testing.T) {
	output := `interface: wg0
  public key: abc123=
  private key: (hidden)
  listening port: 51820

interface: wg1
  public key: def456=
  private key: (hidden)
  listening port: 51821

peer: xyz789=
  endpoint: 10.0.0.1:51821
  latest handshake: 5 seconds ago
  transfer: 1.00 MiB received, 2.00 MiB sent
`
	m := &VPNRuntimeModule{}
	findings := m.parseWgShow([]byte(output))
	require.NotEmpty(t, findings)

	// Should have findings for both wg0 and wg1
	hasWg0 := false
	hasWg1 := false
	for _, f := range findings {
		if strings.Contains(f.CryptoAsset.Purpose, "wg0") {
			hasWg0 = true
		}
		if strings.Contains(f.CryptoAsset.Purpose, "wg1") {
			hasWg1 = true
		}
	}
	assert.True(t, hasWg0, "should have wg0 findings")
	assert.True(t, hasWg1, "should have wg1 findings")
}

func TestParseWgShow_Empty(t *testing.T) {
	m := &VPNRuntimeModule{}
	findings := m.parseWgShow([]byte(""))
	assert.Empty(t, findings)
}

func TestParseWgShow_NoHandshake(t *testing.T) {
	// Interface configured but no active peers
	output := `interface: wg0
  public key: abc123=
  private key: (hidden)
  listening port: 51820
`
	m := &VPNRuntimeModule{}
	findings := m.parseWgShow([]byte(output))
	// Should still report the interface's fixed suite
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.Contains(t, f.CryptoAsset.Purpose, "wg0")
	}
}

// --- openvpn status parser tests ---

func TestParseOpenVPNStatus(t *testing.T) {
	// OpenVPN status file (--status or management interface output)
	output := `OpenVPN CLIENT LIST
Updated,2026-04-12 10:30:00
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
client1,203.0.113.5:54321,1234567,7654321,2026-04-12 09:00:00
client2,198.51.100.10:12345,9876543,3456789,2026-04-12 08:00:00
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.2,client1,203.0.113.5:54321,2026-04-12 10:29:55
10.8.0.3,client2,198.51.100.10:12345,2026-04-12 10:29:50
GLOBAL STATS
Max bcast/mcast queue length,5
END
`
	m := &VPNRuntimeModule{}
	findings := m.parseOpenVPNStatus([]byte(output))
	// OpenVPN status doesn't expose cipher — just reports active tunnel presence
	require.NotEmpty(t, findings)
	assert.Equal(t, "OpenVPN active tunnel", findings[0].CryptoAsset.Function)
	assert.Equal(t, "process", findings[0].Source.Type)
	assert.Equal(t, "openvpn-status", findings[0].Source.DetectionMethod)
}

func TestParseOpenVPNStatus_Empty(t *testing.T) {
	output := `OpenVPN CLIENT LIST
Updated,2026-04-12 10:30:00
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
GLOBAL STATS
Max bcast/mcast queue length,0
END
`
	m := &VPNRuntimeModule{}
	findings := m.parseOpenVPNStatus([]byte(output))
	assert.Empty(t, findings, "no clients = no findings")
}

// --- module interface tests ---

func TestVPNRuntimeModuleInterface(t *testing.T) {
	m := NewVPNRuntimeModule(nil)
	assert.Equal(t, "vpn_runtime", m.Name())
	assert.Equal(t, model.CategoryActiveRuntime, m.Category())
	assert.Equal(t, model.TargetProcess, m.ScanTargetType())
	var _ Module = m
}

// --- command runner mock tests ---

func TestVPNRuntimeScan_MockCommands(t *testing.T) {
	origCmd := vpnRuntimeCmdRunner
	origRead := vpnRuntimeReadFile
	defer func() {
		vpnRuntimeCmdRunner = origCmd
		vpnRuntimeReadFile = origRead
	}()

	vpnRuntimeCmdRunner = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		switch name {
		case "ipsec":
			return []byte(`Security Associations (1 up, 0 connecting):
  test[1]: ESTABLISHED 1 hour ago, 10.0.0.1...10.0.0.2
  test[1]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  test{1}:  AES_GCM_16_256/NO_EXT_SEQ
`), nil
		case "wg":
			return []byte(`interface: wg0
  public key: abc=
  private key: (hidden)
  listening port: 51820
`), nil
		default:
			return nil, fmt.Errorf("unknown command: %s", name)
		}
	}

	vpnRuntimeReadFile = func(_ string) ([]byte, error) {
		return nil, fmt.Errorf("no status file")
	}

	m := NewVPNRuntimeModule(nil)
	findings := make(chan *model.Finding, 100)
	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetProcess, Value: "local"}, findings)
	close(findings)
	require.NoError(t, err)

	var all []*model.Finding
	for f := range findings {
		all = append(all, f)
	}
	// Should have findings from ipsec + wg (openvpn status file absent)
	require.True(t, len(all) >= 2, "expected findings from ipsec and wg, got %d", len(all))
}

func TestVPNRuntimeScan_AllCommandsFail(t *testing.T) {
	origCmd := vpnRuntimeCmdRunner
	origRead := vpnRuntimeReadFile
	defer func() {
		vpnRuntimeCmdRunner = origCmd
		vpnRuntimeReadFile = origRead
	}()

	vpnRuntimeCmdRunner = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, fmt.Errorf("command not found")
	}
	vpnRuntimeReadFile = func(_ string) ([]byte, error) {
		return nil, fmt.Errorf("not found")
	}

	m := NewVPNRuntimeModule(nil)
	findings := make(chan *model.Finding, 100)
	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetProcess, Value: "local"}, findings)
	close(findings)
	require.NoError(t, err, "all commands failing should not be an error")

	var all []*model.Finding
	for f := range findings {
		all = append(all, f)
	}
	assert.Empty(t, all, "no working VPN daemons = no findings")
}

// --- BuildConfig injection test ---

func TestBuildConfig_VPNRuntimeInComprehensive(t *testing.T) {
	cfg, err := scannerconfig.BuildConfig(scannerconfig.BuildOptions{
		Profile: "comprehensive",
	})
	require.NoError(t, err)
	assert.Contains(t, cfg.Modules, "vpn_runtime")
}
