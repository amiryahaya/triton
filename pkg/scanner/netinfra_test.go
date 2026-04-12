package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- file matcher tests ---

func TestIsNetInfraConfigFile(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		// SNMPv3
		{"/etc/snmp/snmpd.conf", true},
		{"/etc/snmp/snmptrapd.conf", true},

		// BGP — bird, FRR, Quagga
		{"/etc/bird/bird.conf", true},
		{"/etc/bird.conf", true},
		{"/etc/frr/frr.conf", true},
		{"/etc/frr/bgpd.conf", true},
		{"/etc/quagga/bgpd.conf", true},

		// RPKI — parser deferred, matcher removed until it exists
		{"/etc/routinator/routinator.conf", false},
		{"/etc/rpki-client.conf", false},

		// 802.1X / RADIUS
		{"/etc/raddb/clients.conf", true},
		{"/etc/freeradius/clients.conf", true},
		{"/etc/raddb/mods-enabled/eap", true},
		{"/etc/freeradius/3.0/mods-enabled/eap", true},

		// NTS — chrony, ntp
		{"/etc/chrony/chrony.conf", true},
		{"/etc/chrony.conf", true},
		{"/etc/ntp.conf", true},
		{"/etc/ntpsec/ntp.conf", true},

		// syslog-TLS
		{"/etc/rsyslog.conf", true},
		{"/etc/rsyslog.d/remote.conf", true},
		{"/etc/syslog-ng/syslog-ng.conf", true},

		// Not net infra
		{"/etc/nginx/nginx.conf", false},
		{"/home/user/random.conf", false},
		{"/etc/ssh/sshd_config", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isNetInfraConfigFile(tc.path), "path: %s", tc.path)
		})
	}
}

// --- SNMPv3 parser tests ---

func TestParseSNMPv3_AuthPriv(t *testing.T) {
	conf := `# SNMPv3 user with authPriv
createUser myuser SHA AES
rouser myuser authpriv
`
	m := &NetInfraModule{}
	findings := m.parseSNMPConfig("/etc/snmp/snmpd.conf", []byte(conf))
	require.NotEmpty(t, findings)

	algoSet := algoSetFrom(findings)
	assert.True(t, algoSet["SHA-1"], "SHA auth should be found")
	assert.True(t, algoSet["AES-128"], "AES priv should be found")
}

func TestParseSNMPv3_SHA256AES256(t *testing.T) {
	conf := `createUser stronguser SHA-256 AES-256
`
	m := &NetInfraModule{}
	findings := m.parseSNMPConfig("/etc/snmp/snmpd.conf", []byte(conf))
	require.NotEmpty(t, findings)

	algoSet := algoSetFrom(findings)
	assert.True(t, algoSet["SHA-256"])
	assert.True(t, algoSet["AES-256"])
}

func TestParseSNMPv3_MD5DES(t *testing.T) {
	conf := `createUser weakuser MD5 DES
`
	m := &NetInfraModule{}
	findings := m.parseSNMPConfig("/etc/snmp/snmpd.conf", []byte(conf))
	require.NotEmpty(t, findings)

	algoSet := algoSetFrom(findings)
	assert.True(t, algoSet["MD5"])
	assert.True(t, algoSet["DES"])
}

// --- BGP parser tests ---

func TestParseBGP_FRRPassword(t *testing.T) {
	conf := `router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.2 password MySecret123
`
	m := &NetInfraModule{}
	findings := m.parseBGPConfig("/etc/frr/frr.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "MD5", findings[0].CryptoAsset.Algorithm, "BGP TCP-MD5 auth")
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "BGP neighbor")
}

func TestParseBGP_BirdPassword(t *testing.T) {
	conf := `protocol bgp upstream {
  local as 65001;
  neighbor 10.0.0.2 as 65002;
  password "secret";
}
`
	m := &NetInfraModule{}
	findings := m.parseBGPConfig("/etc/bird/bird.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "MD5", findings[0].CryptoAsset.Algorithm)
}

func TestParseBGP_NoAuth(t *testing.T) {
	conf := `router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
`
	m := &NetInfraModule{}
	findings := m.parseBGPConfig("/etc/frr/frr.conf", []byte(conf))
	assert.Empty(t, findings, "no password = no finding")
}

// --- NTS parser tests ---

func TestParseChrony_NTSEnabled(t *testing.T) {
	conf := `# chrony config with NTS
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
pool pool.ntp.org iburst
`
	m := &NetInfraModule{}
	findings := m.parseNTSConfig("/etc/chrony/chrony.conf", []byte(conf))
	require.NotEmpty(t, findings)

	ntsCount := 0
	for _, f := range findings {
		if f.CryptoAsset.Function == "NTS-secured time source" {
			ntsCount++
		}
	}
	assert.Equal(t, 2, ntsCount, "two NTS servers")
}

func TestParseChrony_NoNTS(t *testing.T) {
	conf := `server pool.ntp.org iburst
`
	m := &NetInfraModule{}
	findings := m.parseNTSConfig("/etc/chrony.conf", []byte(conf))
	assert.Empty(t, findings)
}

func TestParseNTPSec_NTS(t *testing.T) {
	conf := `server time.cloudflare.com nts
`
	m := &NetInfraModule{}
	findings := m.parseNTSConfig("/etc/ntp.conf", []byte(conf))
	require.NotEmpty(t, findings)
}

// --- syslog-TLS parser tests ---

func TestParseRsyslog_TLS(t *testing.T) {
	conf := `# rsyslog TLS configuration
$DefaultNetstreamDriverCAFile /etc/pki/tls/certs/ca-bundle.crt
$DefaultNetstreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
`
	m := &NetInfraModule{}
	findings := m.parseSyslogTLSConfig("/etc/rsyslog.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "TLS", findings[0].CryptoAsset.Algorithm)
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "rsyslog")
}

func TestParseSyslogNG_TLS(t *testing.T) {
	conf := `destination d_remote {
    network("10.0.0.1"
        transport("tls")
        tls(
            ca-dir("/etc/syslog-ng/ca.d")
            key-file("/etc/syslog-ng/key.pem")
            cert-file("/etc/syslog-ng/cert.pem")
        )
    );
};
`
	m := &NetInfraModule{}
	findings := m.parseSyslogTLSConfig("/etc/syslog-ng/syslog-ng.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "TLS", findings[0].CryptoAsset.Algorithm)
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "syslog-ng")
}

func TestParseSyslog_NoTLS(t *testing.T) {
	conf := `*.* @@10.0.0.1:514
`
	m := &NetInfraModule{}
	findings := m.parseSyslogTLSConfig("/etc/rsyslog.conf", []byte(conf))
	assert.Empty(t, findings)
}

// --- 802.1X / RADIUS parser tests ---

func TestParseRADIUS_EAPMethod(t *testing.T) {
	conf := `eap {
    default_eap_type = peap
    tls-config tls-common {
        private_key_file = /etc/certs/server.key
        certificate_file = /etc/certs/server.pem
        ca_file = /etc/certs/ca.pem
        tls_min_version = "1.2"
        cipher_list = "HIGH"
    }
}
`
	m := &NetInfraModule{}
	findings := m.parseRADIUSConfig("/etc/raddb/mods-enabled/eap", []byte(conf))
	require.NotEmpty(t, findings)

	foundEAP := false
	for _, f := range findings {
		if f.CryptoAsset.Function == "EAP method" {
			foundEAP = true
			assert.Equal(t, "PEAP", f.CryptoAsset.Algorithm)
		}
	}
	assert.True(t, foundEAP)
}

func TestParseRADIUS_SharedSecret(t *testing.T) {
	conf := `client office-switch {
    ipaddr = 10.0.0.1
    secret = testing123
}
`
	m := &NetInfraModule{}
	findings := m.parseRADIUSConfig("/etc/raddb/clients.conf", []byte(conf))
	require.NotEmpty(t, findings)
	assert.Equal(t, "RADIUS shared secret", findings[0].CryptoAsset.Function)
	assert.Equal(t, "MD5", findings[0].CryptoAsset.Algorithm, "RADIUS uses MD5 for shared secret auth")
	// Value must be redacted
	assert.NotContains(t, findings[0].CryptoAsset.Purpose, "testing123")
}

// --- module interface tests ---

func TestNetInfraModuleInterface(t *testing.T) {
	m := NewNetInfraModule(nil)
	assert.Equal(t, "netinfra", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}

// helper
func algoSetFrom(findings []*model.Finding) map[string]bool {
	s := make(map[string]bool)
	for _, f := range findings {
		s[f.CryptoAsset.Algorithm] = true
	}
	return s
}
