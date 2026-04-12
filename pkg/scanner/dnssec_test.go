package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
)

// --- file matcher tests ---

func TestIsDNSSECZoneFile(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		// BIND zone files
		{"/var/named/example.com.zone", true},
		{"/var/named/db.example.com", true},
		{"/etc/bind/zones/example.com.zone", true},
		{"/etc/bind/db.local", true},
		{"/etc/nsd/zones/example.zone", true},
		{"/etc/knot/zones/example.com.zone", true},

		// Zone files by extension alone
		{"/some/path/myzone.zone", true},
		{"/some/path/db.internal", false}, // db.* only matches under DNS paths

		// Named zone directories
		{"/var/named/chroot/var/named/example.zone", true},

		// Not zone files
		{"/etc/bind/named.conf", false},
		{"/var/named/named.ca", false}, // root hints, not zone
		{"/etc/nginx/nginx.conf", false},
		{"/home/user/readme.txt", false},
		{"/var/named/data/cache.db", false}, // no db. prefix
		{"/etc/bind/rndc.key", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isDNSSECZoneFile(tc.path), "path: %s", tc.path)
		})
	}
}

// --- zone file parser tests ---

func TestParseDNSKEYRecord(t *testing.T) {
	zone := `; Example zone with DNSKEY records
$ORIGIN example.com.
$TTL 86400
@   IN  SOA ns1.example.com. admin.example.com. (
            2026041201 ; serial
            3600       ; refresh
            900        ; retry
            604800     ; expire
            86400      ; minimum TTL
)
    IN  NS  ns1.example.com.
    IN  NS  ns2.example.com.

; KSK (flags 257)
example.com. 86400 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0d xCjjnopKl+GqJxpVXckHAeF+KkxLbxIL fDLUT0rAK9iUzy1L53eKGQ==

; ZSK (flags 256)
example.com. 86400 IN DNSKEY 256 3 8 AwEAAb4N53...
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/example.com.zone", []byte(zone))
	require.Len(t, findings, 2, "expected 2 DNSKEY findings")

	// KSK with algo 13 = ECDSA-P256-SHA-256
	assert.Equal(t, "ECDSA-P256-SHA-256", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "DNSKEY (KSK)", findings[0].CryptoAsset.Function)
	assert.Contains(t, findings[0].CryptoAsset.Purpose, "example.com")

	// ZSK with algo 8 = RSA-SHA-256
	assert.Equal(t, "RSA-SHA-256", findings[1].CryptoAsset.Algorithm)
	assert.Equal(t, "DNSKEY (ZSK)", findings[1].CryptoAsset.Function)
}

func TestParseDSRecord(t *testing.T) {
	zone := `$ORIGIN example.com.
example.com. 86400 IN DS 12345 13 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE
example.com. 3600  IN DS 54321  5 1 2BB183AF5F22588179A53B0A98631FAD1A292118
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/etc/bind/db.example.com", []byte(zone))
	// 2 DS records x 2 findings each (signing algo + digest algo) = 4
	require.Len(t, findings, 4)

	// First DS: algo 13, digest type 2
	assert.Equal(t, "ECDSA-P256-SHA-256", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "DNSSEC DS record", findings[0].CryptoAsset.Function)
	assert.Equal(t, "SHA-256", findings[1].CryptoAsset.Algorithm)
	assert.Equal(t, "DNSSEC DS digest", findings[1].CryptoAsset.Function)

	// Second DS: algo 5, digest type 1
	assert.Equal(t, "RSA-SHA1", findings[2].CryptoAsset.Algorithm)
	assert.Equal(t, "DNSSEC DS record", findings[2].CryptoAsset.Function)
	assert.Equal(t, "SHA-1", findings[3].CryptoAsset.Algorithm)
	assert.Equal(t, "DNSSEC DS digest", findings[3].CryptoAsset.Function)
}

func TestParseRRSIGRecord(t *testing.T) {
	zone := `$ORIGIN example.com.
example.com. 86400 IN RRSIG A 13 2 86400 20260401000000 20260301000000 12345 example.com. dGVzdHNpZw==
example.com. 86400 IN RRSIG NS 8 2 86400 20260401000000 20260301000000 54321 example.com. c2lnbmF0dXJl
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/example.zone", []byte(zone))
	require.Len(t, findings, 2)

	assert.Equal(t, "ECDSA-P256-SHA-256", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "DNSSEC RRSIG (A)", findings[0].CryptoAsset.Function)

	assert.Equal(t, "RSA-SHA-256", findings[1].CryptoAsset.Algorithm)
	assert.Equal(t, "DNSSEC RRSIG (NS)", findings[1].CryptoAsset.Function)
}

func TestParseMixedRecords(t *testing.T) {
	zone := `$ORIGIN secure.example.com.
$TTL 3600
@   IN  SOA ns1 admin 2026041201 3600 900 604800 86400
    IN  NS  ns1
    IN  NS  ns2

; DNSKEY KSK
@ 3600 IN DNSKEY 257 3 15 base64key==

; DS
@ IN DS 12345 15 2 abc123

; RRSIG on the SOA
@ IN RRSIG SOA 15 2 3600 20260401000000 20260301000000 12345 secure.example.com. sig==
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/etc/bind/zones/secure.example.com.zone", []byte(zone))
	// DNSKEY + DS(signing+digest) + RRSIG = 4
	require.Len(t, findings, 4)

	assert.Equal(t, "DNSKEY (KSK)", findings[0].CryptoAsset.Function)
	assert.Equal(t, "Ed25519", findings[0].CryptoAsset.Algorithm)

	assert.Equal(t, "DNSSEC DS record", findings[1].CryptoAsset.Function)
	assert.Equal(t, "Ed25519", findings[1].CryptoAsset.Algorithm)

	assert.Equal(t, "DNSSEC DS digest", findings[2].CryptoAsset.Function)
	assert.Equal(t, "SHA-256", findings[2].CryptoAsset.Algorithm)

	assert.Equal(t, "DNSSEC RRSIG (SOA)", findings[3].CryptoAsset.Function)
	assert.Equal(t, "Ed25519", findings[3].CryptoAsset.Algorithm)
}

func TestParseUnknownAlgorithm(t *testing.T) {
	zone := `example.com. IN DNSKEY 257 3 99 keydata==
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/test.zone", []byte(zone))
	require.Len(t, findings, 1)
	assert.Equal(t, "DNSSEC-algo-99", findings[0].CryptoAsset.Algorithm)
}

func TestParseEmptyZone(t *testing.T) {
	zone := `; Empty zone file — no DNSSEC records
$ORIGIN example.com.
$TTL 3600
@   IN  SOA ns1 admin 1 3600 900 604800 86400
    IN  NS  ns1
    IN  A   192.0.2.1
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/plain.zone", []byte(zone))
	assert.Empty(t, findings)
}

func TestParseCommentsAndBlankLines(t *testing.T) {
	zone := `
; comment line
$ORIGIN example.com.

; another comment
example.com. IN DNSKEY 257 3 14 key==
; trailing comment
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/test.zone", []byte(zone))
	require.Len(t, findings, 1)
	assert.Equal(t, "ECDSA-P384-SHA-384", findings[0].CryptoAsset.Algorithm)
}

func TestParseNoTTLNoClass(t *testing.T) {
	// Minimal record without explicit TTL or class
	zone := `example.com. DNSKEY 257 3 13 key==
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/test.zone", []byte(zone))
	require.Len(t, findings, 1)
	assert.Equal(t, "ECDSA-P256-SHA-256", findings[0].CryptoAsset.Algorithm)
}

func TestParseDNSKEYFlags(t *testing.T) {
	zone := `; KSK
example.com. IN DNSKEY 257 3 13 kskkey==
; ZSK
example.com. IN DNSKEY 256 3 13 zskkey==
; SEP bit not set, not KSK
example.com. IN DNSKEY 0 3 13 otherkey==
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/test.zone", []byte(zone))
	require.Len(t, findings, 3)
	assert.Equal(t, "DNSKEY (KSK)", findings[0].CryptoAsset.Function)
	assert.Equal(t, "DNSKEY (ZSK)", findings[1].CryptoAsset.Function)
	assert.Equal(t, "DNSKEY", findings[2].CryptoAsset.Function)
}

func TestFindingSource(t *testing.T) {
	zone := `example.com. IN DNSKEY 257 3 13 key==
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/example.zone", []byte(zone))
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "file", f.Source.Type)
	assert.Equal(t, "/var/named/example.zone", f.Source.Path)
	assert.Equal(t, "configuration", f.Source.DetectionMethod)
	assert.Equal(t, CategoryConfig, f.Category)
	assert.Equal(t, ConfidenceDefinitive, f.Confidence)
	assert.Equal(t, "dnssec", f.Module)
}

func TestDNSSECModuleInterface(t *testing.T) {
	m := NewDNSSECModule(nil)
	assert.Equal(t, "dnssec", m.Name())
	// Module interface compliance
	var _ Module = m
}

func TestDeprecatedAlgorithmsClassified(t *testing.T) {
	zone := `; Old RSA-SHA1 signer
example.com. IN DNSKEY 257 3 5 oldkey==
; Even older RSA-MD5
example.com. IN DNSKEY 257 3 1 ancientkey==
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/test.zone", []byte(zone))
	require.Len(t, findings, 2)

	assert.Equal(t, "RSA-SHA1", findings[0].CryptoAsset.Algorithm)
	assert.NotEmpty(t, findings[0].CryptoAsset.PQCStatus, "deprecated algo should be classified")

	assert.Equal(t, "RSA-MD5", findings[1].CryptoAsset.Algorithm)
	assert.NotEmpty(t, findings[1].CryptoAsset.PQCStatus)
}

func TestParseDSDigestTypes(t *testing.T) {
	// DS records with different digest types — each DS now produces
	// two findings (signing algo + digest algo).
	zone := `example.com. IN DS 12345 14 1 abc123
example.com. IN DS 12345 14 2 def456
example.com. IN DS 12345 14 4 ghi789
`
	m := &DNSSECModule{}
	findings := m.parseZoneFile("/var/named/test.zone", []byte(zone))
	// 3 DS records x 2 findings = 6
	require.Len(t, findings, 6)

	// Each pair: signing algo (ECDSA-P384-SHA-384) + digest algo
	assert.Equal(t, "ECDSA-P384-SHA-384", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "SHA-1", findings[1].CryptoAsset.Algorithm) // digest type 1
	assert.Equal(t, "DNSSEC DS digest", findings[1].CryptoAsset.Function)

	assert.Equal(t, "ECDSA-P384-SHA-384", findings[2].CryptoAsset.Algorithm)
	assert.Equal(t, "SHA-256", findings[3].CryptoAsset.Algorithm) // digest type 2

	assert.Equal(t, "ECDSA-P384-SHA-384", findings[4].CryptoAsset.Algorithm)
	assert.Equal(t, "SHA-384", findings[5].CryptoAsset.Algorithm) // digest type 4
}

// --- active dig query tests ---

func TestParseDigOutput(t *testing.T) {
	digOut := `example.com.		86400	IN	DNSKEY	257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0d xCjjnopKl+GqJxpVXckHAeF+KkxLbxIL fDLUT0rAK9iUzy1L53eKGQ==
example.com.		86400	IN	DNSKEY	256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWz JaOau8XNEZeqCYKD5ar0IRd8KqXXFJkq mVfRvMGPmM1x8fGAa2XhSA==
`
	m := &DNSSECModule{}
	findings := m.parseDigOutput("example.com", []byte(digOut))
	require.Len(t, findings, 2)

	assert.Equal(t, "DNSKEY (KSK)", findings[0].CryptoAsset.Function)
	assert.Equal(t, "ECDSA-P256-SHA-256", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "network", findings[0].Source.Type)
	assert.Equal(t, "example.com", findings[0].Source.Endpoint)
	assert.Equal(t, "dns-query", findings[0].Source.DetectionMethod)

	assert.Equal(t, "DNSKEY (ZSK)", findings[1].CryptoAsset.Function)
	assert.Equal(t, "ECDSA-P256-SHA-256", findings[1].CryptoAsset.Algorithm)
}

func TestParseDigOutputWithComments(t *testing.T) {
	digOut := `; <<>> DiG 9.18 <<>> +dnssec +noall +answer DNSKEY example.com
;; Got answer:
example.com.		86400	IN	DNSKEY	257 3 8 AwEAAb4N53...
`
	m := &DNSSECModule{}
	findings := m.parseDigOutput("example.com", []byte(digOut))
	require.Len(t, findings, 1)
	assert.Equal(t, "RSA-SHA-256", findings[0].CryptoAsset.Algorithm)
}

func TestParseDigOutputEmpty(t *testing.T) {
	m := &DNSSECModule{}
	findings := m.parseDigOutput("nosec.example.com", []byte(""))
	assert.Empty(t, findings)
}

func TestQueryDNSKEY_MockSuccess(t *testing.T) {
	// Save and restore the original dig runner.
	orig := digRunner
	defer func() { digRunner = orig }()

	digRunner = func(_ context.Context, zone string) ([]byte, error) {
		return []byte(fmt.Sprintf("%s.\t86400\tIN\tDNSKEY\t257 3 15 base64key==\n", zone)), nil
	}

	m := &DNSSECModule{}
	findings := m.queryDNSKEY(context.Background(), "ed25519.example.com")
	require.Len(t, findings, 1)
	assert.Equal(t, "Ed25519", findings[0].CryptoAsset.Algorithm)
	assert.Equal(t, "DNSKEY (KSK)", findings[0].CryptoAsset.Function)
}

func TestQueryDNSKEY_MockFailure(t *testing.T) {
	orig := digRunner
	defer func() { digRunner = orig }()

	digRunner = func(_ context.Context, _ string) ([]byte, error) {
		return nil, fmt.Errorf("dig: command not found")
	}

	m := &DNSSECModule{}
	findings := m.queryDNSKEY(context.Background(), "example.com")
	assert.Empty(t, findings, "failed dig should return no findings, not panic")
}

func TestBuildConfig_DNSSECZonesInjectsModule(t *testing.T) {
	cfg, err := scannerconfig.BuildConfig(scannerconfig.BuildOptions{
		Profile:     "quick",
		DNSSECZones: []string{"example.com"},
	})
	require.NoError(t, err)
	assert.Contains(t, cfg.Modules, "dnssec")
	assert.Equal(t, []string{"example.com"}, cfg.DNSSECZones)
}

func TestBuildConfig_NoDNSSECZonesNoModule(t *testing.T) {
	cfg, err := scannerconfig.BuildConfig(scannerconfig.BuildOptions{
		Profile: "quick",
	})
	require.NoError(t, err)
	assert.NotContains(t, cfg.Modules, "dnssec", "dnssec should not be injected without --dnssec-zone")
}
