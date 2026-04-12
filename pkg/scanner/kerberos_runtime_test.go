package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- klist parser tests ---

func TestParseKlist_StrongEnctypes(t *testing.T) {
	output := `Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: user@EXAMPLE.COM

Valid starting       Expires              Service principal
04/12/2026 09:00:00  04/12/2026 19:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 04/13/2026 09:00:00, Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96
04/12/2026 09:01:00  04/12/2026 19:00:00  HTTP/server.example.com@EXAMPLE.COM
	Etype (skey, tkt): aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96
`
	m := &KerberosRuntimeModule{}
	findings := m.parseKlist([]byte(output))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["AES-256"])
	assert.True(t, algoSet["AES-128"])
}

func TestParseKlist_WeakRC4(t *testing.T) {
	output := `Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: user@LEGACY.COM

Valid starting       Expires              Service principal
04/12/2026 09:00:00  04/12/2026 19:00:00  krbtgt/LEGACY.COM@LEGACY.COM
	Etype (skey, tkt): arcfour-hmac, arcfour-hmac
`
	m := &KerberosRuntimeModule{}
	findings := m.parseKlist([]byte(output))
	require.NotEmpty(t, findings)
	assert.Equal(t, "RC4", findings[0].CryptoAsset.Algorithm)
}

func TestParseKlist_Empty(t *testing.T) {
	m := &KerberosRuntimeModule{}
	findings := m.parseKlist([]byte("klist: No credentials cache found"))
	assert.Empty(t, findings)
}

// --- krb5.conf parser tests ---

func TestParseKrb5Conf_Enctypes(t *testing.T) {
	conf := `[libdefaults]
    default_realm = EXAMPLE.COM
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96

[realms]
    EXAMPLE.COM = {
        kdc = kdc.example.com
    }
`
	m := &KerberosRuntimeModule{}
	findings := m.parseKrb5Conf("/etc/krb5.conf", []byte(conf))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["AES-256"])
	assert.True(t, algoSet["AES-128"])
}

func TestParseKrb5Conf_WeakDES(t *testing.T) {
	conf := `[libdefaults]
    permitted_enctypes = des-cbc-crc des3-cbc-sha1
`
	m := &KerberosRuntimeModule{}
	findings := m.parseKrb5Conf("/etc/krb5.conf", []byte(conf))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["DES"])
	assert.True(t, algoSet["3DES"])
}

func TestParseKrb5Conf_NoEnctypes(t *testing.T) {
	conf := `[libdefaults]
    default_realm = EXAMPLE.COM
`
	m := &KerberosRuntimeModule{}
	findings := m.parseKrb5Conf("/etc/krb5.conf", []byte(conf))
	assert.Empty(t, findings)
}

// --- module interface + mock tests ---

func TestKerberosRuntimeModuleInterface(t *testing.T) {
	m := NewKerberosRuntimeModule(nil)
	assert.Equal(t, "kerberos_runtime", m.Name())
	assert.Equal(t, model.CategoryActiveRuntime, m.Category())
	assert.Equal(t, model.TargetProcess, m.ScanTargetType())
	var _ Module = m
}

func TestKerberosRuntime_MockScan(t *testing.T) {
	origCmd := kerberosCmdRunner
	origRead := kerberosReadFile
	defer func() {
		kerberosCmdRunner = origCmd
		kerberosReadFile = origRead
	}()

	kerberosCmdRunner = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(`Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: user@EXAMPLE.COM
Valid starting       Expires              Service principal
04/12/2026 09:00:00  04/12/2026 19:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96
`), nil
	}
	kerberosReadFile = func(path string) ([]byte, error) {
		if path == "/etc/krb5.conf" {
			return []byte(`[libdefaults]
    permitted_enctypes = aes256-cts-hmac-sha1-96
`), nil
		}
		return nil, fmt.Errorf("not found")
	}

	m := NewKerberosRuntimeModule(nil)
	findings := make(chan *model.Finding, 100)
	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetProcess, Value: "local"}, findings)
	close(findings)
	require.NoError(t, err)

	var all []*model.Finding
	for f := range findings {
		all = append(all, f)
	}
	require.True(t, len(all) >= 2, "expected findings from klist + krb5.conf, got %d", len(all))
}
