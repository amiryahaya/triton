package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

var _ Module = (*XMLDSigModule)(nil)

func TestXMLDSigModule_Interface(t *testing.T) {
	t.Parallel()
	m := NewXMLDSigModule(&scannerconfig.Config{})
	assert.Equal(t, "xml_dsig", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
}

func TestIsXMLDSigCandidate(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"/etc/shibboleth/idp-metadata.xml":     true,
		"/opt/saml/sp-metadata.xml":            true,
		"/etc/pki/saml/metadata.xml":           true,
		"/srv/app/config/signed-config.xml":    true,
		"/etc/nginx/nginx.conf":                false,
		"/etc/shibboleth/idp-metadata.xml.bak": false,
	}
	for path, want := range cases {
		got := isXMLDSigCandidate(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

const samlMetadataStrong = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://idp.example.com/">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
</md:EntityDescriptor>`

const samlMetadataWeak = `<?xml version="1.0"?>
<EntityDescriptor>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
</EntityDescriptor>`

func TestParseXMLDSig_StrongSaml(t *testing.T) {
	t.Parallel()
	m := NewXMLDSigModule(&scannerconfig.Config{})
	findings := m.parseXMLDSig("/etc/shibboleth/idp-metadata.xml", []byte(samlMetadataStrong))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "RSA-SHA256")
	assert.Contains(t, joined, "SHA-256")
}

func TestParseXMLDSig_WeakSha1(t *testing.T) {
	t.Parallel()
	m := NewXMLDSigModule(&scannerconfig.Config{})
	findings := m.parseXMLDSig("/etc/shibboleth/idp-metadata.xml", []byte(samlMetadataWeak))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "RSA-SHA1")
	assert.Contains(t, joined, "SHA-1")
}

func TestXMLDSig_NoSignature(t *testing.T) {
	t.Parallel()
	// Plain XML with no <Signature> should produce zero findings.
	m := NewXMLDSigModule(&scannerconfig.Config{})
	findings := m.parseXMLDSig("/etc/app/config.xml", []byte(`<?xml version="1.0"?><config><setting>value</setting></config>`))
	assert.Empty(t, findings)
}

func TestXMLDSigModule_ScanWalk(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	shibDir := filepath.Join(tmp, "etc", "shibboleth")
	require.NoError(t, os.MkdirAll(shibDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(shibDir, "idp-metadata.xml"), []byte(samlMetadataStrong), 0o644))

	m := NewXMLDSigModule(&scannerconfig.Config{MaxDepth: 10, MaxFileSize: 1024 * 1024})
	findings := make(chan *model.Finding, 32)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()

	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetFilesystem, Value: tmp, Depth: 10}, findings)
	require.NoError(t, err)
	close(findings)
	<-done

	require.NotEmpty(t, collected)
}
