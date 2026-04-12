package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// KerberosRuntimeModule enumerates live Kerberos encryption types:
//
//   - `klist -e` — ticket cache encryption types (negotiated)
//   - /etc/krb5.conf — permitted_enctypes, default_tkt_enctypes,
//     default_tgs_enctypes
//
// Enterprise tier (accesses runtime ticket state).
type KerberosRuntimeModule struct {
	config *scannerconfig.Config
}

// NewKerberosRuntimeModule constructs a KerberosRuntimeModule.
func NewKerberosRuntimeModule(cfg *scannerconfig.Config) *KerberosRuntimeModule {
	return &KerberosRuntimeModule{config: cfg}
}

func (m *KerberosRuntimeModule) Name() string                         { return "kerberos_runtime" }
func (m *KerberosRuntimeModule) Category() model.ModuleCategory       { return model.CategoryActiveRuntime }
func (m *KerberosRuntimeModule) ScanTargetType() model.ScanTargetType { return model.TargetProcess }

var kerberosCmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

var kerberosReadFile func(string) ([]byte, error) = os.ReadFile

// Scan probes Kerberos ticket cache and config for encryption types.
func (m *KerberosRuntimeModule) Scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	// 1. klist -e — live ticket enctypes
	if out, err := kerberosCmdRunner(ctx, "klist", "-e"); err == nil {
		for _, f := range m.parseKlist(out) {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	} else {
		log.Printf("kerberos_runtime: klist unavailable: %v", err)
	}

	// 2. /etc/krb5.conf — configured enctypes
	if data, err := kerberosReadFile("/etc/krb5.conf"); err == nil {
		for _, f := range m.parseKrb5Conf("/etc/krb5.conf", data) {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// kerberosEnctypeMap maps Kerberos enctype names to canonical algorithm names.
var kerberosEnctypeMap = map[string]string{
	"aes256-cts-hmac-sha1-96":    "AES-256",
	"aes128-cts-hmac-sha1-96":    "AES-128",
	"aes256-cts-hmac-sha384-192": "AES-256",
	"aes128-cts-hmac-sha256-128": "AES-128",
	"arcfour-hmac":               "RC4",
	"arcfour-hmac-md5":           "RC4",
	"rc4-hmac":                   "RC4",
	"des-cbc-crc":                "DES",
	"des-cbc-md4":                "DES",
	"des-cbc-md5":                "DES",
	"des3-cbc-sha1":              "3DES",
	"des3-cbc-raw":               "3DES",
	"camellia256-cts-cmac":       "Camellia-256",
	"camellia128-cts-cmac":       "Camellia-128",
}

// parseKlist extracts encryption types from `klist -e` output.
// Looks for lines matching "Etype (skey, tkt): <skey>, <tkt>"
func (m *KerberosRuntimeModule) parseKlist(data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	seen := make(map[string]bool)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		idx := strings.Index(line, "Etype (skey, tkt):")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("Etype (skey, tkt):"):])
		for _, tok := range strings.Split(rest, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" || seen[tok] {
				continue
			}
			seen[tok] = true

			algo := tok
			if canonical, ok := kerberosEnctypeMap[strings.ToLower(tok)]; ok {
				algo = canonical
			}
			out = append(out, m.kerberosFinding("klist", "Kerberos ticket enctype", algo,
				fmt.Sprintf("klist: %s", tok)))
		}
	}
	return out
}

// parseKrb5Conf extracts permitted/default enctypes from krb5.conf.
//
//nolint:unparam // path is architecturally required (logScannerErr, finding source)
func (m *KerberosRuntimeModule) parseKrb5Conf(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "krb5.conf", sc.Err()) }()
	seen := make(map[string]bool)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])

		switch key {
		case "permitted_enctypes", "default_tkt_enctypes", "default_tgs_enctypes":
			for _, tok := range strings.Fields(val) {
				tok = strings.TrimSpace(tok)
				if tok == "" || seen[tok] {
					continue
				}
				seen[tok] = true
				algo := tok
				if canonical, ok := kerberosEnctypeMap[strings.ToLower(tok)]; ok {
					algo = canonical
				}
				out = append(out, m.kerberosFinding(path, "Kerberos configured enctype", algo,
					fmt.Sprintf("krb5.conf %s: %s", key, tok)))
			}
		}
	}
	return out
}

func (m *KerberosRuntimeModule) kerberosFinding(source, function, algorithm, purpose string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  function,
		Algorithm: algorithm,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = algorithm

	sourceType := "process"
	method := "klist"
	if source != "klist" {
		sourceType = "file"
		method = "configuration"
	}

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryRuntime,
		Source: model.FindingSource{
			Type:            sourceType,
			Path:            source,
			DetectionMethod: method,
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceDefinitive,
		Module:      "kerberos_runtime",
		Timestamp:   time.Now(),
	}
}
