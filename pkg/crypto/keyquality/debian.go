package keyquality

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/sha1" //nolint:gosec // SHA-1 is required: that's how the Debian blocklist fingerprints are keyed.
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"io"
	"strings"
)

//go:embed testdata/blocklist-rsa-1024.gz
var debianRSA1024Data []byte

//go:embed testdata/blocklist-rsa-2048.gz
var debianRSA2048Data []byte

//go:embed testdata/blocklist-dsa-1024.gz
var debianDSA1024Data []byte

//go:embed testdata/blocklist-dsa-2048.gz
var debianDSA2048Data []byte

type fingerprintSet map[[20]byte]struct{}

var (
	debianRSA1024Set fingerprintSet
	debianRSA2048Set fingerprintSet
	debianDSA1024Set fingerprintSet
	debianDSA2048Set fingerprintSet
)

func init() {
	debianRSA1024Set = mustLoadFingerprintSet(debianRSA1024Data, "rsa-1024")
	debianRSA2048Set = mustLoadFingerprintSet(debianRSA2048Data, "rsa-2048")
	debianDSA1024Set = mustLoadFingerprintSet(debianDSA1024Data, "dsa-1024")
	debianDSA2048Set = mustLoadFingerprintSet(debianDSA2048Data, "dsa-2048")
}

// mustLoadFingerprintSet decodes a gzipped newline-separated 40-hex-char list.
// Panics at init on corrupted data — the embedded blobs are committed, so any
// error is a build-time bug.
func mustLoadFingerprintSet(gz []byte, name string) fingerprintSet {
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		panic("keyquality: gunzip " + name + ": " + err.Error())
	}
	defer func() { _ = gr.Close() }()
	raw, err := io.ReadAll(gr)
	if err != nil {
		panic("keyquality: read " + name + ": " + err.Error())
	}
	out := fingerprintSet{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil || len(b) != 20 {
			panic("keyquality: bad fingerprint in " + name + ": " + line)
		}
		var fp [20]byte
		copy(fp[:], b)
		out[fp] = struct{}{}
	}
	return out
}

// debianWeakCheck looks up SHA-1(MarshalPKIX(pub)) in the appropriate
// Debian-weak-key blocklist based on algo + keySize. Supported combinations:
// RSA-1024, RSA-2048, DSA-1024, DSA-2048. Anything else → no check.
func debianWeakCheck(pub crypto.PublicKey, algo string, keySize int) (Warning, bool) {
	if pub == nil {
		return Warning{}, false
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Warning{}, false
	}
	h := sha1.Sum(der) //nolint:gosec // see above
	set := pickFingerprintSet(algo, keySize)
	if set == nil {
		return Warning{}, false
	}
	if _, ok := set[h]; !ok {
		return Warning{}, false
	}
	return Warning{
		Code:     CodeDebianWeak,
		Severity: SeverityCritical,
		Message:  "public key matches Debian OpenSSL PRNG weak-key blocklist",
		CVE:      "CVE-2008-0166",
	}, true
}

func pickFingerprintSet(algo string, keySize int) fingerprintSet {
	algo = strings.ToUpper(strings.TrimSpace(algo))
	switch {
	case strings.HasPrefix(algo, "RSA") && keySize == 1024:
		return debianRSA1024Set
	case strings.HasPrefix(algo, "RSA") && keySize == 2048:
		return debianRSA2048Set
	case strings.HasPrefix(algo, "DSA") && keySize == 1024:
		return debianDSA1024Set
	case strings.HasPrefix(algo, "DSA") && keySize == 2048:
		return debianDSA2048Set
	}
	return nil
}

// --- test-only helpers; see debian_testhelp_test.go ---
