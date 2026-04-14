//go:build integration

package integration_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// TestASN1OID_ScansSystemOpenSSL exercises the asn1_oid module against a
// real OpenSSL installation. The openssl(1) CLI frontend is a thin dispatcher;
// the canonical cryptographic OIDs live in libcrypto. We locate libcrypto by
// walking up from the openssl binary to its installation prefix (covers
// /usr/bin/openssl → /usr, Homebrew Cellar/openssl@3/<ver>/bin → Cellar prefix,
// etc.) and scan the enclosing tree. Every libcrypto embeds the OIDs for RSA,
// SHA-256, and at least one AES variant, so we assert those as minimum
// classifications.
func TestASN1OID_ScansSystemOpenSSL(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed on test host")
	}

	// Resolve symlinks so we anchor on the real file (important on Homebrew
	// where /opt/homebrew/bin/openssl → Cellar/openssl@3/<ver>/bin/openssl).
	resolved, err := filepath.EvalSymlinks(opensslPath)
	if err != nil {
		resolved = opensslPath
	}

	// Walk upward from the binary's directory looking for a sibling "lib"
	// directory containing libcrypto. This covers:
	//   - Homebrew: /opt/homebrew/Cellar/openssl@3/<ver>/{bin,lib}
	//   - Debian:   /usr/{bin,lib/x86_64-linux-gnu}
	//   - /usr/local/{bin,lib}
	scanRoot := findOpenSSLInstallRoot(resolved)
	if scanRoot == "" {
		t.Skipf("could not locate libcrypto near %s (platform=%s)", resolved, runtime.GOOS)
	}
	t.Logf("scanning OpenSSL installation root: %s", scanRoot)

	m := scanner.NewASN1OIDModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 4096)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()

	target := model.ScanTarget{
		Type:  model.TargetFilesystem,
		Value: scanRoot,
	}
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	close(findings)
	<-done

	t.Logf("OpenSSL scan produced %d findings", len(collected))

	// Collect classified algorithms and AES/AES-family membership. We assert
	// the *minimum* set of algos that any libcrypto build must classify:
	// RSA signing key, SHA-256 digest, and the AES family. Specific AES modes
	// (GCM vs wrap) vary between builds — we only require *some* AES OID be
	// present, not a specific cipher mode.
	got := map[string]bool{}
	sawAES := false
	for _, f := range collected {
		if f.CryptoAsset == nil {
			continue
		}
		algo := f.CryptoAsset.Algorithm
		got[algo] = true
		if len(algo) >= 3 && algo[:3] == "AES" {
			sawAES = true
		}
	}

	for _, want := range []string{"RSA", "SHA-256"} {
		if !got[want] {
			t.Errorf("expected %q in OpenSSL findings, missing (platform=%s, root=%s)", want, runtime.GOOS, scanRoot)
		}
	}
	if !sawAES {
		t.Errorf("expected at least one AES-family OID in OpenSSL findings, none found (platform=%s, root=%s)", runtime.GOOS, scanRoot)
	}
}

// findOpenSSLInstallRoot walks upward from opensslBin looking for a directory
// that contains both a "lib" subdir and a crypto library within. Returns the
// install prefix (to be scanned) or "" if nothing suitable was found.
func findOpenSSLInstallRoot(opensslBin string) string {
	dir := filepath.Dir(opensslBin) // .../bin
	for i := 0; i < 4; i++ {        // walk up at most 4 levels
		dir = filepath.Dir(dir)
		if dir == "/" || dir == "." {
			break
		}
		if hasLibCrypto(dir) {
			return dir
		}
	}
	return ""
}

// hasLibCrypto reports whether root contains a libcrypto.* file somewhere
// beneath it (checked via a bounded-depth walk).
func hasLibCrypto(root string) bool {
	rootDepth := depthOf(root)
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Cap relative depth at 4 levels below root to keep scan cheap.
			if depthOf(path)-rootDepth > 4 {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		// Match libcrypto.so*, libcrypto.*.dylib, libcrypto-*.dll, etc.
		if len(name) >= 9 && name[:9] == "libcrypto" {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// depthOf returns the number of path separators in an absolute path,
// used as a coarse directory depth for bounded traversal.
func depthOf(p string) int {
	n := 0
	for _, c := range p {
		if c == filepath.Separator {
			n++
		}
	}
	return n
}
