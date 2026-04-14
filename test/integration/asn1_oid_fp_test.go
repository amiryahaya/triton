//go:build integration

package integration_test

import (
	"context"
	"os/exec"
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// TestASN1OID_FalsePositiveBaseline scans /bin/echo (a minimal non-crypto
// binary) and asserts the asn1_oid module produces fewer than 5 findings.
// This guards against registry expansions or decoder relaxations that would
// introduce noisy false positives on benign binaries. If this breaches, the
// filters in pkg/crypto/asn1.go (tryDecodeOIDAt validity rules) need
// tightening before the change lands.
func TestASN1OID_FalsePositiveBaseline(t *testing.T) {
	echoPath, err := exec.LookPath("echo")
	if err != nil {
		t.Skip("echo not found")
	}

	m := scanner.NewASN1OIDModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 100)
	done := make(chan struct{})
	var count int
	go func() {
		for range findings {
			count++
		}
		close(done)
	}()

	target := model.ScanTarget{
		Type:  model.TargetFilesystem,
		Value: echoPath,
	}
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	close(findings)
	<-done

	t.Logf("%s produced %d asn1_oid findings", echoPath, count)
	if count > 5 {
		t.Errorf("false positive baseline breached: %d findings (threshold 5)", count)
	}
}
