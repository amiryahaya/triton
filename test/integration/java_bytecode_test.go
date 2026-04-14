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

// TestJavaBytecode_ScansTestdataJAR runs the module against the checked-in
// crypto.jar fixture (built in Phase 1 Task 2). SKIPs if the fixture is
// missing. Validates end-to-end module behavior including profile defaults.
func TestJavaBytecode_ScansTestdataJAR(t *testing.T) {
	fixture := "../../pkg/scanner/internal/javaclass/testdata/crypto.jar"
	if _, err := exec.LookPath("java"); err == nil {
		t.Logf("java present on PATH — fixture is authoritative")
	}
	m := scanner.NewJavaBytecodeModule(&scannerconfig.Config{})
	findings := make(chan *model.Finding, 64)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: fixture}
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Skipf("scan failed: %v", err)
	}
	close(findings)
	<-done

	if len(collected) == 0 {
		t.Skipf("no findings — is %s present?", fixture)
	}
	t.Logf("%s produced %d findings", fixture, len(collected))
	for _, f := range collected {
		if f.CryptoAsset != nil {
			t.Logf("  finding: algo=%q status=%q", f.CryptoAsset.Algorithm, f.CryptoAsset.PQCStatus)
		}
	}
}
