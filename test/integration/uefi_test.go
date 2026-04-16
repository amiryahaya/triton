//go:build integration

package integration

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
)

func TestUEFI_EndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uefi module is Linux-only")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := thisFile
	for i := 0; i < 3; i++ { // go up from test/integration/uefi_test.go
		repoRoot = repoRoot[:strings.LastIndex(repoRoot, "/")]
	}
	varRoot := repoRoot + "/pkg/scanner/internal/uefivars/testdata/efivars"

	cfg := &scannerconfig.Config{UEFIVarRoot: varRoot, MaxFileSize: 16 << 20}
	m := scanner.NewUEFIModule(cfg)
	ch := make(chan *model.Finding, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		_ = m.Scan(ctx, model.ScanTarget{Type: model.TargetFilesystem}, ch)
		close(ch)
	}()

	got := []*model.Finding{}
	for f := range ch {
		got = append(got, f)
	}
	if len(got) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range got {
		if f.Module != "uefi" {
			t.Errorf("Module = %q, want uefi", f.Module)
		}
	}
}
