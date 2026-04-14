package scanner

import (
	"context"
	"io/fs"
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

type stubReader struct{}

func (stubReader) ReadFile(ctx context.Context, p string) ([]byte, error)          { return nil, nil }
func (stubReader) Stat(ctx context.Context, p string) (fs.FileInfo, error)         { return nil, nil }
func (stubReader) ReadDir(ctx context.Context, p string) ([]fs.DirEntry, error)    { return nil, nil }
func (stubReader) Walk(ctx context.Context, r string, fn fsadapter.WalkFunc) error { return nil }

type stubFRAware struct {
	name   string
	reader fsadapter.FileReader
}

func (s *stubFRAware) Name() string                         { return s.name }
func (s *stubFRAware) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (s *stubFRAware) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (s *stubFRAware) Scan(ctx context.Context, t model.ScanTarget, f chan<- *model.Finding) error {
	return nil
}
func (s *stubFRAware) SetFileReader(r fsadapter.FileReader) { s.reader = r }

func TestEngineInjectsFileReader(t *testing.T) {
	cfg := &scannerconfig.Config{Workers: 1}
	eng := New(cfg)
	m := &stubFRAware{name: "stub"}
	eng.RegisterModule(m)
	r := stubReader{}
	eng.SetFileReader(r)

	progressCh := make(chan Progress, 4)
	eng.Scan(context.Background(), progressCh)

	if m.reader == nil {
		t.Fatal("expected FileReader to be injected into module")
	}
}

func TestEngineHostnameOverride(t *testing.T) {
	cfg := &scannerconfig.Config{Workers: 1}
	eng := New(cfg)
	eng.SetHostnameOverride("remote-host.example")

	progressCh := make(chan Progress, 4)
	result := eng.Scan(context.Background(), progressCh)

	if result.Metadata.Hostname != "remote-host.example" {
		t.Fatalf("expected hostname override, got %q", result.Metadata.Hostname)
	}
}
