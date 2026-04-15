//go:build linux

package scanner

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/ebpftrace"
)

func TestEBPFTrace_Linux_RunnerErrorEmitsSkipped(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to bypass not-root short-circuit")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("requires BTF")
	}
	m := NewEBPFTraceModule(&scannerconfig.Config{EBPFWindow: time.Second})
	m.runner = func(_ context.Context, _ ebpftrace.Options) (*ebpftrace.Outcome, error) {
		return nil, errors.New("synthetic loader failure")
	}
	ch := make(chan *model.Finding, 4)
	if err := m.scan(context.Background(), model.ScanTarget{}, ch); err != nil {
		t.Fatal(err)
	}
	close(ch)
	var got []*model.Finding
	for f := range ch {
		got = append(got, f)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1 skipped finding", len(got))
	}
	if got[0].Source.DetectionMethod != "ebpf-skipped" {
		t.Errorf("DetectionMethod = %q, want ebpf-skipped", got[0].Source.DetectionMethod)
	}
}

func TestEBPFTrace_Linux_QuietWindowEmitsSkipped(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("requires BTF")
	}
	m := NewEBPFTraceModule(&scannerconfig.Config{EBPFWindow: time.Second})
	m.runner = func(_ context.Context, _ ebpftrace.Options) (*ebpftrace.Outcome, error) {
		return &ebpftrace.Outcome{Aggregates: nil, Window: time.Second}, nil
	}
	ch := make(chan *model.Finding, 4)
	if err := m.scan(context.Background(), model.ScanTarget{}, ch); err != nil {
		t.Fatal(err)
	}
	close(ch)
	var got []*model.Finding
	for f := range ch {
		got = append(got, f)
	}
	if len(got) != 1 || got[0].Source.DetectionMethod != "ebpf-skipped" {
		t.Errorf("expected single skipped finding for quiet window, got %+v", got)
	}
}
