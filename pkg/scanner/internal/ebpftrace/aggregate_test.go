package ebpftrace

import (
	"testing"
	"time"
)

func TestAggregator_Adds(t *testing.T) {
	agg := NewAggregator()

	agg.Add(Event{PID: 100, Source: SourceUprobe, LibID: LibLibcrypto, NID: 672, Comm: "nginx"},
		"/usr/lib/libcrypto.so.3")
	agg.Add(Event{PID: 100, Source: SourceUprobe, LibID: LibLibcrypto, NID: 672, Comm: "nginx"},
		"/usr/lib/libcrypto.so.3")
	agg.Add(Event{PID: 200, Source: SourceUprobe, LibID: LibLibcrypto, NID: 672, Comm: "httpd"},
		"/usr/lib/libcrypto.so.3")
	// Different NID → separate bucket
	agg.Add(Event{PID: 100, Source: SourceUprobe, LibID: LibLibcrypto, NID: 6, Comm: "nginx"},
		"/usr/lib/libcrypto.so.3")

	got := agg.Flush()
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (sha256, rsa)", len(got))
	}
	byAlgo := map[string]*Aggregate{}
	for i := range got {
		byAlgo[got[i].Algorithm] = &got[i]
	}
	sha := byAlgo["SHA-256"]
	if sha == nil {
		t.Fatal("missing SHA-256 aggregate")
	}
	if sha.Count != 3 {
		t.Errorf("SHA-256 Count = %d, want 3", sha.Count)
	}
	if len(sha.PIDs) != 2 {
		t.Errorf("SHA-256 PIDs = %d unique, want 2", len(sha.PIDs))
	}
	if sha.BinaryPath != "/usr/lib/libcrypto.so.3" {
		t.Errorf("BinaryPath = %q", sha.BinaryPath)
	}
	if sha.Source != SourceUprobe {
		t.Errorf("Source = %v, want SourceUprobe", sha.Source)
	}
}

func TestAggregator_KernelPath(t *testing.T) {
	agg := NewAggregator()
	agg.Add(Event{PID: 500, Source: SourceKprobe, LibID: LibKernel, NID: -1, Name: "sha256"}, "kernel")
	agg.Add(Event{PID: 500, Source: SourceKprobe, LibID: LibKernel, NID: -1, Name: "cbc(aes)"}, "kernel")

	got := agg.Flush()
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
}

func TestAggregator_DropsUnclassified(t *testing.T) {
	agg := NewAggregator()
	agg.Add(Event{PID: 1, Source: SourceUprobe, LibID: LibLibcrypto, NID: 99999, Comm: "x"}, "/lib.so")
	agg.Add(Event{PID: 1, Source: SourceKprobe, LibID: LibKernel, NID: -1, Name: "unknownthing"}, "kernel")

	got := agg.Flush()
	if len(got) != 0 {
		t.Errorf("len(got) = %d, want 0 (unclassified dropped)", len(got))
	}
}

func TestAggregator_FlushResets(t *testing.T) {
	agg := NewAggregator()
	agg.Add(Event{PID: 1, Source: SourceUprobe, LibID: LibLibcrypto, NID: 672, Comm: "x"}, "/lib")
	_ = agg.Flush()
	got := agg.Flush()
	if len(got) != 0 {
		t.Errorf("second Flush should return empty, got %d", len(got))
	}
	_ = time.Second // keep time import minimal
}
