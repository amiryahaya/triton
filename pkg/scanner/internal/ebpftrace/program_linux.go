//go:build linux

package ebpftrace

import (
	"bytes"
	"context"
	"debug/elf"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/crypto.o
var cryptoObject []byte

// Run executes a single observation window and returns the aggregates.
// Any prerequisite failure (no BTF, no privilege, missing crypto.o) is surfaced
// as an error; the caller (ebpf_trace_linux.go) converts that into a
// skipped-finding. Callers MUST pass a non-nil context and positive Window.
func Run(ctx context.Context, opts Options) (*Outcome, error) {
	startedAt := time.Now().UTC()
	if opts.Window <= 0 {
		return nil, errors.New("ebpftrace: Window must be positive")
	}
	if len(cryptoObject) == 0 {
		return nil, errors.New("ebpftrace: crypto.o not embedded (needs Linux build with compiled eBPF object)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpftrace: RemoveMemlock: %w", err)
	}

	loader := opts.ObjectLoader
	if loader == nil {
		loader = func() ([]byte, error) { return cryptoObject, nil }
	}
	data, err := loader()
	if err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("ebpftrace: LoadCollectionSpec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("ebpftrace: NewCollection: %w", err)
	}
	defer coll.Close()

	// Open the events map for ring-buffer reading.
	eventsMap, ok := coll.Maps["events"]
	if !ok {
		return nil, errors.New("ebpftrace: 'events' map missing from crypto.o")
	}
	rdr, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("ebpftrace: ringbuf reader: %w", err)
	}
	// Close is handled explicitly after drain below; a deferred Close would
	// double-close in the normal path but is kept as a safety net for any
	// early return before the drain block via a sync.Once-style guard.
	closedReader := false
	defer func() {
		if !closedReader {
			_ = rdr.Close()
		}
	}()

	// Attach probes.
	var closers []link.Link
	defer func() {
		for _, l := range closers {
			_ = l.Close()
		}
	}()
	var probesAttached, probesFailed int
	if !opts.SkipUprobes {
		ua, uf, cls := attachUprobes(coll, closers)
		probesAttached += ua
		probesFailed += uf
		closers = cls
	}
	if !opts.SkipKprobes {
		ka, kf, cls := attachKprobes(coll, closers)
		probesAttached += ka
		probesFailed += kf
		closers = cls
	}

	// Read events until window expires or context cancels.
	agg := NewAggregator()
	readCtx, cancel := context.WithTimeout(ctx, opts.Window)
	defer cancel()

	var eventsObserved, decodeErrors int
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			record, err := rdr.Read()
			if err != nil {
				return // ringbuf closed
			}
			eventsObserved++
			ev, decErr := DecodeEvent(record.RawSample)
			if decErr != nil {
				decodeErrors++
				continue
			}
			binPath := binaryPathForEvent(ev)
			agg.Add(ev, binPath)
		}
	}()

	<-readCtx.Done()
	// Track whether the parent ctx was cancelled (not just our window timeout)
	// BEFORE setting the drain deadline, so we can propagate parent cancellation.
	parentCancelled := ctx.Err() != nil && !errors.Is(readCtx.Err(), context.DeadlineExceeded)
	// SetDeadline unblocks any in-flight Read while still letting the reader
	// drain records already queued in the ring buffer; unlike Close, it does
	// not error out events already published by the kernel (Fix B6).
	rdr.SetDeadline(time.Now().Add(50 * time.Millisecond))
	<-done
	_ = rdr.Close()
	closedReader = true

	if parentCancelled {
		return nil, ctx.Err()
	}

	return &Outcome{
		Aggregates:     agg.Flush(),
		Window:         opts.Window,
		StartedAt:      startedAt,
		EventsObserved: eventsObserved,
		DecodeErrors:   decodeErrors,
		ProbesAttached: probesAttached,
		ProbesFailed:   probesFailed,
	}, nil
}

// attachUprobes walks /proc/self/maps for currently-loaded libs (best effort
// across all processes via /proc/*/maps) and attaches each uprobe target it
// can resolve in any discovered library. Per-process /proc scanning is
// deliberately shallow: we enumerate libraries via /proc/*/maps union, not
// one attach per PID.
func attachUprobes(coll *ebpf.Collection, closers []link.Link) (attached, failed int, out []link.Link) {
	libsByID := map[LibID][]DiscoveredLib{}
	procs, _ := filepath.Glob("/proc/[0-9]*/maps")
	seenInodes := map[string]bool{}
	for _, p := range procs {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		libs, _ := DiscoverLibsFromMaps(f)
		_ = f.Close()
		for _, lib := range libs {
			if seenInodes[lib.Inode] {
				continue
			}
			seenInodes[lib.Inode] = true
			libsByID[lib.LibID] = append(libsByID[lib.LibID], lib)
		}
	}

	for _, target := range UprobeTargets() {
		libs := libsByID[target.LibID]
		for _, lib := range libs {
			prog := coll.Programs[target.ProgName]
			if prog == nil {
				failed++
				continue
			}
			exe, err := link.OpenExecutable(lib.Path)
			if err != nil {
				failed++
				continue
			}
			if !symbolExists(lib.Path, target.SymbolName) {
				failed++
				continue
			}
			l, err := exe.Uprobe(target.SymbolName, prog, nil)
			if err != nil {
				failed++
				continue
			}
			closers = append(closers, l)
			attached++
		}
	}
	return attached, failed, closers
}

// symbolExists returns true iff the ELF symbol table contains the named symbol.
// Handles stripped libraries by returning false instead of erroring.
func symbolExists(path, symbol string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	syms, err := f.DynamicSymbols()
	if err != nil {
		return false
	}
	for _, s := range syms {
		if s.Name == symbol {
			return true
		}
	}
	return false
}

// attachKprobes attaches one link per kernel crypto allocator symbol.
func attachKprobes(coll *ebpf.Collection, closers []link.Link) (attached, failed int, out []link.Link) {
	targets := []struct{ progName, sym string }{
		{"kprobe__crypto_alloc_shash", "crypto_alloc_shash"},
		{"kprobe__crypto_alloc_skcipher", "crypto_alloc_skcipher"},
		{"kprobe__crypto_alloc_akcipher", "crypto_alloc_akcipher"},
		{"kprobe__crypto_alloc_aead", "crypto_alloc_aead"},
	}
	for _, tg := range targets {
		prog := coll.Programs[tg.progName]
		if prog == nil {
			failed++
			continue
		}
		l, err := link.Kprobe(tg.sym, prog, nil)
		if err != nil {
			failed++
			continue
		}
		closers = append(closers, l)
		attached++
	}
	return attached, failed, closers
}

// binaryPathForEvent chooses the path label for aggregation based on LibID.
// Uprobe events do not carry the source library path in the event struct —
// we rely on the first-mapped library-path we know for that LibID. For PR #1
// we collapse all uprobe events of a given LibID onto a single representative
// path (first seen); this simplifies aggregation at the cost of losing
// per-library attribution when multiple copies exist. Acceptable for v1;
// revisit when per-PID findings land.
func binaryPathForEvent(ev Event) string {
	if ev.Source == SourceKprobe {
		return "kernel"
	}
	switch ev.LibID {
	case LibLibcrypto:
		return "libcrypto"
	case LibGnuTLS:
		return "libgnutls"
	case LibNSS:
		return "libnss3"
	}
	return "unknown"
}
