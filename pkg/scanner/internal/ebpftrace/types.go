// Package ebpftrace observes live crypto calls via eBPF uprobes and kprobes.
// Linux-only (see program_linux.go); the package compiles on all platforms
// but Run() is unavailable on non-Linux.
package ebpftrace

import "time"

// Source discriminates the eBPF probe family that produced an event.
type Source uint8

const (
	SourceUnknown Source = 0
	SourceUprobe  Source = 1
	SourceKprobe  Source = 2
)

// LibID discriminates the userspace library for uprobe events.
type LibID uint8

const (
	LibUnknown   LibID = 0
	LibLibcrypto LibID = 1
	LibGnuTLS    LibID = 2
	LibNSS       LibID = 3
	LibKernel    LibID = 4
)

// Event is one observed crypto call, decoded from the eBPF ring buffer.
type Event struct {
	PID uint32
	UID uint32
	// TS is the wall-clock time (converted from bpf_ktime_get_ns). Monotonic
	// reading is lost; do not use for duration math between events. For
	// in-window ordering, events are emitted in read-order.
	TS     time.Time
	Source Source
	LibID  LibID
	NID    int32  // -1 if string-based (kernel path)
	Name   string // kernel-crypto string; "" for NID path
	Comm   string // /proc/PID/comm snapshot at trace time
}

// Options configures a single Run() invocation.
type Options struct {
	Window      time.Duration
	SkipUprobes bool
	SkipKprobes bool
}

// Outcome is the result of a Run.
type Outcome struct {
	Aggregates     []Aggregate
	Window         time.Duration
	StartedAt      time.Time
	EventsObserved int
	DecodeErrors   int
	ProbesAttached int
	ProbesFailed   int
}

// AlgoInfo is the classified result of a crypto observation.
type AlgoInfo struct {
	Algorithm string
	Family    string
	Library   string
}

// uprobeTarget describes one uprobe attach request (package-internal).
type uprobeTarget struct {
	LibID       LibID
	SymbolName  string
	ProgName    string // eBPF program section, e.g. "uprobe/EVP_CipherInit_ex"
	ArgIdx      uint8  // which PARM to read the NID/enum from (0 = constant)
	ConstAlgo   string // used when ArgIdx == 0
	ConstFamily string
}
