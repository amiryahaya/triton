package ebpftrace

// Aggregate is the collapsed observation for one (binary, algorithm, source) tuple.
type Aggregate struct {
	BinaryPath string
	Algorithm  string
	Family     string
	Library    string // "libcrypto.so.3" or "kernel"
	Source     Source
	Count      int
	PIDs       map[uint32]bool
	FirstPID   uint32
}

// Aggregator collects Events and emits per-tuple Aggregates on Flush().
// NOT goroutine-safe: callers MUST serialise all method calls (Add, Flush).
// Flush resets internal state, so concurrent Add + Flush produces undefined
// behaviour. The reader coordinator (program_linux.go) serialises by using
// a single goroutine for event consumption.
type Aggregator struct {
	buckets map[aggKey]*Aggregate
}

type aggKey struct {
	binary string
	algo   string
	source Source
}

// NewAggregator constructs an empty aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{buckets: map[aggKey]*Aggregate{}}
}

// Add folds an Event into the aggregator. Events that classify to no known
// algorithm (unknown NID + unknown kernel name) are silently dropped.
func (a *Aggregator) Add(ev Event, binaryPath string) {
	info, ok := classifyEvent(ev)
	if !ok {
		return
	}
	key := aggKey{binary: binaryPath, algo: info.Algorithm, source: ev.Source}
	ag := a.buckets[key]
	if ag == nil {
		ag = &Aggregate{
			BinaryPath: binaryPath,
			Algorithm:  info.Algorithm,
			Family:     info.Family,
			Library:    info.Library,
			Source:     ev.Source,
			PIDs:       map[uint32]bool{},
			FirstPID:   ev.PID,
		}
		a.buckets[key] = ag
	}
	ag.Count++
	ag.PIDs[ev.PID] = true
}

// Flush returns every aggregate and resets internal state.
func (a *Aggregator) Flush() []Aggregate {
	out := make([]Aggregate, 0, len(a.buckets))
	for _, ag := range a.buckets {
		out = append(out, *ag)
	}
	a.buckets = map[aggKey]*Aggregate{}
	return out
}

// classifyEvent resolves an Event to AlgoInfo via the NID table or kernel registry.
func classifyEvent(ev Event) (AlgoInfo, bool) {
	if ev.Source == SourceKprobe {
		return ResolveKernelAlgo(ev.Name)
	}
	// Uprobe path: resolve NID, or fall back to special sentinels.
	if info, ok := ResolveNID(ev.NID); ok {
		return info, true
	}
	// Sentinels used by C source for constant-inferred probes (see bpf/crypto.c):
	switch ev.NID {
	case -2:
		return AlgoInfo{Algorithm: "TLS", Family: "TLS", Library: "libcrypto"}, true
	case -3:
		return AlgoInfo{Algorithm: "Verify", Family: "Signature", Library: "libgnutls"}, true
	case -4:
		return AlgoInfo{Algorithm: "Cipher", Family: "Cipher", Library: "libnss3"}, true
	case -5:
		return AlgoInfo{Algorithm: "Digest", Family: "Hash", Library: "libnss3"}, true
	case -7:
		return AlgoInfo{Algorithm: "KEX", Family: "ECDH", Library: "libcrypto"}, true
	}
	return AlgoInfo{}, false
}
