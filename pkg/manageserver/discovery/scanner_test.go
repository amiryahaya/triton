//go:build !integration

package discovery

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----- mock Dialer -----

// acceptDialer accepts connections to a specific set of "ip:port" pairs and
// rejects everything else.
type acceptDialer struct {
	// accept is a set of "ip:port" strings that should succeed.
	accept map[string]bool
	// blockDuration, if > 0, makes each dial sleep before returning.
	blockDuration time.Duration
	// goroutineCounter is incremented while the dial is in-flight (optional).
	goroutineCounter *atomic.Int64
}

func (d *acceptDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.goroutineCounter != nil {
		d.goroutineCounter.Add(1)
		defer d.goroutineCounter.Add(-1)
	}
	if d.blockDuration > 0 {
		select {
		case <-time.After(d.blockDuration):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if d.accept[addr] {
		// Return a trivial loopback conn pair.
		c1, _ := net.Pipe()
		return c1, nil
	}
	return nil, errors.New("connection refused")
}

// rejectDialer refuses every connection immediately.
type rejectDialer struct{}

func (rejectDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, errors.New("connection refused")
}

// ----- mock Resolver -----

// fixedResolver always returns the same names (or error).
type fixedResolver struct {
	names []string
	err   error
}

func (r *fixedResolver) LookupAddr(_ context.Context, _ string) ([]string, error) {
	return r.names, r.err
}

// ----- helpers -----

func collectCandidates(out <-chan Candidate) []Candidate {
	var cs []Candidate
	for c := range out {
		cs = append(cs, c)
	}
	return cs
}

// ----- tests -----

// TestLiveHostDetected verifies that a host with at least one open port is
// emitted as a Candidate.
func TestLiveHostDetected(t *testing.T) {
	t.Parallel()

	dialer := &acceptDialer{
		accept: map[string]bool{
			net.JoinHostPort("192.168.1.1", strconv.Itoa(22)): true,
		},
	}
	s := &Scanner{
		Dialer:         dialer,
		Resolver:       &fixedResolver{names: []string{"host.local."}},
		MaxConcurrency: 20,
		DialTimeout:    100 * time.Millisecond,
		DNSTimeout:     100 * time.Millisecond,
	}

	out := make(chan Candidate, 16)
	err := s.Scan(context.Background(), "192.168.1.0/30", []int{22, 80}, out)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	candidates := collectCandidates(out)
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	c := candidates[0]
	if c.IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", c.IP)
	}
	found22 := false
	for _, p := range c.OpenPorts {
		if p == 22 {
			found22 = true
		}
	}
	if !found22 {
		t.Errorf("expected port 22 in OpenPorts, got %v", c.OpenPorts)
	}
}

// TestDeadHostNotEmitted verifies that hosts with no open ports produce no
// Candidates.
func TestDeadHostNotEmitted(t *testing.T) {
	t.Parallel()

	s := &Scanner{
		Dialer:         rejectDialer{},
		Resolver:       &fixedResolver{names: []string{"host.local."}},
		MaxConcurrency: 20,
		DialTimeout:    50 * time.Millisecond,
		DNSTimeout:     50 * time.Millisecond,
	}

	out := make(chan Candidate, 16)
	err := s.Scan(context.Background(), "192.168.1.0/30", []int{22, 80}, out)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	candidates := collectCandidates(out)
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates, got %d: %v", len(candidates), candidates)
	}
}

// TestDNSFailureSetNilHostname verifies that a DNS lookup failure leaves
// Candidate.Hostname nil but does not abort the scan.
func TestDNSFailureSetNilHostname(t *testing.T) {
	t.Parallel()

	dialer := &acceptDialer{
		accept: map[string]bool{
			net.JoinHostPort("192.168.1.1", strconv.Itoa(22)): true,
		},
	}
	s := &Scanner{
		Dialer:         dialer,
		Resolver:       &fixedResolver{err: errors.New("lookup failed")},
		MaxConcurrency: 20,
		DialTimeout:    100 * time.Millisecond,
		DNSTimeout:     100 * time.Millisecond,
	}

	out := make(chan Candidate, 16)
	err := s.Scan(context.Background(), "192.168.1.0/30", []int{22}, out)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	candidates := collectCandidates(out)
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Hostname != nil {
		t.Errorf("expected nil Hostname on DNS failure, got %q", *candidates[0].Hostname)
	}
}

// TestNetworkBroadcastSkipped verifies that for 192.168.1.0/30 (4 addresses:
// .0 network, .1, .2, .3 broadcast) only .1 and .2 are emitted.
func TestNetworkBroadcastSkipped(t *testing.T) {
	t.Parallel()

	// Accept port 22 on ALL addresses (including network/broadcast) so that
	// if the scanner accidentally probes them they would be emitted.
	dialer := &acceptDialer{
		accept: map[string]bool{
			net.JoinHostPort("192.168.1.0", strconv.Itoa(22)): true,
			net.JoinHostPort("192.168.1.1", strconv.Itoa(22)): true,
			net.JoinHostPort("192.168.1.2", strconv.Itoa(22)): true,
			net.JoinHostPort("192.168.1.3", strconv.Itoa(22)): true,
		},
	}
	s := &Scanner{
		Dialer:         dialer,
		Resolver:       &fixedResolver{names: []string{"host.local."}},
		MaxConcurrency: 20,
		DialTimeout:    100 * time.Millisecond,
		DNSTimeout:     100 * time.Millisecond,
	}

	out := make(chan Candidate, 16)
	err := s.Scan(context.Background(), "192.168.1.0/30", []int{22}, out)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	candidates := collectCandidates(out)

	// Build a set of emitted IPs.
	emitted := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		emitted[c.IP] = true
	}

	if emitted["192.168.1.0"] {
		t.Error("network address 192.168.1.0 must not be emitted")
	}
	if emitted["192.168.1.3"] {
		t.Error("broadcast address 192.168.1.3 must not be emitted")
	}
	if !emitted["192.168.1.1"] {
		t.Error("host 192.168.1.1 should be emitted")
	}
	if !emitted["192.168.1.2"] {
		t.Error("host 192.168.1.2 should be emitted")
	}
	if len(candidates) != 2 {
		t.Errorf("expected exactly 2 candidates, got %d: %v", len(candidates), candidates)
	}
}

// TestConcurrencyLimit verifies that MaxConcurrency bounds the number of
// simultaneous IP-level goroutines. A single port (22) is used intentionally:
// with parallel port probing the total dial count is MaxConcurrency×len(ports),
// so using one port keeps the peak dial count equal to the IP goroutine count,
// making the semaphore assertion straightforward.
func TestConcurrencyLimit(t *testing.T) {
	t.Parallel()

	const maxConcurrency = 5
	var peak atomic.Int64
	var current atomic.Int64

	dialer := &acceptDialer{
		blockDuration: 10 * time.Millisecond,
		// Accept port 22 on the whole /24 — we build the set lazily below.
	}
	// Pre-populate all 254 host addresses for the /24.
	dialer.accept = make(map[string]bool, 254)
	for i := 1; i <= 254; i++ {
		addr := net.JoinHostPort("10.0.0."+strconv.Itoa(i), strconv.Itoa(22))
		dialer.accept[addr] = true
	}

	// Wrap with a peak-tracking dialer.
	peakDialer := &peakTrackingDialer{
		inner:   dialer,
		current: &current,
		peak:    &peak,
	}

	s := &Scanner{
		Dialer:         peakDialer,
		Resolver:       &fixedResolver{names: []string{"host.local."}},
		MaxConcurrency: maxConcurrency,
		DialTimeout:    200 * time.Millisecond,
		DNSTimeout:     50 * time.Millisecond,
	}

	out := make(chan Candidate, 512)
	err := s.Scan(context.Background(), "10.0.0.0/24", []int{22}, out)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	// Drain so the goroutine that closes out can finish.
	for range out {
	}

	got := peak.Load()
	// With a single port per IP, peak concurrent dials equals the number of
	// concurrent IP goroutines, which must not exceed maxConcurrency.
	if got > int64(maxConcurrency) {
		t.Errorf("peak concurrent dials = %d, want ≤ %d", got, maxConcurrency)
	}
}

// countingDialer invokes a user-supplied dial function and counts calls.
type countingDialer struct {
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

// TestParallelPortProbing verifies that all ports for a single IP are dialled
// concurrently. A dead host with 5 ports should complete in approximately one
// DialTimeout, not five.
func TestParallelPortProbing(t *testing.T) {
	t.Parallel()

	// A dead host with 5 ports should complete in approximately one DialTimeout,
	// not five. We verify this by checking wall-clock time.
	dialCount := atomic.Int32{}
	slowDialer := &countingDialer{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCount.Add(1)
			// Simulate a 50ms response — fast enough to be well under one
			// sequential chain (5×50ms = 250ms) but still measurable.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
			return nil, errors.New("refused")
		},
	}
	sc := &Scanner{
		Dialer:         slowDialer,
		Resolver:       &fixedResolver{err: errors.New("no dns")},
		MaxConcurrency: 10,
		DialTimeout:    200 * time.Millisecond,
		DNSTimeout:     time.Second,
	}
	ports := []int{22, 80, 443, 3389, 8080} // 5 ports
	out := make(chan Candidate, 10)
	start := time.Now()
	err := sc.Scan(context.Background(), "10.0.0.0/30", ports, out) // 2 host IPs
	elapsed := time.Since(start)
	require.NoError(t, err)

	// Sequential probing would take 2 hosts × 5 ports × 50ms = 500ms.
	// Parallel probing should complete in roughly 2 × 50ms = 100ms.
	// We use 300ms as the upper bound to allow for scheduling jitter.
	require.Less(t, elapsed, 300*time.Millisecond,
		"parallel port probing should complete in ~100ms, got %v", elapsed)
	assert.Equal(t, int32(10), dialCount.Load(), "should have dialled 2 IPs × 5 ports = 10 times")
}

// peakTrackingDialer wraps another Dialer and tracks peak concurrency.
type peakTrackingDialer struct {
	inner   Dialer
	current *atomic.Int64
	peak    *atomic.Int64
}

func (d *peakTrackingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	cur := d.current.Add(1)
	defer d.current.Add(-1)

	// Update peak atomically using a compare-and-swap loop.
	for {
		old := d.peak.Load()
		if cur <= old {
			break
		}
		if d.peak.CompareAndSwap(old, cur) {
			break
		}
	}

	return d.inner.DialContext(ctx, network, addr)
}
