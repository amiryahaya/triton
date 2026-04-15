package discovery

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// listenLocal opens a TCP listener on 127.0.0.1:0 and returns the
// listener + the chosen port. The caller is responsible for closing.
func listenLocal(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("splithostport: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	return ln, port
}

func TestScanner_DetectsOpenPort(t *testing.T) {
	ln, openPort := listenLocal(t)
	defer func() { _ = ln.Close() }()

	s := &Scanner{DialTimeout: 100 * time.Millisecond, Workers: 4}
	got, err := s.Scan(context.Background(), []string{"127.0.0.1/32"}, []int{openPort, openPort + 1})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("candidates = %d, want 1: %+v", len(got), got)
	}
	if got[0].Address != "127.0.0.1" {
		t.Errorf("address = %q, want 127.0.0.1", got[0].Address)
	}
	if len(got[0].OpenPorts) != 1 || got[0].OpenPorts[0] != openPort {
		t.Errorf("OpenPorts = %v, want [%d]", got[0].OpenPorts, openPort)
	}
}

func TestScanner_MultipleOpenPorts(t *testing.T) {
	ln1, p1 := listenLocal(t)
	defer func() { _ = ln1.Close() }()
	ln2, p2 := listenLocal(t)
	defer func() { _ = ln2.Close() }()

	s := &Scanner{DialTimeout: 100 * time.Millisecond, Workers: 4}
	got, err := s.Scan(context.Background(), []string{"127.0.0.1/32"}, []int{p1, p2})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("candidates = %d, want 1", len(got))
	}
	seen := map[int]bool{}
	for _, p := range got[0].OpenPorts {
		seen[p] = true
	}
	if !seen[p1] || !seen[p2] {
		t.Errorf("OpenPorts = %v, want both %d and %d", got[0].OpenPorts, p1, p2)
	}
}

func TestScanner_ClosedPorts_NoCandidate(t *testing.T) {
	// Bind a listener to claim a port, then close it so we know the
	// port is free. Racy in theory, safe enough in practice — the
	// kernel won't immediately reassign it inside this test.
	ln, port := listenLocal(t)
	_ = ln.Close()

	s := &Scanner{DialTimeout: 100 * time.Millisecond, Workers: 4}
	got, err := s.Scan(context.Background(), []string{"127.0.0.1/32"}, []int{port})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("candidates = %d, want 0: %+v", len(got), got)
	}
}

func TestScanner_CIDRTooLarge_Errors(t *testing.T) {
	s := &Scanner{}
	_, err := s.Scan(context.Background(), []string{"10.0.0.0/8"}, []int{80})
	if err == nil {
		t.Fatalf("expected error for /8 CIDR")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("error = %v, want cap-related message", err)
	}
}

func TestScanner_InvalidCIDR_Errors(t *testing.T) {
	s := &Scanner{}
	_, err := s.Scan(context.Background(), []string{"not-a-cidr"}, []int{80})
	if err == nil {
		t.Fatalf("expected error for invalid CIDR")
	}
}

func TestScanner_ContextCancellation(t *testing.T) {
	s := &Scanner{DialTimeout: 2 * time.Second, Workers: 32}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Cancel after 100ms; scan should return promptly.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	// 10.99.99.0/24 is (likely) unroutable here; TCP connect attempts
	// will hang to DialTimeout. Cancellation must unblock faster than
	// that.
	_, _ = s.Scan(ctx, []string{"10.99.99.0/24"}, []int{9999})
	elapsed := time.Since(start)
	if elapsed > 1500*time.Millisecond {
		t.Errorf("Scan took %v after cancel, want <1.5s", elapsed)
	}
}

func TestScanner_TotalAddressesCap_Errors(t *testing.T) {
	// Five /16 blocks: each passes the per-CIDR cap of 65,536, but the
	// total (~327k) should trip maxAddressesTotal (262,144).
	cidrs := []string{
		"10.0.0.0/16",
		"10.1.0.0/16",
		"10.2.0.0/16",
		"10.3.0.0/16",
		"10.4.0.0/16",
	}
	_, err := expandCIDRs(cidrs)
	if err == nil {
		t.Fatalf("expected error for 5 × /16 total exceeding cap")
	}
	if !strings.Contains(err.Error(), "total addresses") {
		t.Errorf("error = %v, want total-addresses cap message", err)
	}
}

func TestExpandCIDRs_SkipsNetworkAndBroadcast(t *testing.T) {
	got, err := expandCIDRs([]string{"192.168.1.0/30"})
	if err != nil {
		t.Fatalf("expandCIDRs: %v", err)
	}
	// /30 = 4 addresses; skip .0 and .3; expect .1 and .2.
	want := []string{"192.168.1.1", "192.168.1.2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExpandCIDRs_Slash32IncludesAddress(t *testing.T) {
	got, err := expandCIDRs([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("expandCIDRs: %v", err)
	}
	if len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("got %v, want [127.0.0.1]", got)
	}
}
