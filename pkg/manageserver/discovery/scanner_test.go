package discovery

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// mockDialer returns an open connection for allowed addresses, error for others.
type mockDialer struct {
	allowed map[string]bool // "ip:port"
}

func (m *mockDialer) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	if m.allowed[addr] {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	return nil, errors.New("connection refused")
}

// mockResolver returns a hostname for allowed IPs.
type mockResolver struct {
	names map[string]string // ip → hostname
}

func (m *mockResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if n, ok := m.names[addr]; ok {
		return []string{n}, nil
	}
	return nil, errors.New("not found")
}

func TestScanner_LiveHostFound(t *testing.T) {
	s := &Scanner{
		Dialer:         &mockDialer{allowed: map[string]bool{"10.0.0.1:22": true}},
		Resolver:       &mockResolver{names: map[string]string{"10.0.0.1": "host1.example.com."}},
		MaxConcurrency: 10,
		DialTimeout:    50 * time.Millisecond,
		DNSTimeout:     50 * time.Millisecond,
	}
	candidates := make(chan Candidate, 10)
	progress := make(chan struct{}, 10)

	err := s.Scan(context.Background(), "10.0.0.0/30", 22, candidates, progress)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	var found []Candidate
	for c := range candidates {
		found = append(found, c)
	}

	if len(found) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(found))
	}
	if found[0].IP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", found[0].IP)
	}
	if found[0].Hostname == nil || *found[0].Hostname != "host1.example.com" {
		t.Errorf("Hostname = %v, want host1.example.com", found[0].Hostname)
	}
}

func TestScanner_DeadHostNotEmitted(t *testing.T) {
	s := &Scanner{
		Dialer:         &mockDialer{allowed: map[string]bool{}},
		Resolver:       &mockResolver{},
		MaxConcurrency: 10,
		DialTimeout:    50 * time.Millisecond,
		DNSTimeout:     50 * time.Millisecond,
	}
	candidates := make(chan Candidate, 10)
	progress := make(chan struct{}, 10)

	err := s.Scan(context.Background(), "10.0.0.0/30", 22, candidates, progress)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	var found []Candidate
	for c := range candidates {
		found = append(found, c)
	}
	if len(found) != 0 {
		t.Errorf("expected 0 candidates, got %d", len(found))
	}
}

func TestScanner_DNSFailureSetsNilHostname(t *testing.T) {
	s := &Scanner{
		Dialer:         &mockDialer{allowed: map[string]bool{"10.0.0.1:2222": true}},
		Resolver:       &mockResolver{names: map[string]string{}},
		MaxConcurrency: 10,
		DialTimeout:    50 * time.Millisecond,
		DNSTimeout:     50 * time.Millisecond,
	}
	candidates := make(chan Candidate, 10)
	progress := make(chan struct{}, 10)

	err := s.Scan(context.Background(), "10.0.0.0/30", 2222, candidates, progress)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for c := range candidates {
		if c.Hostname != nil {
			t.Errorf("expected nil hostname when DNS fails, got %q", *c.Hostname)
		}
	}
}

func TestScanner_NetworkAndBroadcastSkipped(t *testing.T) {
	// 10.0.0.0/30 has exactly 2 usable hosts: 10.0.0.1 and 10.0.0.2.
	// 10.0.0.0 (network) and 10.0.0.3 (broadcast) must not be probed.
	s := &Scanner{
		Dialer:         &mockDialer{allowed: map[string]bool{}},
		Resolver:       &mockResolver{},
		MaxConcurrency: 10,
		DialTimeout:    50 * time.Millisecond,
		DNSTimeout:     50 * time.Millisecond,
	}
	candidates := make(chan Candidate, 10)
	progress := make(chan struct{}, 10)

	var progCount int
	done := make(chan struct{})
	go func() {
		for range progress {
			progCount++
		}
		close(done)
	}()

	err := s.Scan(context.Background(), "10.0.0.0/30", 22, candidates, progress)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for range candidates {
	}
	<-done

	if progCount != 2 {
		t.Errorf("progress ticks = %d, want 2 (network+broadcast not probed)", progCount)
	}
}

func TestScanner_ProgressCountMatchesHostsProbed(t *testing.T) {
	// /29 has 6 usable hosts; progress channel should receive exactly 6 sends.
	s := &Scanner{
		Dialer:         &mockDialer{allowed: map[string]bool{}},
		Resolver:       &mockResolver{},
		MaxConcurrency: 10,
		DialTimeout:    50 * time.Millisecond,
		DNSTimeout:     50 * time.Millisecond,
	}
	candidates := make(chan Candidate, 10)
	progress := make(chan struct{}, 10)

	var count int
	done := make(chan struct{})
	go func() {
		for range progress {
			count++
		}
		close(done)
	}()

	err := s.Scan(context.Background(), "10.0.0.0/29", 22, candidates, progress)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for range candidates {
	}
	<-done

	if count != 6 {
		t.Errorf("progress count = %d, want 6", count)
	}
}
