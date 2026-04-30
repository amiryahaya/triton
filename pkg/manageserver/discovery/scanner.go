package discovery

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dialer is a testable TCP connection factory.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Resolver is a testable reverse-DNS lookup abstraction.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Scanner expands a CIDR and probes each IP for an open SSH port.
type Scanner struct {
	Dialer   Dialer
	Resolver Resolver
	// MaxConcurrency limits simultaneous dial goroutines (default 200).
	MaxConcurrency int
	// DialTimeout is the per-probe TCP connect timeout (default 1.5s per spec).
	DialTimeout time.Duration
	// DNSTimeout is the per-IP reverse-DNS timeout (default 3s).
	DNSTimeout time.Duration
}

// NewScanner returns a Scanner with production defaults.
func NewScanner() *Scanner {
	return &Scanner{
		Dialer:         &net.Dialer{},
		Resolver:       net.DefaultResolver,
		MaxConcurrency: 200,
		DialTimeout:    1500 * time.Millisecond,
		DNSTimeout:     3 * time.Second,
	}
}

// ScannerIface is the interface implemented by *Scanner.
type ScannerIface interface {
	Scan(ctx context.Context, cidr string, sshPort int, candidates chan<- Candidate, progress chan<- struct{}) error
}

// Scan expands cidr, dials sshPort on each host concurrently, and sends
// Candidate values to candidates for every IP that accepts the connection.
// A struct{} is sent to progress for every IP probed (open or closed).
// Both channels are closed before Scan returns.
func (s *Scanner) Scan(ctx context.Context, cidr string, sshPort int, candidates chan<- Candidate, progress chan<- struct{}) error {
	defer close(candidates)
	defer close(progress)

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	ips := expandCIDR(ipNet)

	concurrency := s.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 200
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

loop:
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		ipStr := ip.String()

		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			break loop
		}

		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Always report progress for this IP, whether open or closed.
			defer func() {
				select {
				case progress <- struct{}{}:
				case <-ctx.Done():
				}
			}()

			addr := net.JoinHostPort(ipStr, strconv.Itoa(sshPort))
			dialCtx, cancel := context.WithTimeout(ctx, s.DialTimeout)
			conn, err := s.Dialer.DialContext(dialCtx, "tcp", addr)
			cancel()
			if err != nil {
				return // not a candidate — progress reported via defer
			}
			_ = conn.Close()

			// Reverse DNS — failure sets hostname to nil, never aborts scan.
			var hostname *string
			dnsCtx, dnsCancel := context.WithTimeout(ctx, s.DNSTimeout)
			names, dnsErr := s.Resolver.LookupAddr(dnsCtx, ipStr)
			dnsCancel()
			if dnsErr == nil && len(names) > 0 {
				name := strings.TrimSuffix(names[0], ".")
				hostname = &name
			}

			select {
			case candidates <- Candidate{IP: ipStr, Hostname: hostname}:
			case <-ctx.Done():
			}
		}(ipStr)
	}

	wg.Wait()
	return nil
}

// expandCIDR returns all usable host IPs in the network
// (excluding network address and broadcast address for IPv4).
func expandCIDR(ipNet *net.IPNet) []net.IP {
	base := ipNet.IP.To4()
	if base == nil {
		base = ipNet.IP.To16()
	}
	ip := cloneIP(base)

	var ips []net.IP
	for ipNet.Contains(ip) {
		if !isNetworkAddr(ip, ipNet) && !isBroadcastAddr(ip, ipNet) {
			ips = append(ips, cloneIP(ip))
		}
		if !incrementIP(ip) {
			break
		}
	}
	return ips
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incrementIP(ip net.IP) bool {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return true
		}
	}
	return false
}

func isNetworkAddr(ip net.IP, ipNet *net.IPNet) bool {
	return ip.Equal(ipNet.IP.To4()) || ip.Equal(ipNet.IP.To16())
}

func isBroadcastAddr(ip net.IP, ipNet *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	mask := ipNet.Mask
	if len(mask) == 16 {
		mask = mask[12:]
	}
	if len(mask) != 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		if ip4[i]&^mask[i] != ^mask[i]&0xff {
			return false
		}
	}
	return true
}
