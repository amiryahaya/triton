package discovery

import (
	"context"
	"net"
	"strconv"
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

// Scanner expands a CIDR and probes each IP for open ports.
type Scanner struct {
	Dialer   Dialer
	Resolver Resolver
	// MaxConcurrency limits simultaneous goroutines (default 200).
	MaxConcurrency int
	// DialTimeout is the per-port connection timeout (default 1.5s).
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

// Scan expands cidr, probes each host for open ports, and sends live
// Candidates to out. It closes out before returning.
func (s *Scanner) Scan(ctx context.Context, cidr string, ports []int, out chan<- Candidate) error {
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

	for _, ip := range ips {
		ipStr := ip.String()

		wg.Add(1)
		sem <- struct{}{}

		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Probe each port.
			var openPorts []int
			for _, port := range ports {
				addr := net.JoinHostPort(ipStr, strconv.Itoa(port))
				dialCtx, cancel := context.WithTimeout(ctx, s.DialTimeout)
				conn, dialErr := s.Dialer.DialContext(dialCtx, "tcp", addr)
				cancel()
				if dialErr == nil {
					conn.Close()
					openPorts = append(openPorts, port)
				}
			}

			// Skip dead hosts.
			if len(openPorts) == 0 {
				return
			}

			// Reverse DNS — failure is non-fatal.
			var hostname *string
			dnsCtx, dnsCancel := context.WithTimeout(ctx, s.DNSTimeout)
			names, dnsErr := s.Resolver.LookupAddr(dnsCtx, ipStr)
			dnsCancel()
			if dnsErr == nil && len(names) > 0 {
				name := names[0]
				hostname = &name
			}

			out <- Candidate{
				IP:        ipStr,
				Hostname:  hostname,
				OpenPorts: openPorts,
			}
		}(ipStr)
	}

	wg.Wait()
	close(out)
	return nil
}

// ScannerIface is the interface implemented by *Scanner. Extracted so
// Worker can accept a test double without duplicating its Run logic.
type ScannerIface interface {
	Scan(ctx context.Context, cidr string, ports []int, out chan<- Candidate) error
}

// expandCIDR returns all usable host IPs in the network (excluding network
// address and broadcast address for IPv4).
func expandCIDR(ipNet *net.IPNet) []net.IP {
	// Prefer 4-byte form for IPv4 so mask arithmetic is consistent.
	base := ipNet.IP.To4()
	if base == nil {
		base = ipNet.IP.To16()
	}
	ip := cloneIP(base)

	var ips []net.IP
	for {
		if !ipNet.Contains(ip) {
			break
		}
		if !isNetworkAddr(ip, ipNet) && !isBroadcastAddr(ip, ipNet) {
			ips = append(ips, cloneIP(ip))
		}
		if !incrementIP(ip) {
			break
		}
	}
	return ips
}

// cloneIP returns a copy of an IP so mutations don't alias the original.
func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// incrementIP increments ip in place (big-endian). Returns false on overflow.
func incrementIP(ip net.IP) bool {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return true
		}
	}
	return false // wrapped all the way around
}

// isNetworkAddr returns true if ip equals the network address (all host bits zero).
func isNetworkAddr(ip net.IP, ipNet *net.IPNet) bool {
	return ip.Equal(ipNet.IP.To4()) || ip.Equal(ipNet.IP.To16())
}

// isBroadcastAddr returns true if ip is the IPv4 broadcast (all host bits one).
// IPv6 has no broadcast; always returns false for IPv6.
func isBroadcastAddr(ip net.IP, ipNet *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	mask := ipNet.Mask
	if len(mask) == 16 {
		mask = mask[12:] // trim to 4-byte mask for IPv4-in-IPv6
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
