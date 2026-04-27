package discovery

import (
	"context"
	"net"
	"sort"
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

// Scanner expands a CIDR and probes each IP for open ports.
type Scanner struct {
	Dialer   Dialer
	Resolver Resolver
	// MaxConcurrency limits simultaneous IP-level goroutines (default 2000).
	MaxConcurrency int
	// DialTimeout is the per-port TCP connect timeout (default 150ms — suitable
	// for LAN where RTT is sub-millisecond; raise for WAN targets).
	DialTimeout time.Duration
	// DNSTimeout is the per-IP reverse-DNS timeout (default 3s).
	DNSTimeout time.Duration
	// BannerTimeout is how long to wait for the SSH banner read (default 500ms).
	BannerTimeout time.Duration
}

// NewScanner returns a Scanner with production defaults.
func NewScanner() *Scanner {
	return &Scanner{
		Dialer:         &net.Dialer{},
		Resolver:       net.DefaultResolver,
		MaxConcurrency: 2000,
		DialTimeout:    150 * time.Millisecond,
		DNSTimeout:     3 * time.Second,
		BannerTimeout:  500 * time.Millisecond,
	}
}

// Scan expands cidr, probes each host concurrently for open ports, and
// sends live Candidates to out. All ports for a given IP are dialled in
// parallel so unreachable hosts pay one DialTimeout, not N_ports×DialTimeout.
// Scan closes out before returning.
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

			// Probe all ports concurrently so a dead host pays one timeout, not N×timeout.
			// The port-22 connection is kept alive for SSH banner reading (OS detection).
			type portResult struct {
				port int
				open bool
				conn net.Conn // non-nil only for port 22, caller must close
			}
			portCh := make(chan portResult, len(ports))
			var portWg sync.WaitGroup
			for _, port := range ports {
				portWg.Add(1)
				go func(p int) {
					defer portWg.Done()
					addr := net.JoinHostPort(ipStr, strconv.Itoa(p))
					dialCtx, cancel := context.WithTimeout(ctx, s.DialTimeout)
					conn, err := s.Dialer.DialContext(dialCtx, "tcp", addr)
					cancel()
					if err != nil {
						portCh <- portResult{port: p, open: false}
						return
					}
					if p == 22 {
						portCh <- portResult{port: p, open: true, conn: conn} // keep alive for banner
					} else {
						_ = conn.Close()
						portCh <- portResult{port: p, open: true}
					}
				}(port)
			}
			portWg.Wait()
			close(portCh)

			var openPorts []int
			var sshConn net.Conn
			for r := range portCh {
				if r.open {
					openPorts = append(openPorts, r.port)
					if r.conn != nil {
						sshConn = r.conn
					}
				}
			}
			sort.Ints(openPorts)

			// Skip dead hosts.
			if len(openPorts) == 0 {
				if sshConn != nil {
					_ = sshConn.Close()
				}
				return
			}

			// OS detection using SSH banner or port heuristics.
			osName := s.detectOS(sshConn, openPorts)
			if sshConn != nil {
				_ = sshConn.Close()
			}

			// MAC address from ARP cache (populated by our TCP probes above).
			macAddr := lookupMAC(ipStr)

			// mDNS name — unicast PTR query to the host's port 5353.
			mdnsCtx, mdnsCancel := context.WithTimeout(ctx, s.DNSTimeout)
			mdnsName := lookupMDNS(mdnsCtx, ipStr, s.DNSTimeout)
			mdnsCancel()

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
				IP:         ipStr,
				Hostname:   hostname,
				OpenPorts:  openPorts,
				OS:         osName,
				MACAddress: macAddr,
				MDNSName:   mdnsName,
			}
		}(ipStr)
	}

	wg.Wait()
	close(out)
	return nil
}

// detectOS infers the host OS from an open SSH connection's banner
// or from the set of open ports when SSH is unavailable.
func (s *Scanner) detectOS(sshConn net.Conn, openPorts []int) string {
	if sshConn != nil {
		banner := s.readBanner(sshConn)
		if os := parseSSHBanner(banner); os != "" {
			return os
		}
		if strings.HasPrefix(banner, "SSH-") {
			return "Linux" // SSH open but no distro in banner → still Linux/Unix
		}
	}
	for _, p := range openPorts {
		switch p {
		case 5555:
			return "Android TV" // ADB port — specific to Android devices
		case 8008, 8009:
			return "Smart TV (Cast)" // Google Cast — Android TV / Chromecast
		case 3389, 5985, 5986:
			return "Windows"
		}
	}
	return ""
}

// readBanner reads the first 256 bytes from conn with BannerTimeout deadline.
func (s *Scanner) readBanner(conn net.Conn) string {
	timeout := s.BannerTimeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return strings.TrimRight(string(buf[:n]), "\r\n ")
}

// parseSSHBanner extracts a human-readable OS name from an SSH banner string.
// Returns "" if the banner is not an SSH banner or carries no distro hint.
func parseSSHBanner(banner string) string {
	if !strings.HasPrefix(banner, "SSH-") {
		return ""
	}
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "ubuntu"):
		return "Ubuntu"
	case strings.Contains(b, "debian"):
		return "Debian"
	case strings.Contains(b, "raspbian"):
		return "Raspberry Pi OS"
	case strings.Contains(b, "centos"):
		return "CentOS"
	case strings.Contains(b, "rhel"), strings.Contains(b, "red hat"):
		return "RHEL"
	case strings.Contains(b, "fedora"):
		return "Fedora"
	case strings.Contains(b, "suse"):
		return "openSUSE"
	case strings.Contains(b, "alpine"):
		return "Alpine Linux"
	case strings.Contains(b, "arch"):
		return "Arch Linux"
	case strings.Contains(b, "freebsd"):
		return "FreeBSD"
	case strings.Contains(b, "openbsd"):
		return "OpenBSD"
	case strings.Contains(b, "netbsd"):
		return "NetBSD"
	case strings.Contains(b, "windows"):
		return "Windows"
	default:
		return ""
	}
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
