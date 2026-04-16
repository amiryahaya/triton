// Package discovery implements the engine-side network discovery
// scanner and worker. The scanner expands operator-supplied CIDRs into
// host addresses and probes each (address, port) pair with a bounded
// TCP connect; the worker long-polls the portal for jobs, drives the
// scanner, and streams candidates back.
package discovery

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// maxAddressesPerCIDR caps how many addresses a single CIDR can
// expand to. A /16 (65,536 addresses) is the largest block we're
// willing to probe in one job — anything larger almost certainly
// represents operator error and would flood the network.
const maxAddressesPerCIDR = 65536

// maxAddressesTotal caps the total address count across all CIDRs in
// one job. Without this, an operator could submit e.g. 50 × /16 and
// blow past the per-CIDR cap cumulatively, expanding to ~3.2M entries
// and OOMing the engine. 262,144 = 4 × /16, generous enough for real
// multi-subnet audits while preventing runaway expansions.
const maxAddressesTotal = 262144

// Candidate is a host the scanner confirmed responsive on at least
// one of the requested ports. Address is the dotted-quad / IPv6
// string form so the worker can trivially JSON-encode it.
type Candidate struct {
	Address   string
	Hostname  string
	OpenPorts []int
}

// Scanner probes networks for open TCP ports. Zero-value Scanner uses
// production defaults (500ms dial timeout, 128 workers).
type Scanner struct {
	DialTimeout time.Duration
	Workers     int
}

// PingSweep sends ICMP echo requests to all addresses in the given
// CIDRs and returns the addresses that responded. Requires CAP_NET_RAW
// on Linux. Falls back to TCP-connect on port 80 if ICMP fails (no
// permissions).
func (s *Scanner) PingSweep(ctx context.Context, cidrs []string) ([]Candidate, error) {
	addrs, err := expandCIDRs(cidrs)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, nil
	}

	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = 1 * time.Second
	}
	workers := s.Workers
	if workers <= 0 {
		workers = 128
	}

	// Try ICMP first; if no permission, log and fall back to TCP:80.
	alive, err := s.icmpSweep(ctx, addrs, timeout, workers)
	if err != nil {
		log.Printf("ICMP ping failed (%v) — falling back to TCP:80 probe", err)
		return s.Scan(ctx, cidrs, []int{80})
	}

	out := make([]Candidate, 0, len(alive))
	for _, addr := range alive {
		out = append(out, Candidate{Address: addr})
	}
	return out, nil
}

// icmpSweep sends ICMP echo requests to all addrs and collects
// replies. Returns an error if the ICMP socket cannot be opened
// (e.g. missing CAP_NET_RAW), signalling the caller to fall back.
func (s *Scanner) icmpSweep(ctx context.Context, addrs []string, timeout time.Duration, workers int) ([]string, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("icmp listen: %w (need CAP_NET_RAW)", err)
	}
	defer conn.Close() //nolint:errcheck // best-effort close on ICMP socket

	// Give 2× single-host timeout for the full sweep, but respect
	// the parent context deadline if it's tighter.
	sweepDeadline := time.Now().Add(timeout * 2)
	if dl, ok := ctx.Deadline(); ok && dl.Before(sweepDeadline) {
		sweepDeadline = dl
	}
	_ = conn.SetReadDeadline(sweepDeadline)

	// Sender: fan out ICMP echo requests.
	var mu sync.Mutex
	alive := map[string]bool{}

	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, addr := range addrs {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(seq int, target string) {
			defer wg.Done()
			defer func() { <-sem }()

			dst, resolveErr := net.ResolveIPAddr("ip4", target)
			if resolveErr != nil {
				return
			}

			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   os.Getpid() & 0xffff,
					Seq:  seq,
					Data: []byte("triton-ping"),
				},
			}
			b, marshalErr := msg.Marshal(nil)
			if marshalErr != nil {
				return
			}
			_, _ = conn.WriteTo(b, dst)
		}(i, addr)
	}
	wg.Wait()

	// Receiver: read replies until deadline.
	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		n, peer, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			break // timeout or ctx cancelled
		}
		parsed, parseErr := icmp.ParseMessage(1, buf[:n]) // protocol 1 = ICMPv4
		if parseErr != nil {
			continue
		}
		if parsed.Type == ipv4.ICMPTypeEchoReply {
			mu.Lock()
			alive[peer.String()] = true
			mu.Unlock()
		}
	}

	out := make([]string, 0, len(alive))
	for addr := range alive {
		out = append(out, addr)
	}
	return out, nil
}

// Scan expands cidrs to host addresses, probes each (addr, port)
// pair with a TCP connect, and returns one Candidate per address
// that had at least one open port. If ports is empty, delegates to
// PingSweep for ICMP-based host discovery.
//
// Implementation is deliberately simple: one host at a time,
// all ports per host, then next host. No goroutine pools, no
// channels, no race conditions. A /24 × 6 ports takes ~5 min
// (254 hosts × 6 ports × ~130ms avg per unreachable host).
func (s *Scanner) Scan(ctx context.Context, cidrs []string, ports []int) ([]Candidate, error) {
	if len(ports) == 0 {
		return s.PingSweep(ctx, cidrs)
	}

	addrs, err := expandCIDRs(cidrs)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, nil
	}

	dialTimeout := s.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second
	}

	log.Printf("scanner: scanning %d hosts × %d ports (%s timeout per probe)",
		len(addrs), len(ports), dialTimeout)

	dialer := &net.Dialer{Timeout: dialTimeout}
	var out []Candidate

	for _, addr := range addrs {
		if ctx.Err() != nil {
			break
		}

		var openPorts []int
		for _, port := range ports {
			if ctx.Err() != nil {
				break
			}
			target := net.JoinHostPort(addr, strconv.Itoa(port))
			conn, err := dialer.DialContext(ctx, "tcp", target)
			if err != nil {
				continue
			}
			_ = conn.Close()
			openPorts = append(openPorts, port)
		}

		if len(openPorts) > 0 {
			log.Printf("scanner: found %s with ports %v", addr, openPorts)
			out = append(out, Candidate{Address: addr, OpenPorts: openPorts})
		}
	}

	log.Printf("scanner: done — %d candidates from %d hosts", len(out), len(addrs))
	return out, nil
}

// expandCIDRs walks each CIDR and returns the full list of host
// addresses. For IPv4 blocks with a mask of /30 or larger (i.e.
// smaller than /30), the network and broadcast addresses are skipped
// per RFC 3021. For /31 and /32 every address is usable. IPv6 blocks
// include all addresses unchanged.
func expandCIDRs(cidrs []string) ([]string, error) {
	var out []string
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}

		ones, bits := ipnet.Mask.Size()
		isV4 := bits == 32
		skipNetBcast := isV4 && ones <= 30

		// Pre-count with the cap check so we don't start allocating a
		// /8 before noticing it's huge.
		hostBits := bits - ones
		var count uint64
		if hostBits >= 64 {
			count = maxAddressesPerCIDR + 1 // definitely too large
		} else {
			count = uint64(1) << uint(hostBits)
		}
		if skipNetBcast && count >= 2 {
			count -= 2
		}
		if count > maxAddressesPerCIDR {
			return nil, fmt.Errorf("CIDR %q expands to %d addresses, exceeds cap of %d", c, count, maxAddressesPerCIDR)
		}
		if uint64(len(out))+count > maxAddressesTotal {
			return nil, fmt.Errorf("total addresses exceed cap %d across all CIDRs", maxAddressesTotal)
		}

		start := ipnet.IP
		if isV4 {
			start = start.To4()
		}
		ip := make(net.IP, len(start))
		copy(ip, start)

		first := true
		for ipnet.Contains(ip) {
			// For /30 and larger IPv4 blocks, skip the network address
			// on the first iteration and break before the broadcast.
			if skipNetBcast && first {
				first = false
				incIP(ip)
				continue
			}
			first = false

			// Peek ahead: if the next address would fall outside the
			// block AND we're skipping broadcasts, this one is the
			// broadcast and should be dropped.
			if skipNetBcast {
				next := make(net.IP, len(ip))
				copy(next, ip)
				incIP(next)
				if !ipnet.Contains(next) {
					break
				}
			}

			out = append(out, ip.String())
			incIP(ip)
		}
	}
	return out, nil
}

// incIP adds 1 to ip in place, treating it as a big-endian integer.
// Overflow wraps silently — callers are expected to bound the loop
// with ipnet.Contains.
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
