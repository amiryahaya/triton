// Package discovery implements the engine-side network discovery
// scanner and worker. The scanner expands operator-supplied CIDRs into
// host addresses and probes each (address, port) pair with a bounded
// TCP connect; the worker long-polls the portal for jobs, drives the
// scanner, and streams candidates back.
package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// maxAddressesPerCIDR caps how many addresses a single CIDR can
// expand to. A /16 (65,536 addresses) is the largest block we're
// willing to probe in one job — anything larger almost certainly
// represents operator error and would flood the network.
const maxAddressesPerCIDR = 65536

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

// probe is a single (address, port) unit of work fanned out over the
// worker pool.
type probe struct {
	address string
	port    int
}

// result is a worker's verdict for a single probe. Only "open"
// results are forwarded to the collector; closed ports are dropped
// at the worker to keep channel traffic low.
type result struct {
	address string
	port    int
}

// Scan expands cidrs to host addresses, probes each (addr, port)
// pair with a TCP connect, and returns one Candidate per address
// that had at least one open port. Per-CIDR expansion is capped at
// maxAddressesPerCIDR; exceeding the cap returns an error without
// probing anything.
func (s *Scanner) Scan(ctx context.Context, cidrs []string, ports []int) ([]Candidate, error) {
	addrs, err := expandCIDRs(cidrs)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 || len(ports) == 0 {
		return nil, nil
	}

	dialTimeout := s.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 500 * time.Millisecond
	}
	workers := s.Workers
	if workers <= 0 {
		workers = 128
	}

	probes := make(chan probe)
	results := make(chan result, workers)

	dialer := &net.Dialer{Timeout: dialTimeout}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range probes {
				if ctx.Err() != nil {
					return
				}
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(p.address, strconv.Itoa(p.port)))
				if err != nil {
					continue
				}
				_ = conn.Close()
				select {
				case results <- result(p):
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Feeder: emits every (addr, port) pair then closes the probes
	// channel so workers exit. Respects ctx cancellation.
	go func() {
		defer close(probes)
		for _, a := range addrs {
			for _, port := range ports {
				select {
				case probes <- probe{address: a, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Closer: wait for workers to drain, then close results so the
	// collector loop below can terminate.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Single-goroutine collector — no mutex needed.
	byAddr := make(map[string]*Candidate)
	var order []string
	for r := range results {
		c, ok := byAddr[r.address]
		if !ok {
			c = &Candidate{Address: r.address}
			byAddr[r.address] = c
			order = append(order, r.address)
		}
		c.OpenPorts = append(c.OpenPorts, r.port)
	}

	out := make([]Candidate, 0, len(order))
	for _, a := range order {
		out = append(out, *byAddr[a])
	}
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
