// Package discovery implements the engine-side network discovery
// scanner and worker. Uses arp-scan for fast L2 host detection (~2s),
// with nmap fallback for port/service enrichment.
package discovery

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Candidate is a discovered host on the network.
type Candidate struct {
	Address    string
	Hostname   string
	OpenPorts  []int
	MACAddress string   // from ARP or nmap L2 detection
	MACVendor  string   // e.g. "Apple", "Raspberry Pi Foundation"
	Services   []string // e.g. ["ssh OpenSSH 8.9", "http nginx 1.24"]
}

// Scanner discovers hosts on the network. Uses arp-scan for fast L2
// discovery, nmap for port/service enrichment. Zero-value is ready to use.
type Scanner struct {
	ArpScanPath string // default: "arp-scan"
	NmapPath    string // default: "nmap"
}

func (s *Scanner) arpScanBin() string {
	if s.ArpScanPath != "" {
		return s.ArpScanPath
	}
	return "arp-scan"
}

func (s *Scanner) nmapBin() string {
	if s.NmapPath != "" {
		return s.NmapPath
	}
	return "nmap"
}

// Scan discovers hosts on the given CIDRs.
//
// Strategy:
//  1. Fast ARP sweep via arp-scan (~2-3s for a /24) → IP + MAC + vendor
//  2. If ports are specified, run nmap -sV on discovered hosts ONLY
//     (not the whole subnet) → open ports + service versions
//  3. Fall back to nmap-only if arp-scan is unavailable
//
// This is the same architecture as LanScan / Fing / Angry IP Scanner:
// ARP for speed, TCP for detail.
func (s *Scanner) Scan(ctx context.Context, cidrs []string, ports []int) ([]Candidate, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}

	// Phase 1: ARP sweep — fast host discovery.
	candidates, arpErr := s.arpSweep(ctx, cidrs)
	if arpErr != nil {
		log.Printf("scanner: arp-scan unavailable (%v) — falling back to nmap", arpErr)
		// Full fallback to nmap.
		return s.nmapScan(ctx, cidrs, ports)
	}

	log.Printf("scanner: arp-scan found %d hosts", len(candidates))

	if len(candidates) == 0 || len(ports) == 0 {
		return candidates, nil
	}

	// Phase 2: nmap port/service enrichment on discovered hosts only.
	// Instead of scanning 254 IPs × 6 ports, we scan only the 3-4 alive
	// hosts — takes seconds instead of minutes.
	aliveIPs := make([]string, len(candidates))
	for i, c := range candidates {
		aliveIPs[i] = c.Address
	}

	enriched, err := s.nmapEnrich(ctx, aliveIPs, ports)
	if err != nil {
		log.Printf("scanner: nmap enrichment failed (%v) — returning ARP results only", err)
		return candidates, nil
	}

	// Merge nmap results into ARP candidates.
	byAddr := make(map[string]*Candidate)
	for i := range candidates {
		byAddr[candidates[i].Address] = &candidates[i]
	}
	for _, e := range enriched {
		if c, ok := byAddr[e.Address]; ok {
			c.OpenPorts = e.OpenPorts
			c.Services = e.Services
			if c.Hostname == "" && e.Hostname != "" {
				c.Hostname = e.Hostname
			}
		}
	}

	return candidates, nil
}

// --- arp-scan ---

// arpSweep runs `arp-scan` on each CIDR and parses the output.
// Output format: "192.168.0.1\t00:11:22:33:44:55\tVendor Name"
func (s *Scanner) arpSweep(ctx context.Context, cidrs []string) ([]Candidate, error) {
	// Check if arp-scan is available.
	if _, err := exec.LookPath(s.arpScanBin()); err != nil {
		return nil, fmt.Errorf("arp-scan not found: %w", err)
	}

	var all []Candidate
	for _, cidr := range cidrs {
		args := []string{"--localnet", "--retry=1", "--timeout=500", cidr}
		log.Printf("scanner: running arp-scan %s", strings.Join(args, " "))

		cmd := exec.CommandContext(ctx, s.arpScanBin(), args...)
		out, err := cmd.Output()
		if err != nil {
			// arp-scan may need root — try with --ignoredups and check.
			if exitErr, ok := err.(*exec.ExitError); ok {
				stderr := string(exitErr.Stderr)
				if strings.Contains(stderr, "Operation not permitted") ||
					strings.Contains(stderr, "permission") {
					return nil, fmt.Errorf("arp-scan needs root or CAP_NET_RAW: %s", stderr)
				}
			}
			// Non-fatal — maybe partial results.
			log.Printf("scanner: arp-scan warning: %v", err)
		}

		candidates := parseArpScanOutput(string(out))
		all = append(all, candidates...)
	}

	return all, nil
}

// arp-scan output line: "192.168.0.1\t00:aa:bb:cc:dd:ee\tTP-Link Technologies"
var arpLineRE = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)`)

func parseArpScanOutput(output string) []Candidate {
	var out []Candidate
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		m := arpLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, Candidate{
			Address:    m[1],
			MACAddress: m[2],
			MACVendor:  strings.TrimSpace(m[3]),
		})
	}
	return out
}

// --- nmap enrichment (ports + services on known-alive hosts) ---

func (s *Scanner) nmapEnrich(ctx context.Context, ips []string, ports []int) ([]Candidate, error) {
	portList := make([]string, len(ports))
	for i, p := range ports {
		portList[i] = strconv.Itoa(p)
	}

	args := []string{
		"-oX", "-",
		"--open",
		"-T4",
		"--host-timeout", "2m",
		"-sS", "-sV",
		"-p", strings.Join(portList, ","),
	}
	args = append(args, ips...)

	log.Printf("scanner: enriching %d hosts with nmap -sV -p %s", len(ips), strings.Join(portList, ","))

	cmd := exec.CommandContext(ctx, s.nmapBin(), args...)
	out, err := cmd.Output()
	if err != nil {
		// SYN scan needs root — fall back to TCP connect.
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "requires root") ||
				strings.Contains(stderr, "Operation not permitted") ||
				strings.Contains(stderr, "raw socket") {
				log.Printf("scanner: SYN scan failed — falling back to TCP connect")
				for i, a := range args {
					if a == "-sS" {
						args[i] = "-sT"
						break
					}
				}
				args = append(args, "--unprivileged")
				cmd2 := exec.CommandContext(ctx, s.nmapBin(), args...)
				out, err = cmd2.Output()
				if err != nil {
					return nil, fmt.Errorf("nmap -sT failed: %w", err)
				}
			} else {
				return nil, fmt.Errorf("nmap failed: %w\nstderr: %s", err, stderr)
			}
		} else {
			return nil, fmt.Errorf("nmap failed: %w", err)
		}
	}

	return parseNmapXML(out)
}

// nmapScan is the full-fallback path when arp-scan is unavailable.
// Scans entire CIDRs with nmap (slower but works without arp-scan).
func (s *Scanner) nmapScan(ctx context.Context, cidrs []string, ports []int) ([]Candidate, error) {
	args := []string{
		"-oX", "-",
		"--open",
		"-T4",
		"--host-timeout", "2m",
	}

	if len(ports) == 0 {
		args = append(args, "-sn")
	} else {
		args = append(args, "-sS", "-sV")
		portList := make([]string, len(ports))
		for i, p := range ports {
			portList[i] = strconv.Itoa(p)
		}
		args = append(args, "-p", strings.Join(portList, ","))
	}
	args = append(args, cidrs...)

	log.Printf("scanner: running nmap %s", strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, s.nmapBin(), args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "requires root") ||
				strings.Contains(stderr, "Operation not permitted") ||
				strings.Contains(stderr, "raw socket") {
				log.Printf("scanner: SYN scan failed — falling back to TCP connect")
				for i, a := range args {
					if a == "-sS" {
						args[i] = "-sT"
						break
					}
				}
				args = append(args, "--unprivileged")
				cmd2 := exec.CommandContext(ctx, s.nmapBin(), args...)
				out, err = cmd2.Output()
				if err != nil {
					return nil, fmt.Errorf("nmap -sT failed: %w", err)
				}
			} else {
				return nil, fmt.Errorf("nmap failed: %w\nstderr: %s", err, stderr)
			}
		} else {
			return nil, fmt.Errorf("nmap failed: %w", err)
		}
	}

	candidates, err := parseNmapXML(out)
	if err != nil {
		return nil, fmt.Errorf("parse nmap XML: %w", err)
	}

	log.Printf("scanner: done — %d candidates found", len(candidates))
	return candidates, nil
}

// --- nmap XML parsing ---

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus     `xml:"status"`
	Addresses []nmapAddress  `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     []nmapPort     `xml:"ports>port"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Extra   string `xml:"extrainfo,attr"`
}

func parseNmapXML(data []byte) ([]Candidate, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}

	var out []Candidate
	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}

		var addr, macAddr, macVendor string
		for _, a := range h.Addresses {
			switch a.AddrType {
			case "ipv4", "ipv6":
				if addr == "" {
					addr = a.Addr
				}
			case "mac":
				macAddr = a.Addr
				macVendor = a.Vendor
			}
		}
		if addr == "" {
			continue
		}

		var hostname string
		for _, hn := range h.Hostnames {
			hostname = hn.Name
			break
		}

		var openPorts []int
		var services []string
		for _, p := range h.Ports {
			if p.State.State == "open" {
				openPorts = append(openPorts, p.PortID)
				svc := p.Service.Name
				if p.Service.Product != "" {
					svc += " " + p.Service.Product
					if p.Service.Version != "" {
						svc += " " + p.Service.Version
					}
				}
				services = append(services, svc)
			}
		}

		out = append(out, Candidate{
			Address:    addr,
			Hostname:   hostname,
			OpenPorts:  openPorts,
			MACAddress: macAddr,
			MACVendor:  macVendor,
			Services:   services,
		})
	}
	return out, nil
}
