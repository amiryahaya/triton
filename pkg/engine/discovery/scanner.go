// Package discovery implements the engine-side network discovery
// scanner and worker. The scanner shells out to nmap for reliable,
// fast host detection; the worker long-polls the portal for jobs,
// drives the scanner, and streams candidates back.
package discovery

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

// Candidate is a host nmap found with at least one open port (or
// responsive to ping). Address is the dotted-quad / IPv6 string form.
type Candidate struct {
	Address    string
	Hostname   string
	OpenPorts  []int
	MACAddress string   // from nmap L2 detection (same subnet only)
	MACVendor  string   // e.g. "Apple", "Raspberry Pi Foundation"
	Services   []string // e.g. ["ssh OpenSSH 8.9", "http nginx 1.24"]
}

// Scanner shells out to nmap for network discovery. Zero-value is
// ready to use (nmap must be on $PATH).
type Scanner struct {
	// NmapPath overrides the nmap binary location. Default: "nmap".
	NmapPath string
}

func (s *Scanner) nmapBin() string {
	if s.NmapPath != "" {
		return s.NmapPath
	}
	return "nmap"
}

// Scan runs nmap against the given CIDRs and ports. If ports is empty,
// runs a ping sweep (-sn). If ports is non-empty, runs a SYN scan (-sS)
// on those ports. Returns one Candidate per responsive host.
//
// Requires nmap on $PATH and CAP_NET_RAW (or root) for SYN scan.
// Falls back to TCP connect scan (-sT) if SYN scan fails (no privileges).
func (s *Scanner) Scan(ctx context.Context, cidrs []string, ports []int) ([]Candidate, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}

	args := []string{
		"-oX", "-", // XML output to stdout
		"--open", // only show open ports
		"-T4",    // aggressive timing (fast)
		"--host-timeout", "30s",
	}

	if len(ports) == 0 {
		// Ping sweep — find all live hosts, no port scan.
		args = append(args, "-sn")
	} else {
		// SYN scan on specific ports with service version detection.
		args = append(args, "-sS", "-sV")
		portList := make([]string, len(ports))
		for i, p := range ports {
			portList[i] = strconv.Itoa(p)
		}
		args = append(args, "-p", strings.Join(portList, ","))
	}

	// Append all CIDRs as targets.
	args = append(args, cidrs...)

	log.Printf("scanner: running nmap %s", strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, s.nmapBin(), args...)
	out, err := cmd.Output()
	if err != nil {
		// SYN scan requires root/CAP_NET_RAW. If it fails, retry with
		// TCP connect scan (-sT) which works unprivileged.
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "requires root") || strings.Contains(stderr, "Operation not permitted") {
				log.Printf("scanner: SYN scan failed (no raw socket) — falling back to unprivileged TCP connect scan")
				for i, a := range args {
					if a == "-sS" {
						args[i] = "-sT" // -sV stays for service detection
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

	// Parse nmap XML output.
	candidates, err := parseNmapXML(out)
	if err != nil {
		return nil, fmt.Errorf("parse nmap XML: %w", err)
	}

	log.Printf("scanner: done — %d candidates found", len(candidates))
	return candidates, nil
}

// --- nmap XML parsing ---

// nmapRun is the root element of nmap's -oX output.
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
	AddrType string `xml:"addrtype,attr"` // ipv4, ipv6, mac
	Vendor   string `xml:"vendor,attr"`   // MAC vendor (e.g. "Apple", "HP")
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"` // user, PTR
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"` // open, closed, filtered
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"` // e.g. "OpenSSH", "nginx", "Microsoft IIS"
	Version string `xml:"version,attr"` // e.g. "8.9", "1.24"
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

		// Find IP address + MAC address/vendor.
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

		// Hostname from rDNS or user-supplied.
		var hostname string
		for _, hn := range h.Hostnames {
			hostname = hn.Name
			break
		}

		// Collect open ports + service descriptions.
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

		c := Candidate{
			Address:    addr,
			Hostname:   hostname,
			OpenPorts:  openPorts,
			MACAddress: macAddr,
			MACVendor:  macVendor,
			Services:   services,
		}
		out = append(out, c)
	}
	return out, nil
}
