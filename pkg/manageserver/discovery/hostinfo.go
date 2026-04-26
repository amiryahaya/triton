package discovery

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// lookupMAC returns the MAC address for ip by reading the OS ARP cache.
// The ARP entry is populated by the TCP connections we already made during
// port probing, so no extra network round-trip is needed.
// Returns "" when the MAC cannot be determined (cross-router hop, no entry,
// or unsupported OS).
func lookupMAC(ip string) string {
	// Linux: /proc/net/arp
	// Format: IP address HW type Flags HW address Mask Device
	if data, err := os.ReadFile("/proc/net/arp"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[0] == ip {
				mac := fields[3]
				if mac != "00:00:00:00:00:00" && mac != "<incomplete>" {
					return strings.ToUpper(mac)
				}
			}
		}
	}

	// macOS / BSD: arp -n <ip>
	// Output example: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
	if out, err := exec.Command("arp", "-n", ip).Output(); err == nil {
		macRe := regexp.MustCompile(`(?i)([0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2})`)
		if m := macRe.FindString(string(out)); m != "" {
			return strings.ToUpper(m)
		}
	}

	return ""
}

// lookupMDNS sends a unicast mDNS PTR query to ip:5353 and returns the
// discovered .local hostname, or "" on failure/timeout.
// Works for Apple devices, Linux hosts running Avahi, and modern Windows.
// Requires both endpoints on the same L2 broadcast domain.
func lookupMDNS(ctx context.Context, ip string, timeout time.Duration) string {
	// Build the reverse-DNS name for the PTR query.
	// e.g. 192.168.1.10 → "10.1.168.192.in-addr.arpa."
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "" // IPv6 not handled
	}
	qname := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa."

	// Build a minimal DNS PTR query (RFC 1035 wire format).
	// mDNS uses transaction ID 0x0000 and the unicast-response bit (0x8000)
	// in the class field so the responder replies directly to us.
	pkt := buildDNSQuery(qname)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", ip+":5353")
	if err != nil {
		return ""
	}
	defer conn.Close() //nolint:errcheck

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(pkt); err != nil {
		return ""
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	return parsePTRName(buf[:n])
}

// buildDNSQuery constructs a minimal DNS PTR query for name.
func buildDNSQuery(name string) []byte {
	var b []byte

	// Header: ID=0, QR=0 (query), Opcode=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
	b = append(b, 0x00, 0x00) // Transaction ID
	b = append(b, 0x00, 0x00) // Flags
	b = append(b, 0x00, 0x01) // QDCOUNT=1
	b = append(b, 0x00, 0x00) // ANCOUNT=0
	b = append(b, 0x00, 0x00) // NSCOUNT=0
	b = append(b, 0x00, 0x00) // ARCOUNT=0

	// Question: encode name as DNS labels
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, []byte(label)...)
	}
	b = append(b, 0x00)       // root label
	b = append(b, 0x00, 0x0c) // QTYPE=PTR
	b = append(b, 0x80, 0x01) // QCLASS=IN with unicast-response bit

	return b
}

// parsePTRName extracts the first PTR record's target name from a DNS response.
func parsePTRName(buf []byte) string {
	if len(buf) < 12 {
		return ""
	}
	anCount := binary.BigEndian.Uint16(buf[6:8])
	if anCount == 0 {
		return ""
	}

	// Skip header (12 bytes) + question section.
	// Skip question name (read past labels until 0x00), then QTYPE+QCLASS (4 bytes).
	offset := 12
	offset = skipName(buf, offset)
	if offset < 0 || offset+4 > len(buf) {
		return ""
	}
	offset += 4 // QTYPE + QCLASS

	// Parse first answer record.
	offset = skipName(buf, offset) // RR name
	if offset < 0 || offset+10 > len(buf) {
		return ""
	}
	rrType := binary.BigEndian.Uint16(buf[offset : offset+2])
	// rrClass := binary.BigEndian.Uint16(buf[offset+2 : offset+4]) // unused
	rdLen := int(binary.BigEndian.Uint16(buf[offset+8 : offset+10]))
	offset += 10

	if rrType != 0x000c { // not PTR
		return ""
	}
	if offset+rdLen > len(buf) {
		return ""
	}

	return decodeName(buf, offset)
}

// skipName advances offset past a DNS name (handles pointers).
func skipName(buf []byte, offset int) int {
	for {
		if offset >= len(buf) {
			return -1
		}
		length := int(buf[offset])
		if length == 0 {
			return offset + 1
		}
		if length&0xc0 == 0xc0 { // pointer
			return offset + 2
		}
		offset += 1 + length
	}
}

// decodeName decodes a DNS name at offset (handles pointers).
func decodeName(buf []byte, offset int) string {
	var labels []string
	visited := make(map[int]bool)
	for {
		if offset >= len(buf) || visited[offset] {
			break
		}
		visited[offset] = true
		length := int(buf[offset])
		if length == 0 {
			break
		}
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(buf) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(buf[offset:offset+2]) & 0x3fff)
			offset = ptr
			continue
		}
		offset++
		if offset+length > len(buf) {
			break
		}
		labels = append(labels, string(buf[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, ".")
}
