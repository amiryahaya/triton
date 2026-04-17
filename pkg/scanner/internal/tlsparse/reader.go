package tlsparse

import (
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Packet holds a decoded TCP packet's metadata and payload.
type Packet struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
	Payload []byte
	Time    time.Time
}

// PacketSource yields TCP packets one at a time.
type PacketSource interface {
	// NextPacket returns the next TCP packet with a non-empty payload.
	// Returns io.EOF when the source is exhausted.
	NextPacket() (*Packet, error)
	Close() error
}

// PcapFileReader reads packets from a .pcap file using pcapgo (pure Go, no CGO).
type PcapFileReader struct {
	f     *os.File
	r     *pcapgo.Reader
	ltype layers.LinkType
}

// NewPcapFileReader opens the named .pcap file and prepares it for reading.
func NewPcapFileReader(path string) (*PcapFileReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &PcapFileReader{f: f, r: r, ltype: r.LinkType()}, nil
}

// NextPacket returns the next TCP packet that carries a non-empty payload.
// Non-IP and non-TCP packets are silently skipped. Returns io.EOF when
// the file is exhausted.
func (r *PcapFileReader) NextPacket() (*Packet, error) {
	for {
		data, ci, err := r.r.ReadPacketData()
		if err != nil {
			return nil, err // includes io.EOF
		}

		pkt := gopacket.NewPacket(data, r.ltype.LayerType(), gopacket.NoCopy)

		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp == nil || len(tcp.Payload) == 0 {
			continue
		}

		p := &Packet{
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
			Payload: make([]byte, len(tcp.Payload)),
			Time:    ci.Timestamp,
		}
		copy(p.Payload, tcp.Payload)

		// Extract IP addresses from the appropriate layer.
		if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
			l, _ := ip4.(*layers.IPv4)
			if l != nil {
				p.SrcIP = make(net.IP, len(l.SrcIP))
				copy(p.SrcIP, l.SrcIP)
				p.DstIP = make(net.IP, len(l.DstIP))
				copy(p.DstIP, l.DstIP)
			}
		} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
			l, _ := ip6.(*layers.IPv6)
			if l != nil {
				p.SrcIP = make(net.IP, len(l.SrcIP))
				copy(p.SrcIP, l.SrcIP)
				p.DstIP = make(net.IP, len(l.DstIP))
				copy(p.DstIP, l.DstIP)
			}
		} else {
			// No IP layer — skip.
			continue
		}

		return p, nil
	}
}

// Close releases the underlying file handle.
func (r *PcapFileReader) Close() error {
	return r.f.Close()
}
