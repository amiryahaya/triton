//go:build linux

package tlsparse

import (
	"errors"
	"io"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

// AFPacketReader captures live packets from a network interface using
// Linux AF_PACKET (TPACKET_V3) memory-mapped ring buffers.
// Requires root or CAP_NET_RAW.
type AFPacketReader struct {
	handle *afpacket.TPacket
}

// NewLiveCaptureReader opens an AF_PACKET socket on the named interface.
// bpfFilter is accepted for API compatibility but is not applied in this
// implementation — callers should filter at the PacketSource consumer level.
// Returns an error if the process lacks the required privileges.
func NewLiveCaptureReader(iface string, bpfFilter string) (PacketSource, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("live capture requires root or CAP_NET_RAW")
	}
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(65536*128),
		afpacket.OptNumBlocks(8),
	)
	if err != nil {
		return nil, err
	}
	return &AFPacketReader{handle: handle}, nil
}

// NextPacket returns the next TCP packet with a non-empty payload captured
// from the live interface.  Non-IP and non-TCP packets are skipped silently.
// Returns io.EOF when the handle is closed.
func (r *AFPacketReader) NextPacket() (*Packet, error) {
	for {
		data, ci, err := r.handle.ReadPacketData()
		if err != nil {
			// afpacket signals handle close as an error; normalise to io.EOF.
			if errors.Is(err, afpacket.ErrPoll) {
				return nil, io.EOF
			}
			return nil, err
		}

		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

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
			continue
		}

		return p, nil
	}
}

// Close releases the AF_PACKET handle.
func (r *AFPacketReader) Close() error {
	r.handle.Close()
	return nil
}
