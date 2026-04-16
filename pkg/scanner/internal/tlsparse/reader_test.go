package tlsparse

import (
	"io"
	"net"
	"testing"
	"time"
)

// MockPacketSource is a PacketSource backed by an in-memory slice.
// It is exported so parent packages (e.g. pkg/scanner) can use it in tests.
type MockPacketSource struct {
	packets []*Packet
	idx     int
}

// NewMockSource returns a MockPacketSource that yields the supplied packets in
// order, then returns io.EOF.
func NewMockSource(pkts ...*Packet) *MockPacketSource {
	return &MockPacketSource{packets: pkts}
}

// NextPacket returns the next Packet in the slice, or io.EOF when exhausted.
func (m *MockPacketSource) NextPacket() (*Packet, error) {
	if m.idx >= len(m.packets) {
		return nil, io.EOF
	}
	p := m.packets[m.idx]
	m.idx++
	return p, nil
}

// Close is a no-op for MockPacketSource.
func (m *MockPacketSource) Close() error { return nil }

// Compile-time interface check.
var _ PacketSource = (*MockPacketSource)(nil)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMockPacketSource_ReadAll(t *testing.T) {
	now := time.Now()
	want := []*Packet{
		{
			SrcIP:   net.ParseIP("192.168.1.1"),
			SrcPort: 12345,
			DstIP:   net.ParseIP("10.0.0.1"),
			DstPort: 443,
			Payload: []byte{0x16, 0x03, 0x01},
			Time:    now,
		},
		{
			SrcIP:   net.ParseIP("192.168.1.2"),
			SrcPort: 54321,
			DstIP:   net.ParseIP("10.0.0.2"),
			DstPort: 8443,
			Payload: []byte{0x16, 0x03, 0x03},
			Time:    now.Add(time.Second),
		},
	}

	src := NewMockSource(want...)

	var got []*Packet
	for {
		p, err := src.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got = append(got, p)
	}

	if len(got) != len(want) {
		t.Fatalf("got %d packets, want %d", len(got), len(want))
	}
	for i, p := range got {
		w := want[i]
		if p.SrcPort != w.SrcPort || p.DstPort != w.DstPort {
			t.Errorf("packet[%d]: ports got (%d→%d), want (%d→%d)",
				i, p.SrcPort, p.DstPort, w.SrcPort, w.DstPort)
		}
		if string(p.Payload) != string(w.Payload) {
			t.Errorf("packet[%d]: payload got %v, want %v", i, p.Payload, w.Payload)
		}
		if !p.Time.Equal(w.Time) {
			t.Errorf("packet[%d]: time got %v, want %v", i, p.Time, w.Time)
		}
	}
}

func TestMockPacketSource_EmptySource(t *testing.T) {
	src := NewMockSource()
	p, err := src.NextPacket()
	if err != io.EOF {
		t.Fatalf("expected io.EOF on empty source, got err=%v p=%v", err, p)
	}
}

func TestMockPacketSource_RepeatedEOF(t *testing.T) {
	src := NewMockSource()
	for i := 0; i < 3; i++ {
		_, err := src.NextPacket()
		if err != io.EOF {
			t.Fatalf("call %d: expected io.EOF, got %v", i, err)
		}
	}
}

func TestMockPacketSource_Close(t *testing.T) {
	src := NewMockSource(&Packet{Payload: []byte{1}})
	if err := src.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
}
