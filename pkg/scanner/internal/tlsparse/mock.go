package tlsparse

import "io"

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
