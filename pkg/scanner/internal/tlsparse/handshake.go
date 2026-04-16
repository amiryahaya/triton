package tlsparse

import (
	"encoding/binary"
	"errors"
)

// ErrTruncated is returned when the input is shorter than expected.
var ErrTruncated = errors.New("tlsparse: truncated message")

// ErrNotHandshake is returned when the content type is unexpected.
var ErrNotHandshake = errors.New("tlsparse: not a handshake message")

// ExtractHandshakeFromTLSRecord strips the TLS record layer (5-byte header)
// and returns the handshake payload.
// Input: content_type(1) + legacy_version(2) + length(2) + payload
func ExtractHandshakeFromTLSRecord(record []byte) ([]byte, error) {
	if len(record) < 5 {
		return nil, ErrTruncated
	}
	if record[0] != 0x16 { // handshake content type
		return nil, ErrNotHandshake
	}
	length := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < 5+length {
		return nil, ErrTruncated
	}
	return record[5 : 5+length], nil
}

// ParseClientHello parses a TLS ClientHello handshake message.
// Input must start at the handshake type byte (0x01).
func ParseClientHello(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 4 {
		return nil, ErrTruncated
	}
	if data[0] != 0x01 {
		return nil, ErrNotHandshake
	}

	// handshake length is 3 bytes big-endian
	msgLen := int(uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]))
	if len(data) < 4+msgLen {
		return nil, ErrTruncated
	}
	body := data[4 : 4+msgLen]

	r := &reader{buf: body}
	info := &ClientHelloInfo{}

	// client_version (2)
	v, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	info.TLSVersion = v

	// random (32)
	if _, err = r.readBytes(32); err != nil {
		return nil, err
	}

	// session_id (1-byte length + data)
	sessionLen, err := r.readUint8()
	if err != nil {
		return nil, err
	}
	if _, err = r.readBytes(int(sessionLen)); err != nil {
		return nil, err
	}

	// cipher_suites (2-byte length + 2 bytes each)
	csLen, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	if csLen%2 != 0 {
		return nil, ErrTruncated
	}
	info.CipherSuites = make([]uint16, 0, csLen/2)
	for i := 0; i < int(csLen); i += 2 {
		cs, e2 := r.readUint16()
		if e2 != nil {
			return nil, e2
		}
		info.CipherSuites = append(info.CipherSuites, cs)
	}

	// compression_methods (1-byte length + data)
	compLen, err := r.readUint8()
	if err != nil {
		return nil, err
	}
	if _, err = r.readBytes(int(compLen)); err != nil {
		return nil, err
	}

	// extensions (optional: 2-byte total length)
	if r.remaining() < 2 {
		return info, nil
	}
	extsLen, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	if r.remaining() < int(extsLen) {
		return nil, ErrTruncated
	}

	if err := parseClientExtensions(r.slice(int(extsLen)), info); err != nil {
		return nil, err
	}

	return info, nil
}

// ParseServerHello parses a TLS ServerHello handshake message.
// Input must start at the handshake type byte (0x02).
func ParseServerHello(data []byte) (*ServerHelloInfo, error) {
	if len(data) < 4 {
		return nil, ErrTruncated
	}
	if data[0] != 0x02 {
		return nil, ErrNotHandshake
	}

	msgLen := int(uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]))
	if len(data) < 4+msgLen {
		return nil, ErrTruncated
	}
	body := data[4 : 4+msgLen]

	r := &reader{buf: body}
	info := &ServerHelloInfo{}

	// server_version (2)
	v, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	info.TLSVersion = v

	// random (32)
	if _, err = r.readBytes(32); err != nil {
		return nil, err
	}

	// session_id (1-byte length + data)
	sessionLen, err := r.readUint8()
	if err != nil {
		return nil, err
	}
	if _, err = r.readBytes(int(sessionLen)); err != nil {
		return nil, err
	}

	// cipher_suite (2)
	cs, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	info.CipherSuite = cs

	// compression_method (1)
	if _, err = r.readUint8(); err != nil {
		return nil, err
	}

	// extensions (optional)
	if r.remaining() < 2 {
		return info, nil
	}
	extsLen, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	if r.remaining() < int(extsLen) {
		return nil, ErrTruncated
	}

	if err := parseServerExtensions(r.slice(int(extsLen)), info); err != nil {
		return nil, err
	}

	return info, nil
}

// parseClientExtensions reads the extension list and populates ClientHelloInfo.
func parseClientExtensions(extsData []byte, info *ClientHelloInfo) error {
	r := &reader{buf: extsData}
	for r.remaining() >= 4 {
		extType, err := r.readUint16()
		if err != nil {
			return err
		}
		extLen, err := r.readUint16()
		if err != nil {
			return err
		}
		if r.remaining() < int(extLen) {
			return ErrTruncated
		}
		extData := r.slice(int(extLen))
		info.Extensions = append(info.Extensions, extType)

		switch extType {
		case 0x0000: // SNI
			sni, e2 := parseSNI(extData)
			if e2 == nil {
				info.SNI = sni
			}
		case 0x000a: // supported_groups
			curves, e2 := parseUint16List(extData)
			if e2 == nil {
				info.EllipticCurves = curves
			}
		case 0x000b: // ec_point_formats
			fmts, e2 := parseUint8List(extData)
			if e2 == nil {
				info.ECPointFormats = fmts
			}
		case 0x000d: // signature_algorithms
			schemes, e2 := parseUint16List(extData)
			if e2 == nil {
				info.SignatureSchemes = schemes
			}
		case 0x0010: // ALPN
			protos, e2 := parseALPN(extData)
			if e2 == nil {
				info.ALPNProtocols = protos
			}
		}
	}
	return nil
}

// parseServerExtensions reads the extension list and populates ServerHelloInfo.
func parseServerExtensions(extsData []byte, info *ServerHelloInfo) error {
	r := &reader{buf: extsData}
	for r.remaining() >= 4 {
		extType, err := r.readUint16()
		if err != nil {
			return err
		}
		extLen, err := r.readUint16()
		if err != nil {
			return err
		}
		if r.remaining() < int(extLen) {
			return ErrTruncated
		}
		extData := r.slice(int(extLen))
		info.Extensions = append(info.Extensions, extType)

		if extType == 0x0010 { // ALPN
			protos, e2 := parseALPN(extData)
			if e2 == nil && len(protos) > 0 {
				info.SelectedALPN = protos[0]
			}
		}
	}
	return nil
}

// parseSNI parses the SNI extension value.
// Format: list_length(2) + name_type(1) + name_length(2) + name
func parseSNI(data []byte) (string, error) {
	r := &reader{buf: data}
	listLen, err := r.readUint16()
	if err != nil {
		return "", err
	}
	if r.remaining() < int(listLen) {
		return "", ErrTruncated
	}
	nameType, err := r.readUint8()
	if err != nil {
		return "", err
	}
	if nameType != 0 {
		return "", nil // not host_name type
	}
	nameLen, err := r.readUint16()
	if err != nil {
		return "", err
	}
	nameBytes, err := r.readBytes(int(nameLen))
	if err != nil {
		return "", err
	}
	return string(nameBytes), nil
}

// parseUint16List parses a 2-byte length-prefixed list of uint16 values.
func parseUint16List(data []byte) ([]uint16, error) {
	r := &reader{buf: data}
	listLen, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	if r.remaining() < int(listLen) || listLen%2 != 0 {
		return nil, ErrTruncated
	}
	out := make([]uint16, 0, listLen/2)
	for i := 0; i < int(listLen); i += 2 {
		v, e2 := r.readUint16()
		if e2 != nil {
			return nil, e2
		}
		out = append(out, v)
	}
	return out, nil
}

// parseUint8List parses a 1-byte length-prefixed list of uint8 values.
func parseUint8List(data []byte) ([]uint8, error) {
	r := &reader{buf: data}
	listLen, err := r.readUint8()
	if err != nil {
		return nil, err
	}
	if r.remaining() < int(listLen) {
		return nil, ErrTruncated
	}
	out := make([]uint8, int(listLen))
	copy(out, r.buf[r.pos:r.pos+int(listLen)])
	r.pos += int(listLen)
	return out, nil
}

// parseALPN parses the ALPN extension value.
// Format: protocol_list_length(2) + (proto_length(1) + proto_bytes)*
func parseALPN(data []byte) ([]string, error) {
	r := &reader{buf: data}
	listLen, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	if r.remaining() < int(listLen) {
		return nil, ErrTruncated
	}
	end := r.pos + int(listLen)
	var protos []string
	for r.pos < end {
		protoLen, e2 := r.readUint8()
		if e2 != nil {
			return nil, e2
		}
		pb, e2 := r.readBytes(int(protoLen))
		if e2 != nil {
			return nil, e2
		}
		protos = append(protos, string(pb))
	}
	return protos, nil
}

// reader is a simple cursor over a byte slice.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) remaining() int { return len(r.buf) - r.pos }

func (r *reader) readUint8() (uint8, error) {
	if r.remaining() < 1 {
		return 0, ErrTruncated
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) readUint16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, ErrTruncated
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *reader) readBytes(n int) ([]byte, error) {
	if r.remaining() < n {
		return nil, ErrTruncated
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

// slice reads n bytes and returns them (no copy); advances position.
func (r *reader) slice(n int) []byte {
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b
}
