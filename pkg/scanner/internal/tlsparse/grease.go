package tlsparse

// IsGREASE returns true if the value is a GREASE sentinel per RFC 8701.
// Pattern: 0x?A?A where both nibble pairs are 0x0A (i.e. low nibble of each
// byte is 0xA and both bytes are equal).
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// FilterGREASE returns a new slice with GREASE values removed.
func FilterGREASE(vals []uint16) []uint16 {
	if len(vals) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !IsGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}
