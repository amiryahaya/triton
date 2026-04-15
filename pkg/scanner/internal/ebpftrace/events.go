package ebpftrace

import (
	"encoding/binary"
	"fmt"
	"time"
)

// eventSize matches sizeof(struct crypto_event_t) in bpf/event.h.
const eventSize = 104

// DecodeEvent parses a crypto_event_t struct from a ring-buffer payload.
func DecodeEvent(buf []byte) (Event, error) {
	if len(buf) < eventSize {
		return Event{}, fmt.Errorf("ebpftrace: event buffer too short (%d < %d)", len(buf), eventSize)
	}
	ev := Event{
		PID:    binary.LittleEndian.Uint32(buf[0:4]),
		UID:    binary.LittleEndian.Uint32(buf[4:8]),
		TS:     time.Unix(0, int64(binary.LittleEndian.Uint64(buf[8:16]))),
		Source: Source(buf[16]),
		LibID:  LibID(buf[17]),
		NID:    int32(binary.LittleEndian.Uint32(buf[20:24])),
		Name:   cString(buf[24:88]),
		Comm:   cString(buf[88:104]),
	}
	return ev, nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
