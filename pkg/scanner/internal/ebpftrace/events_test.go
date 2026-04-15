package ebpftrace

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestDecodeEvent_Kprobe(t *testing.T) {
	buf := make([]byte, 104)
	binary.LittleEndian.PutUint32(buf[0:], 1234)                              // pid
	binary.LittleEndian.PutUint32(buf[4:], 0)                                 // uid
	binary.LittleEndian.PutUint64(buf[8:], uint64(1_700_000_000_000_000_000)) // ts_ns
	buf[16] = uint8(SourceKprobe)
	buf[17] = uint8(LibKernel)
	nidNeg := int32(-1)
	binary.LittleEndian.PutUint32(buf[20:], uint32(nidNeg)) // nid = -1
	copy(buf[24:], []byte("sha256\x00"))
	copy(buf[88:], []byte("openssl\x00"))

	ev, err := DecodeEvent(buf)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if ev.PID != 1234 {
		t.Errorf("PID = %d, want 1234", ev.PID)
	}
	if ev.Source != SourceKprobe {
		t.Errorf("Source = %v, want SourceKprobe", ev.Source)
	}
	if ev.LibID != LibKernel {
		t.Errorf("LibID = %v, want LibKernel", ev.LibID)
	}
	if ev.NID != -1 {
		t.Errorf("NID = %d, want -1", ev.NID)
	}
	if ev.Name != "sha256" {
		t.Errorf("Name = %q, want sha256", ev.Name)
	}
	if ev.Comm != "openssl" {
		t.Errorf("Comm = %q, want openssl", ev.Comm)
	}
	if ev.TS.IsZero() {
		t.Error("TS is zero")
	}
	_ = time.Second // keep time import used
}

func TestDecodeEvent_Uprobe(t *testing.T) {
	buf := make([]byte, 104)
	binary.LittleEndian.PutUint32(buf[0:], 5678)
	buf[16] = uint8(SourceUprobe)
	buf[17] = uint8(LibLibcrypto)
	binary.LittleEndian.PutUint32(buf[20:], uint32(int32(672))) // NID_sha256
	// name remains empty for NID path
	copy(buf[88:], []byte("nginx\x00"))

	ev, err := DecodeEvent(buf)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if ev.NID != 672 {
		t.Errorf("NID = %d, want 672", ev.NID)
	}
	if ev.LibID != LibLibcrypto {
		t.Errorf("LibID = %v, want LibLibcrypto", ev.LibID)
	}
	if ev.Name != "" {
		t.Errorf("Name = %q, want empty (NID path)", ev.Name)
	}
}

func TestDecodeEvent_RejectsShortBuffer(t *testing.T) {
	if _, err := DecodeEvent(make([]byte, 50)); err == nil {
		t.Error("expected error on short buffer")
	}
}
