//go:build !linux

package tlsparse

import (
	"errors"
	"runtime"
)

// NewLiveCaptureReader returns an error on non-Linux platforms because live
// capture requires AF_PACKET, which is Linux-only (no CGO required, but the
// kernel interface is unavailable on other operating systems).
func NewLiveCaptureReader(iface, bpfFilter string) (PacketSource, error) {
	return nil, errors.New("live capture is not supported on " + runtime.GOOS + "; only Linux AF_PACKET is available (no CGO)")
}
