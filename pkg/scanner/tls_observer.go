package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/tlsparse"
)

const (
	// maxFlows caps the number of concurrent in-flight flows tracked in memory.
	maxFlows = 10_000

	// defaultPcapWindow is used for live capture when config.PcapWindow is zero.
	defaultPcapWindow = 30 * time.Second
)

// flowKey identifies a unique TCP flow by its four-tuple.
// We use a value type with string IPs for map-key compatibility.
type flowKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
}

// reverseKey returns the flow key with src/dst swapped (server→client direction).
func (k flowKey) reverseKey() flowKey {
	return flowKey{
		srcIP:   k.dstIP,
		srcPort: k.dstPort,
		dstIP:   k.srcIP,
		dstPort: k.srcPort,
	}
}

// flowState tracks the handshake messages seen for one TCP flow.
type flowState struct {
	key         flowKey
	clientHello *tlsparse.ClientHelloInfo
	serverHello *tlsparse.ServerHelloInfo
}

// TLSObserverModule passively observes TLS handshakes from pcap files or live
// capture, computes JA3/JA3S/JA4/JA4S fingerprints, and emits findings.
type TLSObserverModule struct {
	config        *scannerconfig.Config
	readerFactory func(target string) (tlsparse.PacketSource, error)
}

// NewTLSObserverModule creates a TLSObserverModule with the default reader
// factory (pcap file for plain paths, live capture for "iface:" prefix).
func NewTLSObserverModule(cfg *scannerconfig.Config) *TLSObserverModule {
	m := &TLSObserverModule{config: cfg}
	m.readerFactory = m.defaultReaderFactory
	return m
}

// Name implements Module.
func (m *TLSObserverModule) Name() string { return "tls_observer" }

// Category implements Module.
func (m *TLSObserverModule) Category() model.ModuleCategory { return model.CategoryActiveNetwork }

// ScanTargetType implements Module.
func (m *TLSObserverModule) ScanTargetType() model.ScanTargetType { return model.TargetPcap }

// Scan reads packets from the target (pcap file or live interface), processes
// TLS handshakes, and emits one or two findings per completed flow.
func (m *TLSObserverModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	isLive := strings.HasPrefix(target.Value, "iface:")
	flowSource := "pcap_file"
	if isLive {
		flowSource = "live_capture"
	}

	src, err := m.readerFactory(target.Value)
	if err != nil {
		return fmt.Errorf("tls_observer: open source %q: %w", target.Value, err)
	}
	defer func() { _ = src.Close() }()

	// For live capture, apply a timeout via context cancellation.
	if isLive {
		window := defaultPcapWindow
		if m.config != nil && m.config.PcapWindow > 0 {
			window = m.config.PcapWindow
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, window)
		defer cancel()
	}

	flows := make(map[flowKey]*flowState, 128)

	for {
		// Honour context cancellation (important for live capture timeout).
		select {
		case <-ctx.Done():
			// Timeout or cancellation — flush what we have.
			m.emitFlows(ctx, flows, flowSource, findings)
			return nil
		default:
		}

		pkt, err := src.NextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			// Non-fatal read error; skip packet.
			continue
		}

		m.processPacket(pkt, flows)
	}

	m.emitFlows(ctx, flows, flowSource, findings)
	return nil
}

// processPacket inspects a packet's payload and updates flow state.
func (m *TLSObserverModule) processPacket(pkt *tlsparse.Packet, flows map[flowKey]*flowState) {
	// Minimum: content_type(1) + version(2) + length(2) + at least 1 handshake byte.
	if len(pkt.Payload) < 6 {
		return
	}
	if pkt.Payload[0] != 0x16 { // not TLS Handshake
		return
	}

	hs, err := tlsparse.ExtractHandshakeFromTLSRecord(pkt.Payload)
	if err != nil || len(hs) == 0 {
		return
	}

	msgType := hs[0]
	switch msgType {
	case 0x01: // ClientHello
		ch, err := tlsparse.ParseClientHello(hs)
		if err != nil {
			return
		}
		key := packetFlowKey(pkt)
		if _, exists := flows[key]; exists {
			// Already tracking this flow — update ClientHello.
			flows[key].clientHello = ch
			return
		}
		if len(flows) >= maxFlows {
			// Capacity exhausted — drop new flows silently.
			return
		}
		flows[key] = &flowState{key: key, clientHello: ch}

	case 0x02: // ServerHello
		sh, err := tlsparse.ParseServerHello(hs)
		if err != nil {
			return
		}
		// ServerHello is sent in the reverse direction of the ClientHello.
		key := packetFlowKey(pkt).reverseKey()
		if state, exists := flows[key]; exists {
			state.serverHello = sh
		}
		// If we haven't seen the ClientHello, discard the ServerHello.
	}
}

// emitFlows converts accumulated flow states into findings and sends them.
func (m *TLSObserverModule) emitFlows(
	ctx context.Context,
	flows map[flowKey]*flowState,
	flowSource string,
	findings chan<- *model.Finding,
) {
	for _, state := range flows {
		if state.clientHello == nil {
			continue
		}
		m.emitFlowFindings(ctx, state, flowSource, findings)
	}
}

// emitFlowFindings emits up to two findings for a single flow:
//  1. Negotiated cipher finding (if ServerHello present).
//  2. Fingerprint finding (always, if ClientHello present).
func (m *TLSObserverModule) emitFlowFindings(
	ctx context.Context,
	state *flowState,
	flowSource string,
	findings chan<- *model.Finding,
) {
	ch := state.clientHello

	sni := ch.SNI

	// --- 1. Negotiated cipher finding (requires ServerHello) ---
	if state.serverHello != nil {
		sh := state.serverHello
		cipherName := tls.CipherSuiteName(sh.CipherSuite)
		if cipherName == "" {
			cipherName = fmt.Sprintf("0x%04X", sh.CipherSuite)
		}

		asset := &model.CryptoAsset{
			ID:            uuid.Must(uuid.NewV7()).String(),
			Algorithm:     cipherName,
			SNI:           sni,
			TLSFlowSource: flowSource,
			State:         "IN_TRANSIT",
		}
		crypto.ClassifyCryptoAsset(asset)

		select {
		case <-ctx.Done():
			return
		case findings <- &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 9,
			Source: model.FindingSource{
				Type:            "network",
				DetectionMethod: "pcap",
			},
			CryptoAsset: asset,
			Confidence:  0.85,
			Module:      m.Name(),
		}:
		}
	}

	// --- 2. Fingerprint finding ---
	fp := computeFingerprint(ch, state.serverHello)

	fpAsset := &model.CryptoAsset{
		ID:              uuid.Must(uuid.NewV7()).String(),
		Algorithm:       "TLS",
		SNI:             sni,
		TLSFlowSource:   flowSource,
		JA3Fingerprint:  fp.JA3,
		JA3SFingerprint: fp.JA3S,
		JA4Fingerprint:  fp.JA4,
		JA4SFingerprint: fp.JA4S,
		State:           "IN_TRANSIT",
	}
	crypto.ClassifyCryptoAsset(fpAsset)

	select {
	case <-ctx.Done():
		return
	case findings <- &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 9,
		Source: model.FindingSource{
			Type:            "network",
			DetectionMethod: "pcap",
		},
		CryptoAsset: fpAsset,
		Confidence:  0.80,
		Module:      m.Name(),
	}:
	}
}

// computeFingerprint derives JA3/JA3S/JA4/JA4S from the flow's handshake messages.
func computeFingerprint(ch *tlsparse.ClientHelloInfo, sh *tlsparse.ServerHelloInfo) tlsparse.Fingerprint {
	var fp tlsparse.Fingerprint

	fp.JA3Raw, fp.JA3 = tlsparse.JA3(ch)
	fp.JA4 = tlsparse.JA4(ch)

	if sh != nil {
		fp.JA3SRaw, fp.JA3S = tlsparse.JA3S(sh)
		fp.JA4S = tlsparse.JA4S(sh)
	}

	return fp
}

// packetFlowKey constructs a flowKey from a packet (client→server direction).
func packetFlowKey(pkt *tlsparse.Packet) flowKey {
	srcIP := ""
	dstIP := ""
	if pkt.SrcIP != nil {
		srcIP = pkt.SrcIP.String()
	}
	if pkt.DstIP != nil {
		dstIP = pkt.DstIP.String()
	}
	return flowKey{
		srcIP:   srcIP,
		srcPort: pkt.SrcPort,
		dstIP:   dstIP,
		dstPort: pkt.DstPort,
	}
}

// defaultReaderFactory opens a pcap file or live capture depending on the
// target value prefix.
func (m *TLSObserverModule) defaultReaderFactory(target string) (tlsparse.PacketSource, error) {
	if strings.HasPrefix(target, "iface:") {
		iface := strings.TrimPrefix(target, "iface:")
		return tlsparse.NewLiveCaptureReader(iface, "tcp")
	}
	return tlsparse.NewPcapFileReader(target)
}
