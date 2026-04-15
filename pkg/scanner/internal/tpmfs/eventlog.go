package tpmfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// maxEventLogSize caps event-log byte reads.
const maxEventLogSize = 16 * 1024 * 1024

// maxDigestCount and maxEventSize provide defensive bounds against malformed
// or adversarial event logs. Legitimate logs have DigestCount ≤ ~8 and
// EventSize ≤ ~4 KB.
const (
	maxDigestCount = 64
	maxEventSize   = 256 * 1024
)

// ParseEventLog parses a TCG PC Client PFP TPM 2.0 binary event log.
// Returns an EventLog with per-event algorithm records and an aggregate
// AlgoCounts map. The spec-ID pseudo-header (a TCG_PCR_EVENT record at the
// start) is consumed but not added to Entries.
func ParseEventLog(data []byte) (*EventLog, error) {
	if len(data) > maxEventLogSize {
		return nil, fmt.Errorf("tpmfs: event log exceeds %d bytes", maxEventLogSize)
	}
	r := bytes.NewReader(data)

	// Consume the TCG_PCR_EVENT spec-ID pseudo-header.
	if err := skipSpecIDHeader(r); err != nil {
		return nil, fmt.Errorf("tpmfs: spec-ID header: %w", err)
	}

	log := &EventLog{AlgoCounts: map[HashAlgo]int{}}
	for r.Len() > 0 {
		entry, err := parseEvent2(r)
		if err != nil {
			return nil, err
		}
		log.Entries = append(log.Entries, *entry)
		for _, a := range entry.Algorithms {
			log.AlgoCounts[a]++
		}
	}
	return log, nil
}

// skipSpecIDHeader reads the TCG_PCR_EVENT (legacy-format) pseudo-header
// that precedes the TPM 2.0 event log.
func skipSpecIDHeader(r *bytes.Reader) error {
	// PCRIndex (4) + EventType (4) + DigestSHA1 (20) + EventSize (4).
	header := make([]byte, 32)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	eventSize := binary.LittleEndian.Uint32(header[28:32])
	if eventSize > maxEventSize {
		return fmt.Errorf("spec-ID event size %d exceeds cap", eventSize)
	}
	if _, err := io.CopyN(io.Discard, r, int64(eventSize)); err != nil {
		return fmt.Errorf("skip spec-ID body: %w", err)
	}
	return nil
}

// parseEvent2 reads one TCG_PCR_EVENT2 record.
func parseEvent2(r *bytes.Reader) (*EventLogEntry, error) {
	var pcrIndex, eventType, digestCount uint32
	if err := binary.Read(r, binary.LittleEndian, &pcrIndex); err != nil {
		return nil, fmt.Errorf("read PCRIndex: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &eventType); err != nil {
		return nil, fmt.Errorf("read EventType: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &digestCount); err != nil {
		return nil, fmt.Errorf("read DigestCount: %w", err)
	}
	if digestCount > maxDigestCount {
		return nil, fmt.Errorf("DigestCount %d exceeds cap %d", digestCount, maxDigestCount)
	}
	algos := make([]HashAlgo, 0, digestCount)
	for i := uint32(0); i < digestCount; i++ {
		var algID uint16
		if err := binary.Read(r, binary.LittleEndian, &algID); err != nil {
			return nil, fmt.Errorf("read algID: %w", err)
		}
		algo := HashAlgo(algID)
		size := algo.Size()
		if size == 0 {
			return nil, fmt.Errorf("unknown TPM_ALG_ID 0x%04x", algID)
		}
		if _, err := io.CopyN(io.Discard, r, int64(size)); err != nil {
			return nil, fmt.Errorf("skip digest bytes: %w", err)
		}
		algos = append(algos, algo)
	}
	var eventSize uint32
	if err := binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return nil, fmt.Errorf("read EventSize: %w", err)
	}
	if eventSize > maxEventSize {
		return nil, fmt.Errorf("EventSize %d exceeds cap %d", eventSize, maxEventSize)
	}
	if _, err := io.CopyN(io.Discard, r, int64(eventSize)); err != nil {
		return nil, fmt.Errorf("skip event body: %w", err)
	}
	return &EventLogEntry{
		PCRIndex:   pcrIndex,
		EventType:  eventType,
		Algorithms: algos,
	}, nil
}
