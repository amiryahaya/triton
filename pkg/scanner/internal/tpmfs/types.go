// Package tpmfs parses Linux TPM sysfs artefacts (/sys/class/tpm/) and TCG
// event logs. Linux-only for the sysfs walker; the event-log parser is
// portable and runs on any OS (tested via committed binary fixtures).
package tpmfs

// Device captures one TPM device discovered under /sys/class/tpm/.
type Device struct {
	Path            string // e.g. "/sys/class/tpm/tpm0"
	Name            string // e.g. "tpm0"
	SpecVersion     string // "2.0" | "1.2"
	Vendor          string // human name, e.g. "Infineon"; vendor ID raw if unknown
	VendorRawID     string // 4-char ASCII manufacturer code
	FirmwareVersion string // vendor-specific, e.g. "4.32.1.2"
	Description     string // from device/description file, when present
	EKCertPath      string // sysfs path to endorsement_key_cert file, if present
}

// HashAlgo is a TPM_ALG_ID value from TCG specs.
type HashAlgo uint16

const (
	AlgSHA1   HashAlgo = 0x0004
	AlgSHA256 HashAlgo = 0x000B
	AlgSHA384 HashAlgo = 0x000C
	AlgSHA512 HashAlgo = 0x000D
	AlgSM3    HashAlgo = 0x0012
)

// Size returns the digest size in bytes for this algorithm. Returns 0 for
// unknown algorithms (parser must treat as fatal for the event it appears in).
func (a HashAlgo) Size() int {
	switch a {
	case AlgSHA1:
		return 20
	case AlgSHA256, AlgSM3:
		return 32
	case AlgSHA384:
		return 48
	case AlgSHA512:
		return 64
	}
	return 0
}

// String returns a human-readable name for the algorithm.
func (a HashAlgo) String() string {
	switch a {
	case AlgSHA1:
		return "SHA-1"
	case AlgSHA256:
		return "SHA-256"
	case AlgSHA384:
		return "SHA-384"
	case AlgSHA512:
		return "SHA-512"
	case AlgSM3:
		return "SM3"
	}
	return "unknown"
}

// EventLogEntry is one TCG_PCR_EVENT2 record after parsing.
type EventLogEntry struct {
	PCRIndex   uint32
	EventType  uint32
	Algorithms []HashAlgo // one per (algorithm, digest) pair in DigestValues
}

// EventLog holds a parsed TCG PFP binary event log.
type EventLog struct {
	Entries []EventLogEntry
	// Aggregate summary (populated by the parser):
	AlgoCounts map[HashAlgo]int // algo → number of events extending that bank
}

// EKCert holds a parsed endorsement-key certificate.
type EKCert struct {
	RawDER    []byte
	Algorithm string // "RSA" / "ECDSA" / "Ed25519"
	KeySize   int    // bits
	Subject   string
	Issuer    string
}
