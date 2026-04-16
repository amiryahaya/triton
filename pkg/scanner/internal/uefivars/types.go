// Package uefivars parses UEFI Secure Boot variables from /sys/firmware/efi/efivars/.
// Pure parser: zero domain-string emission. Classification stays in the scanner module.
package uefivars

// efiAttrPrefixLen is the 4-byte EFI_VARIABLE_ATTRIBUTES header that precedes
// every variable value file in /sys/firmware/efi/efivars/.
const efiAttrPrefixLen = 4

// EFI_GLOBAL_VARIABLE GUID used by Secure Boot variables (PK, KEK, db, dbx, SecureBoot, SetupMode).
const EFIGlobalGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

// Signature type GUIDs (lowercase, dashes included — match kernel file-name format).
const (
	// EFI_CERT_X509_GUID — signature data is a DER X.509 certificate.
	CertX509GUID = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
	// EFI_CERT_SHA256_GUID — signature data is a 32-byte SHA-256 hash.
	CertSHA256GUID = "c1c41626-504c-4092-aca9-41f936934328"
)

// SignatureType discriminates entries returned by ParseSignatureList.
type SignatureType int

const (
	SigTypeUnknown SignatureType = iota
	SigTypeX509
	SigTypeSHA256
)

// SignatureEntry is one entry inside an EFI_SIGNATURE_LIST.
type SignatureEntry struct {
	Type       SignatureType
	OwnerGUID  string // 16 bytes rendered as hex for attribution
	Data       []byte // DER cert or 32-byte hash, depending on Type
	ListIndex  int    // 0-based index of the parent EFI_SIGNATURE_LIST
	EntryIndex int    // 0-based index within the parent list
}
