package crypto

// UEFIRevocation describes one hash that MUST be present in the dbx
// (forbidden signatures DB) to mitigate a known Secure Boot exploit.
type UEFIRevocation struct {
	CVE         string // e.g. "CVE-2023-24932"
	SHA256Hex   string // 64-char lowercase hex
	Description string
	Severity    string // CRITICAL | HIGH | MEDIUM
	Source      string // provenance
}

// uefiRevocationRegistry is the committed list of "must be revoked" hashes.
// Each entry is one binary bootloader hash whose presence in dbx is required
// to prevent a known exploit. Source provenance in the Source field.
//
// IMPORTANT: adding wrong hashes here causes false negatives (user thinks
// they're safe when they're not). Each entry carries a Source link.
var uefiRevocationRegistry = []UEFIRevocation{
	{
		CVE:         "CVE-2023-24932",
		SHA256Hex:   "80b4d96931bf0d02fd91a61e19d14f1da452e66db2408ca8604d411f92659f0a",
		Description: "BlackLotus UEFI bootkit — Windows Boot Manager binary hash",
		Severity:    "CRITICAL",
		Source:      "Microsoft KB5025885 (2023-05-09)",
	},
	{
		CVE:         "CVE-2020-10713",
		SHA256Hex:   "f52f83a3fa9cfbd6920f722824dbe4a0d9822b0b0aee355693f3f5cfd6b15757",
		Description: "BootHole — GRUB2 buffer overflow allowing Secure Boot bypass",
		Severity:    "CRITICAL",
		Source:      "UEFI Revocation List File update 2020-07-29",
	},
	{
		CVE:         "CVE-2022-21894",
		SHA256Hex:   "d626157e1d6a718bc124ab8da27cbb65072ca03a7b6b257dbdcbbd60f65ef3d1",
		Description: "Eclypsium Baton Drop — Windows Boot Manager secure-boot bypass",
		Severity:    "HIGH",
		Source:      "Microsoft KB5022497 (2023-01-10)",
	},
}

// LookupMissingRevocations returns all registry entries whose SHA256Hex is NOT
// present in the provided dbxHashes set. The caller builds the set from the
// dbx variable's EFI_CERT_SHA256 entries.
func LookupMissingRevocations(dbxHashes map[string]bool) []UEFIRevocation {
	out := []UEFIRevocation{}
	for _, r := range uefiRevocationRegistry {
		if !dbxHashes[r.SHA256Hex] {
			out = append(out, r)
		}
	}
	return out
}
