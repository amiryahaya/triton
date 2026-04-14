# ASN.1 OID Byte Scanner

## What it does

Walks executable binaries (ELF, Mach-O, PE), extracts read-only data sections,
and scans them byte-by-byte for DER-encoded OBJECT IDENTIFIERs (tag `0x06`).
Every valid OID discovered is cross-referenced against the curated registry in
`pkg/crypto/oid.go` (~200 entries) and emitted as a Finding with
`DetectionMethod: "asn1-oid"`.

## Why it complements existing scanners

`binary.go` (regex-based) and `library.go` (symbol-based) both rely on
human-readable names. Stripped, obfuscated, or custom-built binaries often
lose these names but *cannot* strip OIDs — OIDs are embedded as DER byte
sequences at runtime to construct protocol messages. Harvesting them directly
catches crypto that string-based scanners miss.

## Profile + license tier

- **Profile:** comprehensive only (not standard or quick)
- **License:** Pro+ (free tier stripped)
- **Cost:** ~50-200 ms per binary on a 2025-era laptop

## False-positive strategy

`FindOIDsInBuffer` applies five rejection rules to random byte sequences that
coincidentally start with `0x06`:

1. Content length must be 3-30 bytes
2. Length byte must use short form (high bit clear)
3. Final content byte's continuation bit must be clear (arc terminator)
4. First arc must be 0, 1, or 2 (X.690 §8.19.4)
5. Decoded arc count must be 3-20

Surviving candidates are looked up in the registry. Unknown OIDs are
discarded — an OID that isn't in the registry can't be classified, so
emitting it would create an unactionable finding.

## Limitations

- Does not detect OIDs passed dynamically (runtime-assembled from pieces)
- Only scans read-only data sections; OIDs in `.text` (inlined constants) are missed
- PE long-form length encoding rejected (<0.1% of real crypto OIDs use it)
- Universal Mach-O (fat) binaries: only the first architecture slice is scanned

## Agentless / remote scanning

Not supported. This scanner reads local filesystem files via stdlib
`os.Open` and parses ELF/Mach-O/PE sections with readers that require
random access to a local file descriptor. Agentless (remote) binary
scanning requires an `io.ReaderAt`-capable `FileReader` adapter and
section-extraction plumbing that accepts it — planned as a follow-up.
In agentless scans today this module is effectively a no-op.
