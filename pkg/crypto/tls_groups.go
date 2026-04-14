package crypto

import "strings"

// TLSGroup represents a TLS named group (key exchange identifier) from the
// IANA TLS SupportedGroups registry, extended with PQC metadata.
//
// Reference: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
// NIST PQ TLS hybrids: draft-kwiatkowski-tls-ecdhe-mlkem + draft-tls-westerbaan-xyber768d00
type TLSGroup struct {
	ID                  uint16
	Name                string   // Canonical name (matches OpenSSL/BoringSSL naming where possible)
	Family              string   // "ECDHE", "DHE", "Lattice", "Hybrid-ECDHE-MLKEM", etc.
	KeySize             int      // Effective classical key size (bits)
	IsHybrid            bool     // Composite with classical + PQC
	ComponentAlgorithms []string // For hybrids: ["X25519", "ML-KEM-768"]
	Status              PQCStatus
}

// tlsGroupRegistry maps IANA TLS group IDs to their metadata.
// Populated in init() from tlsGroupData(). Read-only after init.
var (
	tlsGroupRegistry  map[uint16]TLSGroup
	tlsGroupNameIndex map[string]TLSGroup // lowercased-name → group
)

func init() {
	data := tlsGroupData()
	tlsGroupRegistry = make(map[uint16]TLSGroup, len(data))
	tlsGroupNameIndex = make(map[string]TLSGroup, len(data))
	for _, g := range data {
		tlsGroupRegistry[g.ID] = g
		tlsGroupNameIndex[strings.ToLower(g.Name)] = g
	}
}

// LookupTLSGroup returns the TLS group metadata for a given IANA ID, or
// (zero, false) if the ID is unknown. Used by the protocol scanner after
// `tls.ConnectionState.CurveID` is read post-handshake.
func LookupTLSGroup(id uint16) (TLSGroup, bool) {
	g, ok := tlsGroupRegistry[id]
	return g, ok
}

// LookupTLSGroupByName does a case-insensitive lookup of a group by its
// canonical name. Used by config-file scanners that encounter group names
// as strings (e.g., `ssl_ecdh_curve X25519MLKEM768` in nginx).
func LookupTLSGroupByName(name string) (TLSGroup, bool) {
	g, ok := tlsGroupNameIndex[strings.ToLower(name)]
	return g, ok
}

// tlsGroupData returns the full IANA + hybrid-PQC group registry. Kept
// in a separate function so additions don't churn init().
func tlsGroupData() []TLSGroup {
	return []TLSGroup{
		// --- Classical elliptic curves ---
		{ID: 0x0017, Name: "secp256r1", Family: "ECDHE", KeySize: 256, Status: TRANSITIONAL},
		{ID: 0x0018, Name: "secp384r1", Family: "ECDHE", KeySize: 384, Status: SAFE},
		{ID: 0x0019, Name: "secp521r1", Family: "ECDHE", KeySize: 521, Status: SAFE},
		{ID: 0x001D, Name: "x25519", Family: "ECDHE", KeySize: 256, Status: TRANSITIONAL},
		{ID: 0x001E, Name: "x448", Family: "ECDHE", KeySize: 448, Status: SAFE},

		// --- Classical finite-field DHE ---
		{ID: 0x0100, Name: "ffdhe2048", Family: "DHE", KeySize: 2048, Status: TRANSITIONAL},
		{ID: 0x0101, Name: "ffdhe3072", Family: "DHE", KeySize: 3072, Status: SAFE},
		{ID: 0x0102, Name: "ffdhe4096", Family: "DHE", KeySize: 4096, Status: SAFE},
		{ID: 0x0103, Name: "ffdhe6144", Family: "DHE", KeySize: 6144, Status: SAFE},
		{ID: 0x0104, Name: "ffdhe8192", Family: "DHE", KeySize: 8192, Status: SAFE},

		// --- Brainpool curves ---
		{ID: 0x001A, Name: "brainpoolP256r1", Family: "ECDHE", KeySize: 256, Status: TRANSITIONAL},
		{ID: 0x001B, Name: "brainpoolP384r1", Family: "ECDHE", KeySize: 384, Status: TRANSITIONAL},
		{ID: 0x001C, Name: "brainpoolP512r1", Family: "ECDHE", KeySize: 512, Status: SAFE},

		// --- Deprecated/legacy ---
		{ID: 0x0015, Name: "secp192r1", Family: "ECDHE", KeySize: 192, Status: UNSAFE},
		{ID: 0x0016, Name: "secp224r1", Family: "ECDHE", KeySize: 224, Status: DEPRECATED},

		// --- Pure PQC KEMs (standalone, not hybrid) ---
		{ID: 0x0200, Name: "MLKEM512", Family: "Lattice", KeySize: 512, Status: SAFE,
			ComponentAlgorithms: []string{"ML-KEM-512"}},
		{ID: 0x0201, Name: "MLKEM768", Family: "Lattice", KeySize: 768, Status: SAFE,
			ComponentAlgorithms: []string{"ML-KEM-768"}},
		{ID: 0x0202, Name: "MLKEM1024", Family: "Lattice", KeySize: 1024, Status: SAFE,
			ComponentAlgorithms: []string{"ML-KEM-1024"}},

		// --- NIST-ratified hybrid ML-KEM groups (draft-kwiatkowski-tls-ecdhe-mlkem) ---
		{ID: 0x11EB, Name: "SecP256r1MLKEM768", Family: "Hybrid-ECDHE-MLKEM", KeySize: 256, IsHybrid: true,
			ComponentAlgorithms: []string{"secp256r1", "ML-KEM-768"}, Status: SAFE},
		{ID: 0x11EC, Name: "X25519MLKEM768", Family: "Hybrid-ECDHE-MLKEM", KeySize: 256, IsHybrid: true,
			ComponentAlgorithms: []string{"X25519", "ML-KEM-768"}, Status: SAFE},
		{ID: 0x11ED, Name: "SecP384r1MLKEM1024", Family: "Hybrid-ECDHE-MLKEM", KeySize: 384, IsHybrid: true,
			ComponentAlgorithms: []string{"secp384r1", "ML-KEM-1024"}, Status: SAFE},

		// --- Draft Kyber hybrids (pre-standard, deployed 2023-2025) ---
		{ID: 0x6399, Name: "X25519Kyber768Draft00", Family: "Hybrid-Draft-Kyber", KeySize: 256, IsHybrid: true,
			ComponentAlgorithms: []string{"X25519", "Kyber-768"}, Status: SAFE},
		{ID: 0x639A, Name: "SecP256r1Kyber768Draft00", Family: "Hybrid-Draft-Kyber", KeySize: 256, IsHybrid: true,
			ComponentAlgorithms: []string{"secp256r1", "Kyber-768"}, Status: SAFE},
		{ID: 0xFE30, Name: "X25519Kyber512Draft00", Family: "Hybrid-Draft-Kyber", KeySize: 256, IsHybrid: true,
			ComponentAlgorithms: []string{"X25519", "Kyber-512"}, Status: SAFE},
		{ID: 0xFE31, Name: "X25519Kyber768Draft00Old", Family: "Hybrid-Draft-Kyber", KeySize: 256, IsHybrid: true,
			ComponentAlgorithms: []string{"X25519", "Kyber-768"}, Status: SAFE},

		// --- OpenSSL/OQS provider pure-PQ group IDs (oqs-provider convention) ---
		// Used when OpenSSL is built with liboqs for experimental PQC support.
		// Values from the oqs-provider group-table: https://github.com/open-quantum-safe/oqs-provider
		{ID: 0x023A, Name: "frodo640aes", Family: "Lattice", KeySize: 640, Status: SAFE,
			ComponentAlgorithms: []string{"FrodoKEM-640-AES"}},
		{ID: 0x023C, Name: "frodo976aes", Family: "Lattice", KeySize: 976, Status: SAFE,
			ComponentAlgorithms: []string{"FrodoKEM-976-AES"}},
	}
}
