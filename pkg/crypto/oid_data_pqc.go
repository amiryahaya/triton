package crypto

// pqcOIDs returns the NIST FIPS 203/204/205/206 OIDs plus IETF LAMPS composite OIDs.
// Kept in its own file so new PQC entries can be added without churning oid.go.
func pqcOIDs() map[string]OIDEntry {
	return map[string]OIDEntry{
		// ML-KEM (FIPS 203)
		"2.16.840.1.101.3.4.4.1": {OID: "2.16.840.1.101.3.4.4.1", Algorithm: "ML-KEM-512", Family: "Lattice", KeySize: 512, Status: SAFE},
		"2.16.840.1.101.3.4.4.2": {OID: "2.16.840.1.101.3.4.4.2", Algorithm: "ML-KEM-768", Family: "Lattice", KeySize: 768, Status: SAFE},
		"2.16.840.1.101.3.4.4.3": {OID: "2.16.840.1.101.3.4.4.3", Algorithm: "ML-KEM-1024", Family: "Lattice", KeySize: 1024, Status: SAFE},

		// ML-DSA (FIPS 204)
		"2.16.840.1.101.3.4.3.17": {OID: "2.16.840.1.101.3.4.3.17", Algorithm: "ML-DSA-44", Family: "Lattice", Status: SAFE},
		"2.16.840.1.101.3.4.3.18": {OID: "2.16.840.1.101.3.4.3.18", Algorithm: "ML-DSA-65", Family: "Lattice", Status: SAFE},
		"2.16.840.1.101.3.4.3.19": {OID: "2.16.840.1.101.3.4.3.19", Algorithm: "ML-DSA-87", Family: "Lattice", Status: SAFE},

		// SLH-DSA (FIPS 205) — 12 variants
		"2.16.840.1.101.3.4.3.20": {OID: "2.16.840.1.101.3.4.3.20", Algorithm: "SLH-DSA-SHA2-128s", Family: "Hash-Based", KeySize: 128, Status: SAFE},
		"2.16.840.1.101.3.4.3.21": {OID: "2.16.840.1.101.3.4.3.21", Algorithm: "SLH-DSA-SHA2-128f", Family: "Hash-Based", KeySize: 128, Status: SAFE},
		"2.16.840.1.101.3.4.3.22": {OID: "2.16.840.1.101.3.4.3.22", Algorithm: "SLH-DSA-SHA2-192s", Family: "Hash-Based", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.3.23": {OID: "2.16.840.1.101.3.4.3.23", Algorithm: "SLH-DSA-SHA2-192f", Family: "Hash-Based", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.3.24": {OID: "2.16.840.1.101.3.4.3.24", Algorithm: "SLH-DSA-SHA2-256s", Family: "Hash-Based", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.3.25": {OID: "2.16.840.1.101.3.4.3.25", Algorithm: "SLH-DSA-SHA2-256f", Family: "Hash-Based", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.3.26": {OID: "2.16.840.1.101.3.4.3.26", Algorithm: "SLH-DSA-SHAKE-128s", Family: "Hash-Based", KeySize: 128, Status: SAFE},
		"2.16.840.1.101.3.4.3.27": {OID: "2.16.840.1.101.3.4.3.27", Algorithm: "SLH-DSA-SHAKE-128f", Family: "Hash-Based", KeySize: 128, Status: SAFE},
		"2.16.840.1.101.3.4.3.28": {OID: "2.16.840.1.101.3.4.3.28", Algorithm: "SLH-DSA-SHAKE-192s", Family: "Hash-Based", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.3.29": {OID: "2.16.840.1.101.3.4.3.29", Algorithm: "SLH-DSA-SHAKE-192f", Family: "Hash-Based", KeySize: 192, Status: SAFE},
		"2.16.840.1.101.3.4.3.30": {OID: "2.16.840.1.101.3.4.3.30", Algorithm: "SLH-DSA-SHAKE-256s", Family: "Hash-Based", KeySize: 256, Status: SAFE},
		"2.16.840.1.101.3.4.3.31": {OID: "2.16.840.1.101.3.4.3.31", Algorithm: "SLH-DSA-SHAKE-256f", Family: "Hash-Based", KeySize: 256, Status: SAFE},

		// FN-DSA (FIPS 206, provisional)
		"2.16.840.1.101.3.4.3.32": {OID: "2.16.840.1.101.3.4.3.32", Algorithm: "FN-DSA-512", Family: "Lattice", KeySize: 512, Status: SAFE},
		"2.16.840.1.101.3.4.3.33": {OID: "2.16.840.1.101.3.4.3.33", Algorithm: "FN-DSA-1024", Family: "Lattice", KeySize: 1024, Status: SAFE},

		// Composite Signatures (IETF LAMPS draft-ietf-lamps-pq-composite-sigs)
		"2.16.840.1.114027.80.8.1.1":  {OID: "2.16.840.1.114027.80.8.1.1", Algorithm: "ML-DSA-44-RSA-2048", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.2":  {OID: "2.16.840.1.114027.80.8.1.2", Algorithm: "ML-DSA-44-RSA-2048-PSS", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.3":  {OID: "2.16.840.1.114027.80.8.1.3", Algorithm: "ML-DSA-44-Ed25519", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.4":  {OID: "2.16.840.1.114027.80.8.1.4", Algorithm: "ML-DSA-44-ECDSA-P256", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.5":  {OID: "2.16.840.1.114027.80.8.1.5", Algorithm: "ML-DSA-65-RSA-3072", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.6":  {OID: "2.16.840.1.114027.80.8.1.6", Algorithm: "ML-DSA-65-RSA-3072-PSS", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.7":  {OID: "2.16.840.1.114027.80.8.1.7", Algorithm: "ML-DSA-65-RSA-4096", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.8":  {OID: "2.16.840.1.114027.80.8.1.8", Algorithm: "ML-DSA-65-RSA-4096-PSS", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.9":  {OID: "2.16.840.1.114027.80.8.1.9", Algorithm: "ML-DSA-65-ECDSA-P384", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.10": {OID: "2.16.840.1.114027.80.8.1.10", Algorithm: "ML-DSA-65-Ed25519", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.11": {OID: "2.16.840.1.114027.80.8.1.11", Algorithm: "ML-DSA-87-ECDSA-P384", Family: "Composite", Status: SAFE},
		"2.16.840.1.114027.80.8.1.12": {OID: "2.16.840.1.114027.80.8.1.12", Algorithm: "ML-DSA-87-Ed448", Family: "Composite", Status: SAFE},
	}
}
