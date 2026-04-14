package crypto

// classicalOIDs returns the pre-PQC OIDs already recognized by Triton.
// New entries added in Task 2.
func classicalOIDs() map[string]OIDEntry {
	return map[string]OIDEntry{
		"1.2.840.113549.1.1.1":  {OID: "1.2.840.113549.1.1.1", Algorithm: "RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.11": {OID: "1.2.840.113549.1.1.11", Algorithm: "SHA256-RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.12": {OID: "1.2.840.113549.1.1.12", Algorithm: "SHA384-RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.113549.1.1.13": {OID: "1.2.840.113549.1.1.13", Algorithm: "SHA512-RSA", Family: "RSA", Status: TRANSITIONAL},
		"1.2.840.10045.2.1":     {OID: "1.2.840.10045.2.1", Algorithm: "EC", Family: "ECDSA", Status: TRANSITIONAL},
		"1.3.101.112":           {OID: "1.3.101.112", Algorithm: "Ed25519", Family: "EdDSA", KeySize: 256, Status: TRANSITIONAL},
		"1.3.101.113":           {OID: "1.3.101.113", Algorithm: "Ed448", Family: "EdDSA", KeySize: 448, Status: TRANSITIONAL},
	}
}
