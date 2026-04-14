# Hybrid PQC Detection

Triton detects hybrid post-quantum cryptography (classical + PQ composite) across three surfaces, unified under `CryptoAsset.IsHybrid` + `CryptoAsset.ComponentAlgorithms` in the data model.

## Detection surfaces

1. **TLS wire detection** — `pkg/scanner/protocol.go` reads `tls.ConnectionState.CurveID` after each handshake and looks up the negotiated named group in `pkg/crypto/tls_groups.go`. Supports NIST-ratified hybrid groups (`X25519MLKEM768` 0x11EC, `SecP256r1MLKEM768` 0x11EB, `SecP384r1MLKEM1024` 0x11ED) and draft Kyber variants (`X25519Kyber768Draft00` 0x6399, `SecP256r1Kyber768Draft00` 0x639A, and pre-standard old-draft variants).

2. **Composite certificate signatures** — `pkg/scanner/certificate.go` detects composite signature OIDs via `crypto.IsCompositeOID` + `crypto.CompositeComponents`. `pkg/scanner/asn1_oid.go` applies the same classification to composite OIDs discovered during binary byte-level scanning, so the hybrid flag is populated consistently whether the OID came from a parsed certificate or from a DER pattern in a binary section.

3. **Config file declarations** — `pkg/scanner/web_server.go` parses nginx `ssl_ecdh_curve`, Apache `SSLOpenSSLConfCmd Groups`, and OpenSSL `Groups =` / `Curves =` directives. Hybrid group names resolve via case-insensitive name-based registry lookup (`LookupTLSGroupByName`).

## What's emitted

```json
{
  "algorithm": "X25519MLKEM768",
  "function": "Key agreement",
  "keySize": 256,
  "isHybrid": true,
  "componentAlgorithms": ["X25519", "ML-KEM-768"],
  "pqcStatus": "SAFE"
}
```

## Report surfacing

- **CycloneDX 1.7 CBOM** — `algorithmProperties.isHybrid` and `algorithmProperties.componentAlgorithms` are emitted for hybrid findings. The composite group name is used as `parameterSetIdentifier` (e.g. `"parameterSetIdentifier": "X25519MLKEM768"`).
- **HTML CBOM report** — Hybrid findings show a `HYBRID` badge next to the algorithm name, with a tooltip listing the composition (e.g. `Hybrid: X25519 + ML-KEM-768`).
- **JSON / Triton native** — `CryptoAsset.IsHybrid` and `CryptoAsset.ComponentAlgorithms` flow through unchanged.

## Requirements

- TLS wire detection requires Go 1.24+ for `tls.CurveID` to expose ratified hybrid groups like `X25519MLKEM768`. Triton's `go.mod` requires Go 1.25+, so this is always satisfied.
- Only the *negotiated* group is detected on the wire. Enumerating the server's full list of supported groups requires a custom ClientHello probe and is out of scope for this module.

## Registry

`pkg/crypto/tls_groups.go` holds the full IANA + hybrid-PQC registry. Additions go in `tlsGroupData()`. The registry is indexed both by IANA group ID (`LookupTLSGroup(id uint16)`) and by case-insensitive canonical name (`LookupTLSGroupByName(name string)`).

## Tests

- Unit: `pkg/crypto/tls_groups_test.go`, `pkg/scanner/protocol_groups_test.go`, `pkg/scanner/asn1_oid_test.go`, `pkg/scanner/web_server_test.go`, `pkg/report/cyclonedx_test.go`, `pkg/report/generator_test.go` (hybrid badge).
- Integration: `test/integration/hybrid_pqc_test.go` — smoke test against `pq.cloudflareresearch.com:443`; skips gracefully when offline.
