# Scanner Coverage Gaps — Roadmap

**Date:** 2026-04-11
**Status:** Parent roadmap. Individual waves will spawn their own design specs + implementation plans.
**Driven by:** `memory/scanner-coverage-gaps.md` audit of all 28 `pkg/scanner` modules against PQC-relevant asset domains.

> **For Claude:** This is the parent roadmap. Each wave below becomes its own `docs/plans/<date>-wave-N-*-design.md` + `-plan.md` pair when work starts, following the same flow as `docs/plans/2026-04-09-analytics-phases.md`. Do **not** try to execute the whole roadmap in one pass.

---

## 1. Context

Triton today ships **28 scanner modules**. An audit on 2026-04-11 mapped actual coverage against PQC-relevant asset domains and found the following overall picture:

**Strong domains (no action needed):** X.509/PKI, TLS transport, SSH, code signing, mail (SMTP+DKIM), password hashing, language dependencies, web app source, XML DSig/SAML, service mesh, kernel crypto, HSM PKCS#11, live LDAP.

**Weak domains (this roadmap):** OCI images, live Kubernetes, DNSSEC, firmware/Secure Boot, live VPN state, OIDC/JWKS discovery, network infrastructure protocols, database at-rest key material, secrets manager enumeration, messaging broker TLS/SASL, CI/CD provenance, live Kerberos enctypes, SCEP/EST/ACME enrollment.

The largest single blind spot is **cloud-native workloads**: Triton can read static Dockerfiles and K8s YAML but cannot open a container image or enumerate a live cluster's secrets, ingresses, or cert-manager resources.

---

## 2. Goals

1. Close every PQC-relevant scanner gap identified in the audit.
2. Preserve Triton's "single binary, TDD, >80% coverage" discipline — each new module follows the existing `Module` interface in `pkg/scanner/engine.go`.
3. Avoid scope creep into CSPM / general vulnerability scanning — findings must classify to a crypto algorithm or deliberately omit (Triton is a CBOM tool, not Trivy).
4. Keep the licence-tier story consistent: most new scanners land as **Pro**; live cloud/k8s enumeration and secrets manager access land as **Enterprise**.
5. Feed all new findings through the existing policy engine (NACSA-2030, CNSA-2.0) and Jadual 1/2 CSV pipeline without schema breakage.

---

## 3. Non-goals

- Runtime *behavioural* container scanning (syscall monitoring, drift detection) — out of scope; that's a CWPP.
- Vulnerability CVE matching against image SBOMs — Trivy/Grype already do this; Triton stays in its lane (crypto/algorithm inventory).
- Cloud KMS scanning — **explicitly removed from roadmap in v2.4** and not revisited here.
- Cloud provider native secrets inventory beyond Vault/AWS SM/Azure KV (the Wave 3 item 9 list is exhaustive).
- Windows-first firmware scanning — Linux-first for Wave 2 item 6; Windows/macOS deferred.
- Retrofitting existing modules — only **additive** new scanners and narrowly-scoped extensions flagged per item.

---

## 4. Cross-cutting prerequisites (Wave 0)

Must land **before** Wave 1. These are infrastructure changes that every new scanner depends on.

### 4.1 New `ScanTargetType` values

`pkg/scanner/engine.go` currently enumerates `TargetFilesystem`, `TargetNetwork`, `TargetDatabase` (and a few others). The engine's dispatch loop assumes a `Path` or `Host:Port` on every target. New values needed:

- `TargetOCIImage` — target is an image reference (`registry/name:tag`, `oci-layout:/path`, `docker-daemon:<id>`) plus optional registry credentials.
- `TargetKubernetesCluster` — target is a kubeconfig path + context name, or in-cluster SA detection.

Engine dispatch must route these to scanners that opt in via `ScanTargetType()`, and skip filesystem walkers that would otherwise panic on an empty `Path`.

### 4.2 Credential plumbing

Today all scanners assume local filesystem access. New scanners need typed credentials:

- Container registry auth (Docker config, env vars, cloud-provider auth helpers)
- kubeconfig path + context + optional bearer-token override
- Cloud SDK default credential chains (Vault token, AWS profile, Azure CLI login) — **read-only metadata only**

New file: `pkg/scanner/credentials.go` with a `ScanCredentials` struct wired through `scannerconfig.Config` and `cmd/root.go` flags (`--image`, `--kubeconfig`, `--k8s-context`, `--registry-auth`).

**Security constraint:** credentials never serialized into findings, never logged at info level, redacted in debug logs following the `vpn_config.go` `PrivateKey = "REDACTED"` precedent.

### 4.3 Licence tier assignment

Extend `internal/license/guard.go` `FilterConfig` module whitelist:

- Pro: `oci_image`, `dnssec`, `oidc_probe`, `vpn_runtime`, `firmware`, `netinfra`, `db_atrest`, `messaging`, `supply_chain`, `enrollment`
- Enterprise: `k8s_live`, `secrets_mgr`, `kerberos_runtime`

Free tier gets nothing new (stays on the current 3-module ceiling).

### 4.4 Jadual 1/2 CSV column mapping decision

**Open question for user:** do DNSSEC / firmware / live-k8s findings fit the existing Malay government CSV columns (Jadual 1 SBOM, Jadual 2 CBOM) as-is, or do we need a schema extension? This blocks government-format reporting for new domains but not CycloneDX CBOM output.

**Recommended default:** ship Waves 1–2 with CycloneDX coverage only, defer Jadual column mapping until we have real sample findings to show the user for column-choice confirmation.

### 4.5 Policy engine impact

Most new findings will Just Work via `CryptoAsset.Algorithm` which the existing NACSA-2030 and CNSA-2.0 matchers key off. Exceptions to verify during each wave's design spec:

- Firmware Secure Boot signature chains may need a new asset type (`AssetType: "firmware_signature"`)
- DNSSEC algorithm numbers (IANA registry) need translation to `pkg/crypto` registry names
- OIDC JWKS `alg` values use JWA naming (`RS256`, `ES384`) that need normalization to the registry's canonical `RSA`/`ECDSA-P384` form — reuse the `vpnAlgoTokenMap` pattern from `vpn_config.go`

---

## 5. Wave 1 — Foundational scan targets (2 sprints)

Biggest single user-visible wins. Both items share Wave 0 credential plumbing.

### 5.1 OCI image scanner — `pkg/scanner/oci_image.go`

**Effort:** ~2 weeks, one sprint. Single biggest gap.

**Approach:**
- Import `github.com/google/go-containerregistry/pkg/v1/remote` (already a Triton-friendly pure-Go, zero-CGO dependency)
- Resolve image ref → pull manifest → extract layers to tmpfs in a sandboxed directory
- For each layer, run the existing `certificates`, `keys`, `library`, `binary`, `deps`, `configs`, `webapp` modules against the extracted rootfs via a synthetic `TargetFilesystem` sub-scan
- Aggregate findings under an `ImageScanSummary` with image digest, layer count, base image detection
- Side effect: cosign / notary signatures attached to the image can be fetched and verified during the same round trip (extend `container_signatures.go`)

**CLI:** `triton scan --image nginx:1.25 --profile standard`

**Out of scope for v1:** image diff (comparing two image digests), SBOM import from images that already ship one (`/usr/share/doc/...`), multi-arch manifest fan-out (scan first matching arch only).

### 5.2 Live Kubernetes cluster scanner — `pkg/scanner/k8s_live.go`

**Effort:** ~2 weeks, second sprint (serialized after OCI to avoid stacking auth complexity).

**Approach:**
- `k8s.io/client-go` against a kubeconfig or in-cluster service account
- Enumerate across all namespaces (or a `--k8s-namespace` filter):
  - `Secret` where `type: kubernetes.io/tls` → decode `tls.crt` / `tls.key` through existing cert/key parsers
  - `Ingress.spec.tls` → cross-reference to referenced Secrets, record hostname → cert mapping
  - `cert-manager.io/v1` CRDs: `Certificate`, `Issuer`, `ClusterIssuer`, `CertificateRequest`
  - `ValidatingWebhookConfiguration` / `MutatingWebhookConfiguration` `.webhooks[].clientConfig.caBundle`
  - `ServiceAccount` tokens actually mounted into running pods (not just existing)
  - `kube-apiserver` / `kubelet` client cert paths if detectable via `kubectl get --raw /configz`

**CLI:** `triton scan --kubeconfig ~/.kube/config --k8s-context prod`

**Security constraint:** never serialize raw `Secret.data` values; only algorithm + key size + subject metadata. Follow the `container_signatures.go` SA-token-header-only precedent.

**Out of scope for v1:** multi-cluster federation, mTLS-based kubelet scanning, custom CRDs beyond cert-manager.

---

## 6. Wave 2 — High PQC-impact scanners (5 items, ship in parallel where possible)

### 6.1 DNSSEC scanner — `pkg/scanner/dnssec.go`
Parse BIND/NSD/Knot zone files for DNSKEY/DS/RRSIG algorithm numbers. Optional active query mode (`dig DNSKEY example.com`) for a target zone. Pure RSA/ECDSA/EdDSA inventory.
**Effort:** ~1 week.

### 6.2 OIDC/JWKS discovery probe
Extend `pkg/scanner/protocol.go` or new `oidc.go`. Fetch `/.well-known/openid-configuration`, follow `jwks_uri`, enumerate `id_token_signing_alg_values_supported` and the actual JWK set. Smallest sprint, highest value-per-LOC ratio — **ship in parallel with Wave 1**.
**Effort:** ~3 days.

### 6.3 Live VPN state scanner
Extend `vpn_config.go` or new `vpn_runtime.go`. Parse output of `ipsec statusall`, `wg show`, `openvpn --status` (if socket available). Records **negotiated** algorithms (which can differ from configured due to peer downgrades).
**Effort:** ~1 week.

### 6.4 Firmware / Secure Boot scanner — `pkg/scanner/firmware.go`
- `/sys/firmware/efi/efivars/PK-*`, `KEK-*`, `db-*`, `dbx-*` — EFI_SIGNATURE_LIST parsing
- `mokutil --list-enrolled` — shim MOK chain
- `/sys/class/tpm/tpm0/` — TPM version, PCR policy presence
- Measured-boot event log at `/sys/kernel/security/tpm0/binary_bios_measurements`
- BMC/Redfish as optional HTTP probe for server hardware

Linux-first. Windows Secure Boot via `Get-SecureBootPolicy` deferred to Wave 4.
**Effort:** ~2 weeks.

### 6.5 Network infrastructure scanner — `pkg/scanner/netinfra.go`
Config-parse only for v1:
- SNMPv3 `/etc/snmp/snmpd.conf` — `usmUser` auth/priv algorithms
- BGP TCP-AO / MD5 — bird, FRR (`frr.conf`), Quagga (`bgpd.conf`)
- RPKI ROA signing algorithm — `rpki-client` output or `routinator` config
- 802.1X RADIUS shared-secret presence (redacted), EAP method
- NTS — chrony `/etc/chrony/chrony.conf`, ntpsec `/etc/ntp.conf` `nts` directives
- syslog-TLS — rsyslog `/etc/rsyslog.d/*.conf` `gtls` driver, syslog-ng `transport("tls")`

**Effort:** ~2 weeks. Largest content load; consider splitting into two sprints.

---

## 7. Wave 3 — Meaningful gaps (6 items)

Lower PQC urgency but meaningful compliance coverage. Each ~1–2 weeks, no strong ordering between them.

1. **Database at-rest key material** — Oracle Wallet (`.ewl`/`.cwl`), MSSQL cert files, MySQL keyring, LUKS header (`cryptsetup luksDump`), BitLocker metadata, FileVault. Extends `database.go`.
2. **Secrets manager live enumeration** — `pkg/scanner/secrets_mgr.go`. Vault `/sys/mounts` + transit list, AWS Secrets Manager ListSecrets, Azure Key Vault list-keys. Metadata only, never values.
3. **Messaging broker TLS/SASL** — `pkg/scanner/messaging.go`. Kafka `server.properties`, RabbitMQ `rabbitmq.conf`, NATS `tls {}`, Mosquitto listener TLS, Redis `tls-*`.
4. **CI/CD provenance** — extend `container_signatures.go` or new `supply_chain.go`. SLSA `.slsa.json`, in-toto `.link`, Fulcio trust roots, GitHub Actions OIDC trust configs.
5. **Kerberos live enctype enumeration** — extend `auth_material.go`. `klist -e`, KDC `permitted_enctypes` / `default_tkt_enctypes`, AD `supportedEncryptionTypes` via LDAP.
6. **SCEP/EST/ACME enrollment** — `pkg/scanner/enrollment.go`. certbot account keys, EST client configs, SCEP profile files, MDM enrollment.

---

## 8. Wave 4 — Nice-to-have (deferred)

1. Helm chart CBOM (render with default values → feed through containers module)
2. S/MIME at rest (Outlook PST index, MIME multipart/signed)
3. FIDO2/WebAuthn credential storage
4. Registry image signature verification against remote refs (full cosign/notary chain)
5. Blockchain wallet keys (bitcoin-core wallet.dat, Ethereum keystore JSON — algorithm reporting only, zero key extraction)

---

## 9. Sequencing

```
Wave 0 (prereqs)
  ├── Sprint 0: ScanTargetType + credential plumbing + licence wiring
  │
Wave 1 (foundational)
  ├── Sprint 1: OCI image scanner        ┐
  │             + OIDC/JWKS probe (6.2)  │  parallel
  │             (shares Wave 0 infra)    ┘
  ├── Sprint 2: Live Kubernetes scanner
  │
Wave 2 (high-impact)
  ├── Sprint 3: DNSSEC scanner
  ├── Sprint 4: Live VPN state + Firmware/Secure Boot (parallel)
  ├── Sprint 5: Network infra (may split into 5a/5b)
  │
Wave 3 (meaningful)
  ├── Sprints 6–11: one item per sprint, no strong ordering
  │
Wave 4 (nice-to-have)
  └── Deferred to post-roadmap backlog
```

**Total estimated effort:** ~14–16 sprints for Waves 0–3 (roughly 3–4 months of focused work assuming one scanner per sprint with TDD + code review gates per project workflow).

---

## 10. Success criteria

Per wave:
- All new modules implement `Module` interface from `pkg/scanner/engine.go`
- >80% test coverage per module (`make test` + `make test-integration` green)
- Findings route through existing policy engine (NACSA-2030, CNSA-2.0) and produce expected violations for known-weak inputs
- CycloneDX CBOM output includes new findings under correct asset type
- Licence tier enforcement verified via `FilterConfig` test
- Code review signed off (mandatory project workflow gate)
- `MEMORY.md` sprint-completion entry + `scanner-coverage-gaps.md` wave marked ✅

Overall roadmap:
- All 13 Wave 1–3 items shipped
- `scanner-coverage-gaps.md` gap list reduced to Wave 4 only
- Scanner module count grows from 28 → ~41
- No regression in existing scanner test coverage or runtime performance

---

## 11. Open questions

1. **Jadual 1/2 column mapping** — see §4.4. User decision needed before Wave 2 ships.
2. **Registry auth precedence** — Docker config vs env vars vs cloud helper? Default to `go-containerregistry` `authn.DefaultKeychain` but need to confirm.
3. **Kubernetes RBAC floor** — what's the minimum ClusterRole we recommend for the scanner SA? Draft: `get`/`list` on `secrets`, `ingresses`, `validatingwebhookconfigurations`, `mutatingwebhookconfigurations`, `serviceaccounts`, `configmaps` + cert-manager.io group read access.
4. **TPM access on hardened hosts** — many production systems lock `/sys/class/tpm/tpm0/` to root-only. Do we document the privilege requirement and skip gracefully, or require a setcap grant?
5. **Network infra scanner split** — is 6.5 one sprint or two? Content load suggests two (SNMP+802.1X+syslog-TLS; BGP+RPKI+NTS).

Answer these before Wave 2 kicks off. Waves 0–1 are self-contained and can start once this roadmap is approved.
