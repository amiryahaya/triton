# Triton Licence Key Generation Guide

This guide covers how to generate Ed25519 keypairs, issue licence tokens, build Triton with your public key, and distribute licences to users.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Generate a Keypair](#3-generate-a-keypair)
4. [Issue a Licence Token](#4-issue-a-licence-token)
5. [Build Triton with Your Public Key](#5-build-triton-with-your-public-key)
6. [Distribute Licences](#6-distribute-licences)
7. [Verify a Licence](#7-verify-a-licence)
8. [Licence Tiers Reference](#8-licence-tiers-reference)
9. [Security Considerations](#9-security-considerations)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Overview

Triton uses Ed25519 digital signatures for offline licence validation. The system consists of:

- **Private key** — kept secret by the licence issuer, used to sign tokens
- **Public key** — embedded into the Triton binary at build time, used to verify tokens
- **Licence token** — a signed string containing tier, org, seats, and expiry

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  generate-keys  │         │  issue           │         │  Triton binary  │
│                 │         │                  │         │                 │
│  → public key   │────────▶│  private key +   │────────▶│  public key     │
│  → private key  │         │  claims          │         │  (embedded)     │
│                 │         │  → signed token  │         │  verifies token │
└─────────────────┘         └──────────────────┘         └─────────────────┘
```

The keygen tool is located at `internal/license/cmd/keygen/main.go` and is build-tagged with `//go:build ignore` so it never compiles into the production binary.

---

## 2. Prerequisites

- Go 1.21 or later installed
- Triton source code cloned locally

```bash
git clone https://github.com/amiryahaya/triton.git
cd triton
```

---

## 3. Generate a Keypair

Run the keygen tool to create a new Ed25519 keypair:

```bash
go run internal/license/cmd/keygen/main.go generate-keys
```

Output:

```
Public key (hex):  a1b2c3d4e5f6...  (64 hex characters = 32 bytes)
Private key (hex): f6e5d4c3b2a1...  (128 hex characters = 64 bytes)

Use the public key with -ldflags:
  go build -ldflags "-X github.com/amiryahaya/triton/internal/license.publicKeyHex=a1b2c3d4e5f6..."
```

**Save both keys securely.** You will need:
- The **public key** to build Triton binaries
- The **private key** to issue licence tokens

> **Important:** Generate the keypair only once. All licences must be signed with the same private key that matches the public key embedded in the binary.

---

## 4. Issue a Licence Token

Use the `issue` subcommand with your private key:

```bash
go run internal/license/cmd/keygen/main.go issue \
  --key <private-key-hex> \
  --tier pro \
  --org "Organisation Name" \
  --seats 10 \
  --days 365
```

### Parameters

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--key` | Yes | — | Private key in hex (128 hex characters) |
| `--tier` | No | `pro` | Licence tier: `free`, `pro`, `enterprise` |
| `--org` | Yes | — | Organisation name |
| `--seats` | No | `1` | Number of licensed seats |
| `--days` | No | `365` | Validity period in days from today |

### Examples

**Pro licence for 1 year, 10 seats:**
```bash
go run internal/license/cmd/keygen/main.go issue \
  --key f6e5d4c3b2a1... \
  --tier pro \
  --org "NACSA Malaysia" \
  --seats 10 \
  --days 365
```

**Enterprise licence for 2 years, 50 seats:**
```bash
go run internal/license/cmd/keygen/main.go issue \
  --key f6e5d4c3b2a1... \
  --tier enterprise \
  --org "Ministry of Digital" \
  --seats 50 \
  --days 730
```

**Short-term trial (30 days, free tier):**
```bash
go run internal/license/cmd/keygen/main.go issue \
  --key f6e5d4c3b2a1... \
  --tier free \
  --org "Trial User" \
  --seats 1 \
  --days 30
```

The command outputs a single-line token string:

```
eyJsaWQiOiI1YTgz...  (base64url-encoded claims + signature)
```

---

## 5. Build Triton with Your Public Key

Embed the public key into the Triton binary using Go linker flags:

```bash
go build -ldflags "-X github.com/amiryahaya/triton/internal/license.publicKeyHex=a1b2c3d4e5f6..." -o bin/triton .
```

Or set `GOFLAGS` before running `make build`:

```bash
export GOFLAGS='-ldflags=-X github.com/amiryahaya/triton/internal/license.publicKeyHex=a1b2c3d4e5f6...'
make build
```

### Cross-compile with Embedded Key

```bash
# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -ldflags "-X github.com/amiryahaya/triton/internal/license.publicKeyHex=a1b2c3d4e5f6..." -o bin/triton_darwin_arm64 .

# Linux AMD64
GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/amiryahaya/triton/internal/license.publicKeyHex=a1b2c3d4e5f6..." -o bin/triton_linux_amd64 .
```

> **Note:** Without the `-ldflags` override, the embedded public key defaults to all zeros. This causes all token verification to fail, and Triton falls back to free tier.

---

## 6. Distribute Licences

Send the token string to the user. They can activate it in three ways (checked in this order):

### Option 1: CLI Flag

```bash
triton --license-key eyJsaWQiOiI1YTgz... --profile standard
```

### Option 2: Environment Variable

```bash
export TRITON_LICENSE_KEY=eyJsaWQiOiI1YTgz...
triton --profile standard
```

### Option 3: Licence File (Recommended for Persistent Use)

```bash
mkdir -p ~/.triton
echo "eyJsaWQiOiI1YTgz..." > ~/.triton/license.key
triton --profile standard
```

The file method is recommended for end users as it persists across sessions without needing to set environment variables or pass flags.

---

## 7. Verify a Licence

### As the Issuer

Verify a token before sending it to a customer:

```bash
triton license verify eyJsaWQiOiI1YTgz...
```

### As the User

Check the currently active licence:

```bash
triton license show
```

Output includes: tier, seats, licence ID, organisation, issued date, expiry date, allowed profiles, formats, and modules.

---

## 8. Licence Tiers Reference

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Profile: quick | Yes | Yes | Yes |
| Profile: standard / comprehensive | — | Yes | Yes |
| Scanner modules | 3 | All 19 | All 19 |
| Format: JSON | Yes | Yes | Yes |
| Format: CDX, HTML, XLSX | — | Yes | Yes |
| Format: SARIF | — | — | Yes |
| Server mode (`triton server`) | — | — | Yes |
| Agent mode (`triton agent`) | — | — | Yes |
| Policy: builtin (NACSA-2030, CNSA-2.0) | — | Yes | Yes |
| Policy: custom YAML | — | — | Yes |
| Metrics / incremental scan | — | Yes | Yes |
| Diff / trend / history | — | Yes | Yes |
| DB persistence | — | Yes | Yes |
| Seats | 1 | Configured | Configured |

**Free tier modules:** certificates, keys, packages (3 modules only).

---

## 9. Security Considerations

### Private Key Storage

- Store the private key in a secure location (password manager, hardware security module, or encrypted vault)
- Never commit the private key to version control
- Never embed the private key in the Triton binary — only the public key is embedded
- Restrict access to the keygen tool in production environments

### Token Properties

- **Offline validation** — no network call or phone-home; verification uses the embedded public key
- **Tamper-proof** — any modification to the claims invalidates the Ed25519 signature
- **Expiry enforcement** — expired tokens degrade to free tier (5-minute grace period)
- **Graceful degradation** — invalid or missing tokens never block the tool; they fall back to free tier

### Key Rotation

To rotate keys:

1. Generate a new keypair
2. Rebuild Triton binaries with the new public key
3. Re-issue all active licences with the new private key
4. Distribute updated binaries and tokens to users

> Old tokens will not work with new binaries (different public key). Plan key rotation during a release cycle.

---

## 10. Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `triton license show` says "free tier" | No token found | Set `--license-key`, `TRITON_LICENSE_KEY`, or create `~/.triton/license.key` |
| Token reports "expired" | Past the `--days` validity | Issue a new token with a longer validity |
| Token reports "invalid signature" | Binary built without public key, or wrong keypair | Rebuild with the correct public key via `-ldflags` |
| `--key is required` error | Missing private key flag | Pass `--key <hex>` to the issue command |
| `--org is required` error | Missing organisation flag | Pass `--org "Name"` to the issue command |
| `private key must be 64 bytes` | Truncated or wrong key | Ensure the key is exactly 128 hex characters (64 bytes) |
| Features still gated after setting key | Token tier too low | Check the tier in the token matches the features needed (see tier matrix above) |
| `triton license verify` fails | Binary has zeroed public key | Build with your public key embedded |

### End-to-End Verification

Run this sequence to confirm everything works:

```bash
# 1. Generate keys
go run internal/license/cmd/keygen/main.go generate-keys
# Save the output

# 2. Issue a test token
go run internal/license/cmd/keygen/main.go issue \
  --key <private-key-hex> \
  --tier enterprise \
  --org "Test" \
  --seats 1 \
  --days 1

# 3. Build with the public key
go build -ldflags "-X github.com/amiryahaya/triton/internal/license.publicKeyHex=<public-key-hex>" -o bin/triton .

# 4. Verify
./bin/triton license verify <token>
./bin/triton --license-key <token> license show
```
