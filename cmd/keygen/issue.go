//go:build ignore

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/amiryahaya/triton/internal/license"
)

func main() {
	// Generate a fresh Ed25519 keypair
	pub, priv, err := license.GenerateKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating keypair: %v\n", err)
		os.Exit(1)
	}

	// Issue enterprise licence — unbound (no machine binding) for client sharing
	token, err := license.IssueTokenWithOptions(
		priv,
		license.TierEnterprise,
		"Antrapolation",
		10,    // seats
		90,    // days
		false, // no machine binding
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error issuing token: %v\n", err)
		os.Exit(1)
	}

	expiry := time.Now().Add(90 * 24 * time.Hour)

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║          TRITON ENTERPRISE LICENSE — Antrapolation          ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║ Tier:           Enterprise                                 ║")
	fmt.Println("║ Organization:   Antrapolation                              ║")
	fmt.Println("║ Seats:          10                                         ║")
	fmt.Printf("║ Expires:        %-43s║\n", expiry.Format("2006-01-02"))
	fmt.Println("║ Machine Bound:  No (portable)                              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Println("=== LICENSE TOKEN ===")
	fmt.Println("(Save to ~/.triton/license.key or pass via --license-key flag)")
	fmt.Println()
	fmt.Println(token)
	fmt.Println()

	fmt.Println("=== Ed25519 PUBLIC KEY ===")
	fmt.Println("(Embed in triton binary at build time)")
	fmt.Println()
	pubHex := hex.EncodeToString(pub)
	fmt.Println(pubHex)
	fmt.Println()

	fmt.Println("=== BUILD COMMAND ===")
	fmt.Println("Build triton with this public key to verify the license:")
	fmt.Println()
	fmt.Printf("go build -ldflags \"-X github.com/amiryahaya/triton/internal/license.publicKeyHex=%s\" -o bin/triton .\n", pubHex)
	fmt.Println()

	fmt.Println("=== Ed25519 PRIVATE KEY (KEEP SECRET) ===")
	fmt.Println(hex.EncodeToString(priv))
	fmt.Println()

	// Also verify the token roundtrips
	lic, err := license.Parse(token, ed25519.PublicKey(pub))
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: token verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Verified: lid=%s tier=%s org=%s seats=%d expires=%s\n",
		lic.ID, lic.Tier, lic.Org, lic.Seats,
		time.Unix(lic.ExpiresAt, 0).UTC().Format(time.RFC3339))
}
