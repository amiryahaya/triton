//go:build ignore

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/amiryahaya/triton/internal/license"
)

func main() {
	pub, priv, err := license.GenerateKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating keypair: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Triton License Server Ed25519 Keypair ===")
	fmt.Println()
	fmt.Println("SIGNING_KEY (private, set as TRITON_LICENSE_SERVER_SIGNING_KEY):")
	fmt.Println(hex.EncodeToString(priv))
	fmt.Println()
	fmt.Println("PUBLIC_KEY (embed in CLI builds or use for verification):")
	fmt.Println(hex.EncodeToString(pub))
	fmt.Println()
	fmt.Printf("Private key size: %d bytes (%d hex chars)\n", ed25519.PrivateKeySize, ed25519.PrivateKeySize*2)
	fmt.Printf("Public key size:  %d bytes (%d hex chars)\n", ed25519.PublicKeySize, ed25519.PublicKeySize*2)
}
