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
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	token, err := license.IssueTokenWithOptions(priv, license.TierEnterprise, "container-dev", 100, 3650, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("PUBLIC_KEY=%s\n", hex.EncodeToString(pub))
	fmt.Printf("TOKEN=%s\n", token)
}
