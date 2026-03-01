//go:build ignore

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/amiryahaya/triton/internal/license"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: go run internal/license/cmd/keygen/main.go <command>\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  generate-keys          Generate Ed25519 keypair\n")
		fmt.Fprintf(os.Stderr, "  issue [flags]          Issue a licence token\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate-keys":
		generateKeys()
	case "issue":
		issueToken()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func generateKeys() {
	pub, priv, err := license.GenerateKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Public key (hex):  %s\n", hex.EncodeToString(pub))
	fmt.Printf("Private key (hex): %s\n", hex.EncodeToString(priv))
	fmt.Println("\nUse the public key with -ldflags:")
	fmt.Printf("  go build -ldflags \"-X github.com/amiryahaya/triton/internal/license.publicKeyHex=%s\"\n", hex.EncodeToString(pub))
}

func issueToken() {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	tier := fs.String("tier", "pro", "Licence tier: free, pro, enterprise")
	org := fs.String("org", "", "Organisation name")
	seats := fs.Int("seats", 1, "Number of seats")
	days := fs.Int("days", 365, "Validity in days")
	privKeyHex := fs.String("key", "", "Private key (hex)")
	noBind := fs.Bool("no-bind", false, "Do not bind token to this machine")
	_ = fs.Parse(os.Args[2:])

	if *privKeyHex == "" {
		fmt.Fprintf(os.Stderr, "error: --key is required\n")
		os.Exit(1)
	}
	if *org == "" {
		fmt.Fprintf(os.Stderr, "error: --org is required\n")
		os.Exit(1)
	}

	privBytes, err := hex.DecodeString(*privKeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding private key: %v\n", err)
		os.Exit(1)
	}
	if len(privBytes) != 64 {
		fmt.Fprintf(os.Stderr, "error: private key must be 64 bytes (128 hex chars), got %d bytes\n", len(privBytes))
		os.Exit(1)
	}

	fmt.Printf("Machine fingerprint: %s\n", license.MachineFingerprint())

	token, err := license.IssueTokenWithOptions(privBytes, license.Tier(*tier), *org, *seats, *days, !*noBind)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error issuing token: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(token)
}
