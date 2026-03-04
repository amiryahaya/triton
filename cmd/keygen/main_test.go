package main_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/amiryahaya/triton/internal/license"
)

func TestKeygen(t *testing.T) {
	out, err := exec.Command("go", "run", "main.go").CombinedOutput()
	if err != nil {
		t.Fatalf("go run main.go failed: %v\n%s", err, out)
	}
	output := string(out)

	t.Run("contains expected labels", func(t *testing.T) {
		for _, label := range []string{
			"SIGNING_KEY",
			"PUBLIC_KEY",
			"TRITON_LICENSE_SERVER_SIGNING_KEY",
			"Private key size: 64 bytes (128 hex chars)",
			"Public key size:  32 bytes (64 hex chars)",
		} {
			if !strings.Contains(output, label) {
				t.Errorf("output missing label %q", label)
			}
		}
	})

	// Extract hex keys from output.
	lines := strings.Split(output, "\n")
	var privHex, pubHex string
	for i, line := range lines {
		if strings.Contains(line, "SIGNING_KEY") && i+1 < len(lines) {
			privHex = strings.TrimSpace(lines[i+1])
		}
		if strings.Contains(line, "PUBLIC_KEY") && i+1 < len(lines) {
			pubHex = strings.TrimSpace(lines[i+1])
		}
	}

	t.Run("private key is valid hex with correct length", func(t *testing.T) {
		if len(privHex) != ed25519.PrivateKeySize*2 {
			t.Fatalf("private key hex length = %d, want %d", len(privHex), ed25519.PrivateKeySize*2)
		}
		if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(privHex) {
			t.Fatal("private key is not valid lowercase hex")
		}
	})

	t.Run("public key is valid hex with correct length", func(t *testing.T) {
		if len(pubHex) != ed25519.PublicKeySize*2 {
			t.Fatalf("public key hex length = %d, want %d", len(pubHex), ed25519.PublicKeySize*2)
		}
		if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(pubHex) {
			t.Fatal("public key is not valid lowercase hex")
		}
	})

	t.Run("keypair can issue and parse a license token", func(t *testing.T) {
		privBytes, err := hex.DecodeString(privHex)
		if err != nil {
			t.Fatalf("decoding private key: %v", err)
		}
		pubBytes, err := hex.DecodeString(pubHex)
		if err != nil {
			t.Fatalf("decoding public key: %v", err)
		}

		priv := ed25519.PrivateKey(privBytes)
		pub := ed25519.PublicKey(pubBytes)

		// Issue a real license token using the generated keypair.
		token, err := license.IssueTokenWithOptions(priv, license.TierEnterprise, "TestOrg", 10, 365, false)
		if err != nil {
			t.Fatalf("IssueTokenWithOptions failed: %v", err)
		}
		if token == "" {
			t.Fatal("token is empty")
		}

		// Parse and verify the token with the public key.
		lic, err := license.Parse(token, pub)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if lic.Tier != license.TierEnterprise {
			t.Errorf("tier = %q, want %q", lic.Tier, license.TierEnterprise)
		}
		if lic.Org != "TestOrg" {
			t.Errorf("org = %q, want %q", lic.Org, "TestOrg")
		}
		if lic.Seats != 10 {
			t.Errorf("seats = %d, want 10", lic.Seats)
		}

		// Verify a wrong public key rejects the token.
		wrongPub, _, _ := ed25519.GenerateKey(nil)
		if _, err := license.Parse(token, wrongPub); err == nil {
			t.Fatal("expected Parse to fail with wrong public key")
		}
	})

	t.Run("each run produces unique keys", func(t *testing.T) {
		out2, err := exec.Command("go", "run", "main.go").CombinedOutput()
		if err != nil {
			t.Fatalf("second run failed: %v\n%s", err, out2)
		}
		if string(out2) == output {
			t.Fatal("two runs produced identical output — keys are not random")
		}
	})
}
