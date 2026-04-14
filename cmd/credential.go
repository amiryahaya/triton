package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage encrypted credentials for agentless scanning",
	Long: `Manage SSH/password credentials used by 'triton network-scan'.
Credentials are stored encrypted at rest with AES-256-GCM. The encryption
key is read from TRITON_SCANNER_CRED_KEY (32 hex bytes) at startup.`,
}

var credentialAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a credential to credentials.yaml",
	RunE:  runCredentialAdd,
}

var credentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List credential names (never plaintext values)",
	RunE:  runCredentialList,
}

var credentialBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Generate an Ed25519 keypair + print Ansible snippet for fleet onboarding",
	RunE:  runCredentialBootstrap,
}

var (
	credFile     string
	credAddName  string
	credAddType  string
	credAddUser  string
	credAddPass  string
	credAddKey   string
	credBootName string
	credBootOut  string
)

func init() {
	credentialCmd.PersistentFlags().StringVar(&credFile, "file", "/etc/triton/credentials.yaml", "path to credentials.yaml")

	credentialAddCmd.Flags().StringVar(&credAddName, "name", "", "credential name (required)")
	credentialAddCmd.Flags().StringVar(&credAddType, "type", "", "type: ssh-key | ssh-password | enable-password")
	credentialAddCmd.Flags().StringVar(&credAddUser, "username", "", "SSH username")
	credentialAddCmd.Flags().StringVar(&credAddPass, "password", "", "SSH password")
	credentialAddCmd.Flags().StringVar(&credAddKey, "key", "", "path to private key file")

	credentialBootstrapCmd.Flags().StringVar(&credBootName, "name", "triton-scanner", "credential name")
	credentialBootstrapCmd.Flags().StringVar(&credBootOut, "out", "/etc/triton/keys", "output directory for generated keypair")

	credentialCmd.AddCommand(credentialAddCmd, credentialListCmd, credentialBootstrapCmd)
	rootCmd.AddCommand(credentialCmd)
}

func runCredentialAdd(_ *cobra.Command, _ []string) error {
	if credAddName == "" || credAddType == "" {
		return fmt.Errorf("--name and --type are required")
	}

	var existing []netscan.Credential
	if _, err := os.Stat(credFile); err == nil {
		store, err := netscan.LoadCredentials(credFile)
		if err != nil {
			return fmt.Errorf("load existing credentials: %w", err)
		}
		existing = store.All()
	}

	for _, c := range existing {
		if c.Name == credAddName {
			return fmt.Errorf("credential %q already exists", credAddName)
		}
	}

	existing = append(existing, netscan.Credential{
		Name:           credAddName,
		Type:           credAddType,
		Username:       credAddUser,
		Password:       credAddPass,
		PrivateKeyPath: credAddKey,
	})

	if err := os.MkdirAll(filepath.Dir(credFile), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(credFile), err)
	}

	if err := netscan.SaveCredentials(credFile, existing); err != nil {
		return err
	}
	fmt.Printf("Added credential %q to %s\n", credAddName, credFile)
	return nil
}

func runCredentialList(_ *cobra.Command, _ []string) error {
	store, err := netscan.LoadCredentials(credFile)
	if err != nil {
		return err
	}
	all := store.All()
	fmt.Printf("Credentials in %s (%d total):\n", credFile, len(all))
	for _, c := range all {
		fmt.Printf("  %s  (%s, user=%s)\n", c.Name, c.Type, c.Username)
	}
	return nil
}

func runCredentialBootstrap(_ *cobra.Command, _ []string) error {
	if err := os.MkdirAll(credBootOut, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", credBootOut, err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "triton-scanner")
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privPath := filepath.Join(credBootOut, credBootName)
	if err := os.WriteFile(privPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("ssh public key: %w", err)
	}
	pubPath := privPath + ".pub"
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	fmt.Printf("Generated keypair:\n  private: %s\n  public:  %s\n\n", privPath, pubPath)
	fmt.Println("Deploy to your fleet with this Ansible task:")
	fmt.Println()
	fmt.Println("  - name: Create triton-scanner user")
	fmt.Println("    user:")
	fmt.Println("      name: triton-scanner")
	fmt.Println("      shell: /bin/bash")
	fmt.Println()
	fmt.Println("  - name: Deploy Triton scanner SSH key")
	fmt.Println("    authorized_key:")
	fmt.Println("      user: triton-scanner")
	fmt.Println("      state: present")
	fmt.Printf("      key: %q\n", string(pubBytes))
	fmt.Println()
	fmt.Println("Then register the credential:")
	fmt.Printf("  triton credential add --name %s --type ssh-key --username triton-scanner --key %s\n",
		credBootName, privPath)
	return nil
}
