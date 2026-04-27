package credentials

import (
	"time"

	"github.com/google/uuid"
)

// AuthType enumerates the supported credential authentication methods.
type AuthType string

const (
	AuthTypeSSHKey      AuthType = "ssh-key"
	AuthTypeSSHPassword AuthType = "ssh-password"
	AuthTypeWinRM       AuthType = "winrm-password"
)

// Credential is the database record for a stored credential set.
type Credential struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	Name       string    `json:"name"`
	AuthType   AuthType  `json:"auth_type"`
	VaultPath  string    `json:"vault_path"`
	InUseCount int       `json:"in_use_count"`
	CreatedAt  time.Time `json:"created_at"`
}

// SecretPayload is the secret material stored in Vault KV v2.
// Fields are omitted from JSON when empty to keep the Vault secret lean.
type SecretPayload struct {
	Username   string `json:"username"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Password   string `json:"password,omitempty"`
	UseHTTPS   bool   `json:"use_https,omitempty"`
}
