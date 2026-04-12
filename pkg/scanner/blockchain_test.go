package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- file matcher tests ---

func TestIsBlockchainFile(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		// Bitcoin Core
		{"/home/user/.bitcoin/wallet.dat", true},
		{"/var/lib/bitcoin/wallet.dat", true},
		{"/home/user/.bitcoin/wallets/default/wallet.dat", true},

		// Ethereum keystore
		{"/home/user/.ethereum/keystore/UTC--2026-04-12T00-00-00.000Z--abcdef1234567890", true},
		{"/var/lib/ethereum/keystore/key.json", true},

		// Solana
		{"/home/user/.config/solana/id.json", true},

		// Not blockchain
		{"/etc/nginx/nginx.conf", false},
		{"/home/user/wallet.txt", false},
		{"/home/user/.bitcoin/debug.log", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isBlockchainFile(tc.path), "path: %s", tc.path)
		})
	}
}

// --- Bitcoin wallet.dat tests ---

func TestParseBitcoinWallet(t *testing.T) {
	// We only detect presence — wallet.dat is a BerkeleyDB file
	// that we don't parse (would require the wallet passphrase).
	m := &BlockchainModule{}
	findings := m.parseBitcoinWallet("/home/user/.bitcoin/wallet.dat")
	require.Len(t, findings, 1)
	assert.Equal(t, "Bitcoin wallet", findings[0].CryptoAsset.Function)
	assert.Equal(t, "ECDSA-secp256k1", findings[0].CryptoAsset.Algorithm)
}

// --- Ethereum keystore tests ---

func TestParseEthKeystore(t *testing.T) {
	keystore := `{
  "address": "abcdef1234567890abcdef1234567890abcdef12",
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {"iv": "0123456789abcdef"},
    "ciphertext": "encrypted...",
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 262144,
      "r": 8,
      "p": 1,
      "salt": "abcdef..."
    },
    "mac": "0123456789..."
  },
  "version": 3
}`
	m := &BlockchainModule{}
	findings := m.parseEthKeystore("/home/user/.ethereum/keystore/key.json", []byte(keystore))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	algoSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, funcSet["Ethereum keystore encryption"])
	assert.True(t, algoSet["AES-128"], "cipher aes-128-ctr")
	assert.True(t, funcSet["Ethereum keystore KDF"])
	assert.True(t, algoSet["SCRYPT"])
}

func TestParseEthKeystore_PBKDF2(t *testing.T) {
	keystore := `{
  "crypto": {
    "cipher": "aes-128-ctr",
    "kdf": "pbkdf2",
    "kdfparams": {"c": 262144, "dklen": 32, "prf": "hmac-sha256"}
  },
  "version": 3
}`
	m := &BlockchainModule{}
	findings := m.parseEthKeystore("/home/user/.ethereum/keystore/key.json", []byte(keystore))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["PBKDF2"])
}

func TestParseEthKeystore_NotKeystore(t *testing.T) {
	m := &BlockchainModule{}
	findings := m.parseEthKeystore("/some/path/key.json", []byte(`{"some": "json"}`))
	assert.Empty(t, findings)
}

// --- Solana key tests ---

func TestParseSolanaKey(t *testing.T) {
	m := &BlockchainModule{}
	findings := m.parseSolanaKey("/home/user/.config/solana/id.json")
	require.Len(t, findings, 1)
	assert.Equal(t, "Solana keypair", findings[0].CryptoAsset.Function)
	assert.Equal(t, "Ed25519", findings[0].CryptoAsset.Algorithm)
}

// --- module interface ---

func TestBlockchainModuleInterface(t *testing.T) {
	m := NewBlockchainModule(nil)
	assert.Equal(t, "blockchain", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}
