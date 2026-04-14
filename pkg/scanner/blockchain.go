package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/store"
)

// BlockchainModule scans for blockchain wallet key material:
//
//   - Bitcoin Core: wallet.dat presence (ECDSA-secp256k1)
//   - Ethereum: keystore JSON — cipher, KDF algorithm extraction
//   - Solana: id.json keypair presence (Ed25519)
//
// Algorithm reporting only — zero private key extraction.
type BlockchainModule struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewBlockchainModule constructs a BlockchainModule.
func NewBlockchainModule(cfg *scannerconfig.Config) *BlockchainModule {
	return &BlockchainModule{config: cfg}
}

func (m *BlockchainModule) Name() string                         { return "blockchain" }
func (m *BlockchainModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *BlockchainModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *BlockchainModule) SetStore(s store.Store)               { m.store = s }

func (m *BlockchainModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree for blockchain wallet files.
func (m *BlockchainModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isBlockchainFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			results := m.parseFile(ctx, reader, path)
			for _, f := range results {
				if f == nil {
					continue
				}
				select {
				case findings <- f:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	})
}

// isBlockchainFile matches blockchain wallet files.
func isBlockchainFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// Bitcoin Core wallet.dat
	if base == "wallet.dat" && strings.Contains(lower, "bitcoin") {
		return true
	}

	// Ethereum keystore
	if strings.Contains(lower, "ethereum") && strings.Contains(lower, "keystore") {
		return true
	}

	// Solana keypair
	if strings.Contains(lower, "solana") && base == "id.json" {
		return true
	}

	return false
}

// parseFile dispatches to the right sub-parser.
func (m *BlockchainModule) parseFile(ctx context.Context, reader fsadapter.FileReader, path string) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	switch {
	case base == "wallet.dat" && strings.Contains(lower, "bitcoin"):
		return m.parseBitcoinWallet(path)
	case strings.Contains(lower, "ethereum") && strings.Contains(lower, "keystore"):
		data, err := reader.ReadFile(ctx, path)
		if err != nil {
			return nil
		}
		return m.parseEthKeystore(path, data)
	case strings.Contains(lower, "solana") && base == "id.json":
		return m.parseSolanaKey(path)
	}
	return nil
}

// --- Bitcoin ---

// parseBitcoinWallet reports presence of a Bitcoin Core wallet.
// wallet.dat is a BerkeleyDB file — we don't parse it (would
// require the wallet passphrase). Bitcoin uses ECDSA-secp256k1.
func (m *BlockchainModule) parseBitcoinWallet(path string) []*model.Finding {
	return []*model.Finding{m.blockchainFinding(path, "Bitcoin wallet", "ECDSA-secp256k1",
		fmt.Sprintf("Bitcoin Core wallet at %s", path))}
}

// --- Ethereum ---

// ethCipherMap maps Ethereum keystore cipher names to canonical algorithms.
var ethCipherMap = map[string]string{
	"aes-128-ctr": "AES-128",
	"aes-128-cbc": "AES-128",
	"aes-256-ctr": "AES-256",
	"aes-256-cbc": "AES-256",
}

// parseEthKeystore extracts cipher and KDF algorithms from Ethereum keystore JSON.
func (m *BlockchainModule) parseEthKeystore(path string, data []byte) []*model.Finding {
	var ks struct {
		Version int `json:"version"`
		Crypto  struct {
			Cipher string `json:"cipher"`
			KDF    string `json:"kdf"`
		} `json:"crypto"`
	}
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil
	}
	if ks.Version == 0 && ks.Crypto.Cipher == "" {
		return nil
	}

	var out []*model.Finding
	base := filepath.Base(path)

	if ks.Crypto.Cipher != "" {
		algo := ks.Crypto.Cipher
		if canonical, ok := ethCipherMap[strings.ToLower(ks.Crypto.Cipher)]; ok {
			algo = canonical
		}
		out = append(out, m.blockchainFinding(path, "Ethereum keystore encryption", algo,
			fmt.Sprintf("Ethereum keystore cipher %s in %s", ks.Crypto.Cipher, base)))
	}

	if ks.Crypto.KDF != "" {
		kdfAlgo := strings.ToUpper(ks.Crypto.KDF)
		out = append(out, m.blockchainFinding(path, "Ethereum keystore KDF", kdfAlgo,
			fmt.Sprintf("Ethereum keystore KDF %s in %s", ks.Crypto.KDF, base)))
	}

	return out
}

// --- Solana ---

// parseSolanaKey reports presence of a Solana keypair file.
// Solana uses Ed25519.
func (m *BlockchainModule) parseSolanaKey(path string) []*model.Finding {
	return []*model.Finding{m.blockchainFinding(path, "Solana keypair", "Ed25519",
		fmt.Sprintf("Solana keypair at %s", path))}
}

// --- finding builder ---

func (m *BlockchainModule) blockchainFinding(path, function, algorithm, purpose string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  function,
		Algorithm: algorithm,
		Purpose:   purpose,
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = algorithm

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: CategoryConfig,
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  ConfidenceHigh,
		Module:      "blockchain",
		Timestamp:   time.Now(),
	}
}
