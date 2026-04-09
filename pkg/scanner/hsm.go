package scanner

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// hsmObject represents a key, certificate, or secret key found in an HSM.
type hsmObject struct {
	objectType string // "Private Key", "Public Key", "Certificate", "Secret Key"
	algorithm  string // "RSA", "EC", "AES", etc.
	keySize    int
	label      string
	id         string
}

// hsmMechanism represents a supported PKCS#11 mechanism.
type hsmMechanism struct {
	name       string
	minKeySize int
	maxKeySize int
	operations []string
}

// hsmSlot represents an HSM token slot.
type hsmSlot struct {
	slotID       string
	tokenLabel   string
	manufacturer string
	model        string
}

// well-known PKCS#11 module paths per platform.
var pkcs11ModulePaths = map[string][]string{
	"linux": {
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/opt/nfast/toolkits/pkcs11/libcknfast.so",
		"/usr/lib/libeTPkcs11.so",
		"/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
	},
	"darwin": {
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/usr/local/lib/opensc-pkcs11.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
	},
}

// HSMModule scans Hardware Security Modules via PKCS#11 for keys,
// certificates, and supported cryptographic mechanisms.
type HSMModule struct {
	config    *scannerconfig.Config
	cmdRunner cmdRunnerFunc
}

// NewHSMModule creates a new HSMModule.
func NewHSMModule(cfg *scannerconfig.Config) *HSMModule {
	return &HSMModule{
		config:    cfg,
		cmdRunner: defaultCmdRunner,
	}
}

func (m *HSMModule) Name() string                         { return "hsm" }
func (m *HSMModule) Category() model.ModuleCategory       { return model.CategoryActiveRuntime }
func (m *HSMModule) ScanTargetType() model.ScanTargetType { return model.TargetHSM }

// Scan probes PKCS#11 modules for keys, certs, and mechanisms.
func (m *HSMModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if target.Value == "auto" {
		return m.scanAutoDiscovery(ctx, findings)
	}
	return m.scanModule(ctx, target.Value, findings)
}

// scanAutoDiscovery checks well-known PKCS#11 module paths.
func (m *HSMModule) scanAutoDiscovery(ctx context.Context, findings chan<- *model.Finding) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	paths, ok := pkcs11ModulePaths[runtime.GOOS]
	if !ok {
		return nil
	}

	for _, modulePath := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if _, err := os.Stat(modulePath); err != nil {
			continue
		}

		if err := m.scanModule(ctx, modulePath, findings); err != nil {
			continue // Non-fatal: try next module
		}
	}

	return nil
}

// scanModule probes a single PKCS#11 module.
func (m *HSMModule) scanModule(ctx context.Context, modulePath string, findings chan<- *model.Finding) error {
	// Reject paths that start with '-' to prevent flag injection
	if strings.HasPrefix(modulePath, "-") {
		return nil
	}
	// List slots/tokens
	if out, err := m.cmdRunner(ctx, "pkcs11-tool", "--module", modulePath, "--list-slots"); err == nil {
		slots := m.parseListSlots(string(out))
		for _, slot := range slots {
			emitSlotFinding(ctx, findings, slot, modulePath)
		}
	}

	// List objects (keys, certs)
	if out, err := m.cmdRunner(ctx, "pkcs11-tool", "--module", modulePath, "--list-objects"); err == nil {
		objects := m.parseListObjects(string(out))
		for _, obj := range objects {
			emitObjectFinding(ctx, findings, obj, modulePath)
		}
	}

	// List mechanisms
	if out, err := m.cmdRunner(ctx, "pkcs11-tool", "--module", modulePath, "--list-mechanisms"); err == nil {
		mechs := m.parseListMechanisms(string(out))
		for _, mech := range mechs {
			emitMechanismFinding(ctx, findings, mech, modulePath)
		}
	}

	return nil
}

// --- Parsing functions ---

// slotRegex extracts slot information from pkcs11-tool output.
var slotRegex = regexp.MustCompile(`Slot\s+(\d+)\s+\(0x[0-9a-fA-F]+\):\s*(.*)`)
var tokenLabelRegex = regexp.MustCompile(`^\s+token label\s*:\s*(.+)$`)
var tokenMfgRegex = regexp.MustCompile(`^\s+token manufacturer\s*:\s*(.+)$`)
var tokenModelRegex = regexp.MustCompile(`^\s+token model\s*:\s*(.+)$`)

// parseListSlots parses pkcs11-tool --list-slots output.
func (m *HSMModule) parseListSlots(output string) []hsmSlot {
	var slots []hsmSlot
	var current *hsmSlot

	for _, line := range strings.Split(output, "\n") {
		if matches := slotRegex.FindStringSubmatch(line); matches != nil {
			if current != nil {
				slots = append(slots, *current)
			}
			current = &hsmSlot{slotID: matches[1]}
			continue
		}

		if current == nil {
			continue
		}

		if matches := tokenLabelRegex.FindStringSubmatch(line); matches != nil {
			current.tokenLabel = strings.TrimSpace(matches[1])
		} else if matches := tokenMfgRegex.FindStringSubmatch(line); matches != nil {
			current.manufacturer = strings.TrimSpace(matches[1])
		} else if matches := tokenModelRegex.FindStringSubmatch(line); matches != nil {
			current.model = strings.TrimSpace(matches[1])
		}
	}

	if current != nil {
		slots = append(slots, *current)
	}

	return slots
}

// objectTypeRegex matches object header lines.
var objectTypeRegex = regexp.MustCompile(`^(Private Key|Public Key|Secret Key|Certificate)\s+Object;\s*(.*)$`)
var objectLabelRegex = regexp.MustCompile(`^\s+label:\s+(.+)$`)
var objectIDRegex = regexp.MustCompile(`^\s+ID:\s+(.+)$`)

// parseListObjects parses pkcs11-tool --list-objects output.
func (m *HSMModule) parseListObjects(output string) []hsmObject {
	var objects []hsmObject
	var current *hsmObject

	for _, line := range strings.Split(output, "\n") {
		if matches := objectTypeRegex.FindStringSubmatch(line); matches != nil {
			if current != nil {
				objects = append(objects, *current)
			}
			objType := matches[1]
			algoInfo := strings.TrimSpace(matches[2])
			algo, keySize := parseObjectAlgoInfo(algoInfo)
			current = &hsmObject{
				objectType: objType,
				algorithm:  algo,
				keySize:    keySize,
			}
			continue
		}

		if current == nil {
			continue
		}

		if matches := objectLabelRegex.FindStringSubmatch(line); matches != nil {
			current.label = strings.TrimSpace(matches[1])
		} else if matches := objectIDRegex.FindStringSubmatch(line); matches != nil {
			current.id = strings.TrimSpace(matches[1])
		}
	}

	if current != nil {
		objects = append(objects, *current)
	}

	return objects
}

// parseObjectAlgoInfo extracts algorithm and key size from object type info.
// e.g., "RSA 2048 bits" → ("RSA", 2048), "EC" → ("EC", 0)
func parseObjectAlgoInfo(info string) (algo string, keySize int) {
	info = strings.TrimSpace(info)
	if info == "" {
		return "Unknown", 0
	}

	// Handle "type = X.509 cert" for certificates
	if strings.Contains(info, "type = X.509") {
		return "X.509", 0
	}

	parts := strings.Fields(info)
	algo = parts[0]

	// Look for key size
	for i, p := range parts {
		if p == "bits" && i > 0 {
			if size, err := strconv.Atoi(parts[i-1]); err == nil {
				return algo, size
			}
		}
	}

	// Try parsing second field as key size directly
	if len(parts) >= 2 {
		if size, err := strconv.Atoi(parts[1]); err == nil {
			return algo, size
		}
	}

	return algo, 0
}

// mechanismRegex parses mechanism lines from pkcs11-tool output.
var mechanismRegex = regexp.MustCompile(`^(\S+),\s+keySize=\{(\d+),(\d+)\}`)

// parseListMechanisms parses pkcs11-tool --list-mechanisms output.
func (m *HSMModule) parseListMechanisms(output string) []hsmMechanism {
	var mechs []hsmMechanism

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Supported") {
			continue
		}

		matches := mechanismRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := matches[1]
		minKey, _ := strconv.Atoi(matches[2])
		maxKey, _ := strconv.Atoi(matches[3])

		// Extract operations (everything after the keySize part)
		rest := mechanismRegex.ReplaceAllString(line, "")
		rest = strings.TrimLeft(rest, ", ")
		var ops []string
		if rest != "" {
			for _, op := range strings.Split(rest, ",") {
				op = strings.TrimSpace(op)
				if op != "" {
					ops = append(ops, op)
				}
			}
		}

		mechs = append(mechs, hsmMechanism{
			name:       name,
			minKeySize: minKey,
			maxKeySize: maxKey,
			operations: ops,
		})
	}

	return mechs
}

// --- Finding emission helpers ---

func emitSlotFinding(ctx context.Context, findings chan<- *model.Finding, slot hsmSlot, modulePath string) {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "HSM token",
		Algorithm: "PKCS#11",
		Purpose:   fmt.Sprintf("Token: %s (slot %s)", slot.tokenLabel, slot.slotID),
		Library:   slot.manufacturer,
	}
	// No classification for token metadata itself

	finding := &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5,
		Source: model.FindingSource{
			Type:            "hsm",
			Path:            modulePath,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "hsm",
		Timestamp:   time.Now(),
	}

	emitFinding(ctx, findings, finding)
}

func emitObjectFinding(ctx context.Context, findings chan<- *model.Finding, obj hsmObject, modulePath string) {
	function := fmt.Sprintf("HSM %s", strings.ToLower(obj.objectType))

	algo := normalizeHSMAlgorithm(obj.algorithm)

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  function,
		Algorithm: algo,
		KeySize:   obj.keySize,
		Purpose:   fmt.Sprintf("HSM object: %s (label: %s)", obj.objectType, obj.label),
		Library:   "PKCS#11",
	}
	crypto.ClassifyCryptoAsset(asset)

	finding := &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5,
		Source: model.FindingSource{
			Type:            "hsm",
			Path:            modulePath,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "hsm",
		Timestamp:   time.Now(),
	}

	emitFinding(ctx, findings, finding)
}

func emitMechanismFinding(ctx context.Context, findings chan<- *model.Finding, mech hsmMechanism, modulePath string) {
	algo := normalizeHSMAlgorithm(mech.name)

	// PKCS#11 reports AES key sizes in bytes (16=128-bit, 32=256-bit).
	// Convert to bits for symmetric algorithms to match the rest of the codebase.
	keySize := mech.maxKeySize
	if algo == "AES" && keySize > 0 && keySize <= 64 {
		keySize *= 8
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "HSM supported algorithm",
		Algorithm: algo,
		KeySize:   keySize,
		Purpose:   fmt.Sprintf("Mechanism: %s (key range: %d-%d)", mech.name, mech.minKeySize, mech.maxKeySize),
		Library:   "PKCS#11",
	}
	crypto.ClassifyCryptoAsset(asset)

	finding := &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5,
		Source: model.FindingSource{
			Type:            "hsm",
			Path:            modulePath,
			DetectionMethod: "configuration",
		},
		CryptoAsset: asset,
		Confidence:  0.85,
		Module:      "hsm",
		Timestamp:   time.Now(),
	}

	emitFinding(ctx, findings, finding)
}

// normalizeHSMAlgorithm maps PKCS#11 mechanism/algorithm names to canonical forms.
func normalizeHSMAlgorithm(name string) string {
	upper := strings.ToUpper(name)

	switch {
	case strings.HasPrefix(upper, "RSA"):
		return "RSA"
	case upper == "EC" || strings.HasPrefix(upper, "ECDSA"):
		return "ECDSA"
	case strings.HasPrefix(upper, "AES"):
		return "AES"
	case strings.HasPrefix(upper, "SHA256-RSA"):
		return "SHA256withRSA"
	case strings.HasPrefix(upper, "SHA384-RSA"):
		return "SHA384withRSA"
	case strings.HasPrefix(upper, "SHA512-RSA"):
		return "SHA512withRSA"
	case upper == "X.509":
		return "X.509"
	default:
		return name
	}
}
