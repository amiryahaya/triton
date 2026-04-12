package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// MessagingModule scans messaging broker configuration files for
// TLS and SASL crypto posture:
//
//   - Kafka: server.properties — ssl.*, sasl.* directives
//   - RabbitMQ: rabbitmq.conf — ssl_options.* directives
//   - NATS: nats-server.conf — tls {} block
//   - Mosquitto: mosquitto.conf — tls_version, ciphers, cafile/certfile
//   - Redis: redis.conf — tls-* directives
//
// Config-parse only — no broker connections.
type MessagingModule struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

// NewMessagingModule constructs a MessagingModule.
func NewMessagingModule(cfg *scannerconfig.Config) *MessagingModule {
	return &MessagingModule{config: cfg}
}

func (m *MessagingModule) Name() string                         { return "messaging" }
func (m *MessagingModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *MessagingModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *MessagingModule) SetStore(s store.Store)               { m.store = s }

func (m *MessagingModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target tree and parses matching config files.
func (m *MessagingModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isMessagingConfigFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			results := m.parseConfig(path, data)
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

// isMessagingConfigFile matches messaging broker config files.
func isMessagingConfigFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	// Kafka — server.properties, producer/consumer.properties under kafka paths
	if strings.HasSuffix(base, ".properties") && strings.Contains(lower, "kafka") {
		return true
	}

	// RabbitMQ
	if strings.Contains(lower, "/rabbitmq/") && (strings.HasSuffix(base, ".conf") || strings.HasSuffix(base, ".config")) {
		return true
	}

	// NATS
	if strings.Contains(lower, "nats") && strings.HasSuffix(base, ".conf") {
		return true
	}

	// Mosquitto
	if strings.Contains(lower, "mosquitto") && strings.HasSuffix(base, ".conf") {
		return true
	}

	// Redis
	if (base == "redis.conf" || base == "sentinel.conf") ||
		(strings.Contains(lower, "/redis/") && strings.HasSuffix(base, ".conf")) {
		return true
	}

	return false
}

// parseConfig dispatches to the right sub-parser.
func (m *MessagingModule) parseConfig(path string, data []byte) []*model.Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(path)

	switch {
	case strings.HasSuffix(base, ".properties") && strings.Contains(lower, "kafka"):
		return m.parseKafkaConfig(path, data)
	case strings.Contains(lower, "/rabbitmq/"):
		return m.parseRabbitMQConfig(path, data)
	case strings.Contains(lower, "nats"):
		return m.parseNATSConfig(path, data)
	case strings.Contains(lower, "mosquitto"):
		return m.parseMosquittoConfig(path, data)
	case strings.Contains(lower, "redis") || base == "sentinel.conf":
		return m.parseRedisConfig(path, data)
	}
	return nil
}

// --- Kafka ---

// parseKafkaConfig extracts TLS and SASL settings from Kafka server.properties.
func (m *MessagingModule) parseKafkaConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "kafka", sc.Err()) }()

	base := filepath.Base(path)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if val == "" {
			continue
		}

		switch key {
		case "ssl.protocol":
			out = append(out, m.msgFinding(path, "Kafka TLS protocol", val,
				fmt.Sprintf("Kafka ssl.protocol in %s", base)))
		case "ssl.enabled.protocols":
			for _, p := range strings.Split(val, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					out = append(out, m.msgFinding(path, "Kafka TLS protocol", p,
						fmt.Sprintf("Kafka ssl.enabled.protocols in %s", base)))
				}
			}
		case "ssl.cipher.suites":
			for _, c := range strings.Split(val, ",") {
				c = strings.TrimSpace(c)
				if c != "" {
					out = append(out, m.msgFinding(path, "Kafka TLS cipher suite", c,
						fmt.Sprintf("Kafka ssl.cipher.suites in %s", base)))
				}
			}
		case "sasl.enabled.mechanisms":
			for _, mech := range strings.Split(val, ",") {
				mech = strings.TrimSpace(mech)
				if mech != "" {
					out = append(out, m.msgFinding(path, "Kafka SASL mechanism", mech,
						fmt.Sprintf("Kafka sasl.enabled.mechanisms in %s", base)))
				}
			}
		case "sasl.mechanism.inter.broker.protocol":
			out = append(out, m.msgFinding(path, "Kafka SASL mechanism", val,
				fmt.Sprintf("Kafka inter-broker SASL in %s", base)))
		}
	}
	return out
}

// --- RabbitMQ ---

// parseRabbitMQConfig extracts TLS settings from rabbitmq.conf (sysctl format).
func (m *MessagingModule) parseRabbitMQConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "rabbitmq", sc.Err()) }()

	base := filepath.Base(path)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if val == "" {
			continue
		}

		switch {
		case strings.HasPrefix(key, "ssl_options.versions."):
			out = append(out, m.msgFinding(path, "RabbitMQ TLS version", val,
				fmt.Sprintf("RabbitMQ ssl_options.versions in %s", base)))
		case strings.HasPrefix(key, "ssl_options.ciphers."):
			out = append(out, m.msgFinding(path, "RabbitMQ TLS cipher suite", val,
				fmt.Sprintf("RabbitMQ ssl_options.ciphers in %s", base)))
		}
	}
	return out
}

// --- NATS ---

// parseNATSConfig looks for tls {} blocks and cipher_suites in NATS config.
func (m *MessagingModule) parseNATSConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "nats", sc.Err()) }()

	base := filepath.Base(path)
	inTLS := false
	hasTLSBlock := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Detect tls { or tls: {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "tls") && strings.Contains(line, "{") {
			inTLS = true
			hasTLSBlock = true
			continue
		}
		if inTLS && strings.HasPrefix(line, "}") {
			inTLS = false
			continue
		}

		if inTLS {
			// cipher_suites: ["TLS_...", "TLS_..."]
			if strings.HasPrefix(strings.TrimSpace(lower), "cipher_suites") {
				// Extract values from array syntax
				start := strings.IndexByte(line, '[')
				end := strings.LastIndexByte(line, ']')
				if start >= 0 && end > start {
					inner := line[start+1 : end]
					for _, c := range strings.Split(inner, ",") {
						c = strings.TrimSpace(c)
						c = strings.Trim(c, `"'`)
						if c != "" {
							out = append(out, m.msgFinding(path, "NATS TLS cipher suite", c,
								fmt.Sprintf("NATS cipher_suites in %s", base)))
						}
					}
				}
			}
			// Multi-line array: bare cipher strings
			if strings.HasPrefix(line, `"TLS_`) || strings.HasPrefix(line, `"ECDHE`) {
				c := strings.Trim(line, `"' `)
				if c != "" {
					out = append(out, m.msgFinding(path, "NATS TLS cipher suite", c,
						fmt.Sprintf("NATS cipher_suites in %s", base)))
				}
			}
		}
	}

	// Report TLS block presence even without explicit cipher_suites
	if hasTLSBlock {
		out = append([]*model.Finding{m.msgFinding(path, "NATS TLS", "TLS",
			fmt.Sprintf("NATS TLS block in %s", base))}, out...)
	}
	return out
}

// --- Mosquitto ---

// parseMosquittoConfig extracts TLS directives from mosquitto.conf.
func (m *MessagingModule) parseMosquittoConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "mosquitto", sc.Err()) }()

	base := filepath.Base(path)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")

		switch directive {
		case "tls_version":
			out = append(out, m.msgFinding(path, "Mosquitto TLS version", value,
				fmt.Sprintf("Mosquitto tls_version in %s", base)))
		case "ciphers":
			for _, c := range strings.Split(value, ":") {
				c = strings.TrimSpace(c)
				if c != "" {
					out = append(out, m.msgFinding(path, "Mosquitto TLS cipher suite", c,
						fmt.Sprintf("Mosquitto ciphers in %s", base)))
				}
			}
		}
	}
	return out
}

// --- Redis ---

// parseRedisConfig extracts tls-* directives from redis.conf.
func (m *MessagingModule) parseRedisConfig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	defer func() { logScannerErr(path, "redis", sc.Err()) }()

	base := filepath.Base(path)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")
		value = strings.Trim(value, `"`)

		switch directive {
		case "tls-protocols":
			for _, p := range strings.Fields(value) {
				p = strings.TrimSpace(p)
				if p != "" {
					out = append(out, m.msgFinding(path, "Redis TLS protocol", p,
						fmt.Sprintf("Redis tls-protocols in %s", base)))
				}
			}
		case "tls-ciphers":
			for _, c := range strings.Split(value, ":") {
				c = strings.TrimSpace(c)
				if c != "" {
					out = append(out, m.msgFinding(path, "Redis TLS cipher suite", c,
						fmt.Sprintf("Redis tls-ciphers in %s", base)))
				}
			}
		case "tls-ciphersuites":
			for _, c := range strings.Split(value, ":") {
				c = strings.TrimSpace(c)
				if c != "" {
					out = append(out, m.msgFinding(path, "Redis TLS cipher suite", c,
						fmt.Sprintf("Redis tls-ciphersuites in %s", base)))
				}
			}
		}
	}
	return out
}

// --- finding builder ---

func (m *MessagingModule) msgFinding(path, function, algorithm, purpose string) *model.Finding {
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
		Module:      "messaging",
		Timestamp:   time.Now(),
	}
}
