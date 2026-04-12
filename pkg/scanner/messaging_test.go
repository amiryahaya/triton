package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- file matcher tests ---

func TestIsMessagingConfigFile(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		// Kafka
		{"/etc/kafka/server.properties", true},
		{"/opt/kafka/config/server.properties", true},
		{"/opt/kafka/config/kraft/server.properties", true},
		{"/etc/kafka/producer.properties", true},
		{"/etc/kafka/consumer.properties", true},

		// RabbitMQ
		{"/etc/rabbitmq/rabbitmq.conf", true},
		{"/etc/rabbitmq/advanced.config", true},

		// NATS
		{"/etc/nats/nats-server.conf", true},
		{"/etc/nats-server.conf", true},
		{"/opt/nats/nats.conf", true},

		// Mosquitto
		{"/etc/mosquitto/mosquitto.conf", true},
		{"/etc/mosquitto/conf.d/tls.conf", true},

		// Redis
		{"/etc/redis/redis.conf", true},
		{"/etc/redis.conf", true},
		{"/etc/redis/sentinel.conf", true},

		// Not messaging
		{"/etc/nginx/nginx.conf", false},
		{"/home/user/server.properties", false}, // no kafka path
		{"/etc/ssh/sshd_config", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.match, isMessagingConfigFile(tc.path), "path: %s", tc.path)
		})
	}
}

// --- Kafka parser tests ---

func TestParseKafka_TLSEnabled(t *testing.T) {
	conf := `# Kafka server TLS config
broker.id=0
listeners=SSL://0.0.0.0:9093
ssl.keystore.location=/etc/kafka/kafka.keystore.jks
ssl.keystore.password=changeit
ssl.key.password=changeit
ssl.truststore.location=/etc/kafka/kafka.truststore.jks
ssl.truststore.password=changeit
ssl.protocol=TLSv1.2
ssl.enabled.protocols=TLSv1.2,TLSv1.3
ssl.cipher.suites=TLS_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
security.inter.broker.protocol=SSL
`
	m := &MessagingModule{}
	findings := m.parseKafkaConfig("/etc/kafka/server.properties", []byte(conf))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	funcSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
		funcSet[f.CryptoAsset.Function] = true
		assert.Equal(t, "messaging", f.Module)
	}
	assert.True(t, funcSet["Kafka TLS protocol"])
	assert.True(t, funcSet["Kafka TLS cipher suite"])
}

func TestParseKafka_SASLPlaintext(t *testing.T) {
	conf := `listeners=SASL_PLAINTEXT://0.0.0.0:9092
security.inter.broker.protocol=SASL_PLAINTEXT
sasl.mechanism.inter.broker.protocol=PLAIN
sasl.enabled.mechanisms=PLAIN,SCRAM-SHA-256
`
	m := &MessagingModule{}
	findings := m.parseKafkaConfig("/etc/kafka/server.properties", []byte(conf))
	require.NotEmpty(t, findings)

	algoSet := make(map[string]bool)
	for _, f := range findings {
		algoSet[f.CryptoAsset.Algorithm] = true
	}
	assert.True(t, algoSet["SCRAM-SHA-256"], "should find SCRAM-SHA-256")
}

func TestParseKafka_NoTLS(t *testing.T) {
	conf := `broker.id=0
listeners=PLAINTEXT://0.0.0.0:9092
`
	m := &MessagingModule{}
	findings := m.parseKafkaConfig("/etc/kafka/server.properties", []byte(conf))
	assert.Empty(t, findings)
}

// --- RabbitMQ parser tests ---

func TestParseRabbitMQ_TLS(t *testing.T) {
	conf := `# RabbitMQ TLS configuration
listeners.ssl.default = 5671
ssl_options.cacertfile = /etc/rabbitmq/ca_certificate.pem
ssl_options.certfile = /etc/rabbitmq/server_certificate.pem
ssl_options.keyfile = /etc/rabbitmq/server_key.pem
ssl_options.versions.1 = tlsv1.2
ssl_options.versions.2 = tlsv1.3
ssl_options.ciphers.1 = TLS_AES_256_GCM_SHA384
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = true
`
	m := &MessagingModule{}
	findings := m.parseRabbitMQConfig("/etc/rabbitmq/rabbitmq.conf", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["RabbitMQ TLS version"])
	assert.True(t, funcSet["RabbitMQ TLS cipher suite"])
}

func TestParseRabbitMQ_NoTLS(t *testing.T) {
	conf := `listeners.tcp.default = 5672
`
	m := &MessagingModule{}
	findings := m.parseRabbitMQConfig("/etc/rabbitmq/rabbitmq.conf", []byte(conf))
	assert.Empty(t, findings)
}

// --- NATS parser tests ---

func TestParseNATS_TLS(t *testing.T) {
	conf := `# NATS server config
port: 4222

tls {
  cert_file: "/etc/nats/server-cert.pem"
  key_file: "/etc/nats/server-key.pem"
  ca_file: "/etc/nats/ca.pem"
  cipher_suites: [
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
  ]
  timeout: 2
}
`
	m := &MessagingModule{}
	findings := m.parseNATSConfig("/etc/nats/nats-server.conf", []byte(conf))
	require.NotEmpty(t, findings)

	hasTLS := false
	hasCipher := false
	for _, f := range findings {
		if f.CryptoAsset.Function == "NATS TLS" {
			hasTLS = true
		}
		if f.CryptoAsset.Function == "NATS TLS cipher suite" {
			hasCipher = true
		}
	}
	assert.True(t, hasTLS)
	assert.True(t, hasCipher)
}

func TestParseNATS_InlineCipherSuites(t *testing.T) {
	conf := `tls {
  cert_file: "/etc/nats/cert.pem"
  key_file: "/etc/nats/key.pem"
  cipher_suites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
} # end tls
`
	m := &MessagingModule{}
	findings := m.parseNATSConfig("/etc/nats/nats-server.conf", []byte(conf))
	require.NotEmpty(t, findings)

	cipherCount := 0
	for _, f := range findings {
		if f.CryptoAsset.Function == "NATS TLS cipher suite" {
			cipherCount++
		}
	}
	assert.Equal(t, 2, cipherCount, "two inline cipher suites")
}

func TestParseNATS_NoTLS(t *testing.T) {
	conf := `port: 4222
`
	m := &MessagingModule{}
	findings := m.parseNATSConfig("/etc/nats/nats-server.conf", []byte(conf))
	assert.Empty(t, findings)
}

// --- Mosquitto parser tests ---

func TestParseMosquitto_TLS(t *testing.T) {
	conf := `# Mosquitto TLS config
listener 8883
cafile /etc/mosquitto/ca.crt
certfile /etc/mosquitto/server.crt
keyfile /etc/mosquitto/server.key
tls_version tlsv1.2
ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384
require_certificate true
`
	m := &MessagingModule{}
	findings := m.parseMosquittoConfig("/etc/mosquitto/mosquitto.conf", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["Mosquitto TLS version"])
	assert.True(t, funcSet["Mosquitto TLS cipher suite"])
}

func TestParseMosquitto_NoTLS(t *testing.T) {
	conf := `listener 1883
allow_anonymous true
`
	m := &MessagingModule{}
	findings := m.parseMosquittoConfig("/etc/mosquitto/mosquitto.conf", []byte(conf))
	assert.Empty(t, findings)
}

// --- Redis parser tests ---

func TestParseRedis_TLS(t *testing.T) {
	conf := `# Redis TLS configuration
port 0
tls-port 6379
tls-cert-file /etc/redis/redis.crt
tls-key-file /etc/redis/redis.key
tls-ca-cert-file /etc/redis/ca.crt
tls-protocols "TLSv1.2 TLSv1.3"
tls-ciphers HIGH:!aNULL:!MD5
tls-ciphersuites TLS_AES_256_GCM_SHA384
tls-auth-clients yes
`
	m := &MessagingModule{}
	findings := m.parseRedisConfig("/etc/redis/redis.conf", []byte(conf))
	require.NotEmpty(t, findings)

	funcSet := make(map[string]bool)
	for _, f := range findings {
		funcSet[f.CryptoAsset.Function] = true
	}
	assert.True(t, funcSet["Redis TLS protocol"])
	assert.True(t, funcSet["Redis TLS cipher suite"])
}

func TestParseRedis_NoTLS(t *testing.T) {
	conf := `port 6379
bind 127.0.0.1
`
	m := &MessagingModule{}
	findings := m.parseRedisConfig("/etc/redis/redis.conf", []byte(conf))
	assert.Empty(t, findings)
}

func TestParseRedis_TLS13Suites(t *testing.T) {
	conf := `tls-port 6380
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
`
	m := &MessagingModule{}
	findings := m.parseRedisConfig("/etc/redis/redis.conf", []byte(conf))
	require.NotEmpty(t, findings)

	cipherCount := 0
	for _, f := range findings {
		if f.CryptoAsset.Function == "Redis TLS cipher suite" {
			cipherCount++
		}
	}
	assert.Equal(t, 2, cipherCount, "two TLS 1.3 cipher suites")
}

// --- module interface tests ---

func TestMessagingModuleInterface(t *testing.T) {
	m := NewMessagingModule(nil)
	assert.Equal(t, "messaging", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
	var _ Module = m
}
