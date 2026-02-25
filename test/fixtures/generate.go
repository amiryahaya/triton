//go:build ignore

// generate.go creates test fixture crypto files.
// Run: go run test/fixtures/generate.go
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	base := "test/fixtures"

	// --- Certificates ---
	certDir := filepath.Join(base, "certificates")

	// RSA-2048 self-signed
	rsaKey2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	writeCert(certDir, "rsa-2048.pem", rsaKey2048, &rsaKey2048.PublicKey, pkix.Name{
		CommonName:   "triton-test-rsa2048",
		Organization: []string{"Triton Test"},
	}, false, time.Now().Add(-1*time.Hour), time.Now().Add(365*24*time.Hour))

	// RSA-4096 self-signed
	rsaKey4096, _ := rsa.GenerateKey(rand.Reader, 4096)
	writeCert(certDir, "rsa-4096.pem", rsaKey4096, &rsaKey4096.PublicKey, pkix.Name{
		CommonName:   "triton-test-rsa4096",
		Organization: []string{"Triton Test"},
	}, false, time.Now().Add(-1*time.Hour), time.Now().Add(365*24*time.Hour))

	// ECDSA P-256
	ecKey256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	writeCert(certDir, "ecdsa-p256.pem", ecKey256, &ecKey256.PublicKey, pkix.Name{
		CommonName:   "triton-test-ecdsa-p256",
		Organization: []string{"Triton Test"},
	}, false, time.Now().Add(-1*time.Hour), time.Now().Add(365*24*time.Hour))

	// Ed25519
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	writeCert(certDir, "ed25519.pem", edPriv, edPub, pkix.Name{
		CommonName:   "triton-test-ed25519",
		Organization: []string{"Triton Test"},
	}, false, time.Now().Add(-1*time.Hour), time.Now().Add(365*24*time.Hour))

	// Expired certificate (RSA-2048)
	rsaKeyExpired, _ := rsa.GenerateKey(rand.Reader, 2048)
	writeCert(certDir, "expired.pem", rsaKeyExpired, &rsaKeyExpired.PublicKey, pkix.Name{
		CommonName:   "triton-test-expired",
		Organization: []string{"Triton Test"},
	}, false, time.Now().Add(-365*24*time.Hour), time.Now().Add(-1*time.Hour))

	// Self-signed CA certificate
	rsaKeyCA, _ := rsa.GenerateKey(rand.Reader, 4096)
	writeCert(certDir, "selfsigned-ca.pem", rsaKeyCA, &rsaKeyCA.PublicKey, pkix.Name{
		CommonName:   "Triton Test CA",
		Organization: []string{"Triton Test CA"},
	}, true, time.Now().Add(-1*time.Hour), time.Now().Add(10*365*24*time.Hour))

	// DER format certificate
	ecKeyDER, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	writeCertDER(certDir, "ecdsa-p256.der", ecKeyDER, &ecKeyDER.PublicKey, pkix.Name{
		CommonName: "triton-test-der",
	})

	// Multi-cert PEM (certificate chain)
	writeChainPEM(certDir, "chain.pem")

	// --- Keys ---
	keyDir := filepath.Join(base, "keys")

	// RSA private key (PKCS#1)
	rsaPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	writeRSAPrivateKey(keyDir, "rsa-private.pem", rsaPrivKey)

	// EC private key
	ecPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	writeECPrivateKey(keyDir, "ec-private.pem", ecPrivKey)

	// PKCS#8 private key
	rsaPKCS8Key, _ := rsa.GenerateKey(rand.Reader, 2048)
	writePKCS8PrivateKey(keyDir, "pkcs8-private.pem", rsaPKCS8Key)

	// RSA public key
	writePublicKey(keyDir, "rsa-public.pem", &rsaPrivKey.PublicKey)

	// OpenSSH Ed25519 placeholder (SSH format is complex, use a PEM-wrapped Ed25519)
	_, edPrivKey, _ := ed25519.GenerateKey(rand.Reader)
	writePKCS8PrivateKey(keyDir, "ed25519-private.pem", edPrivKey)

	// --- Scripts (for Phase 3, placeholders) ---
	scriptDir := filepath.Join(base, "scripts")
	writeFile(scriptDir, "crypto-python.py", `#!/usr/bin/env python3
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

h = hashlib.sha256(b"test data")
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
`)

	writeFile(scriptDir, "crypto-shell.sh", `#!/bin/bash
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 365
openssl enc -aes-256-cbc -in plaintext.txt -out encrypted.txt
openssl dgst -sha256 -sign key.pem -out signature.bin data.txt
`)

	writeFile(scriptDir, "crypto-node.js", `const crypto = require('crypto');

const hash = crypto.createHash('sha256').update('data').digest('hex');
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
`)

	// --- Web app fixtures (for Phase 3) ---
	webDir := filepath.Join(base, "webapp")
	writeFile(webDir, "crypto-php.php", `<?php
$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
$hash = hash('sha256', $data);
openssl_sign($data, $signature, $privKey, OPENSSL_ALGO_SHA256);
?>
`)

	writeFile(webDir, "crypto-java.java", `import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

public class CryptoExample {
    public void example() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }
}
`)

	// --- Config fixtures (for Phase 3) ---
	confDir := filepath.Join(base, "configs")
	writeFile(confDir, "apache-ssl.conf", `<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/server.pem
    SSLCertificateKeyFile /etc/ssl/private/server.key
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder on
</VirtualHost>
`)

	writeFile(confDir, "nginx-ssl.conf", `server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/server.pem;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
}
`)

	fmt.Println("Test fixtures generated successfully.")
}

func writeCert(dir, name string, privKey interface{}, pubKey interface{}, subject pkix.Name, isCA bool, notBefore, notAfter time.Time) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		panic(err)
	}

	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		panic(err)
	}
	defer f.Close()

	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func writeCertDER(dir, name string, privKey interface{}, pubKey interface{}, subject pkix.Name) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		panic(err)
	}

	os.WriteFile(filepath.Join(dir, name), certDER, 0644)
}

func writeChainPEM(dir, name string) {
	// Root CA
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Triton Test Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	// Leaf cert signed by root
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "triton-test-leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)

	f, _ := os.Create(filepath.Join(dir, name))
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

func writeRSAPrivateKey(dir, name string, key *rsa.PrivateKey) {
	f, _ := os.Create(filepath.Join(dir, name))
	defer f.Close()
	pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func writeECPrivateKey(dir, name string, key *ecdsa.PrivateKey) {
	der, _ := x509.MarshalECPrivateKey(key)
	f, _ := os.Create(filepath.Join(dir, name))
	defer f.Close()
	pem.Encode(f, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
}

func writePKCS8PrivateKey(dir, name string, key interface{}) {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	f, _ := os.Create(filepath.Join(dir, name))
	defer f.Close()
	pem.Encode(f, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}

func writePublicKey(dir, name string, key interface{}) {
	der, _ := x509.MarshalPKIXPublicKey(key)
	f, _ := os.Create(filepath.Join(dir, name))
	defer f.Close()
	pem.Encode(f, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

func writeFile(dir, name, content string) {
	os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
}
