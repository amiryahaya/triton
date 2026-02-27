package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestClassifyLibraryVersion_OpenSSL(t *testing.T) {
	tests := []struct {
		name       string
		libName    string
		version    string
		wantStatus string
		wantLabel  string
	}{
		{"OpenSSL 1.0.2 is DEPRECATED", "openssl", "1.0.2", "DEPRECATED", string(NACSATidakPatuh)},
		{"OpenSSL 1.0.2u is DEPRECATED", "libcrypto", "1.0.2u", "DEPRECATED", string(NACSATidakPatuh)},
		{"OpenSSL 1.1.1k is TRANSITIONAL", "openssl", "1.1.1k", "TRANSITIONAL", string(NACSAPeralihan)},
		{"OpenSSL 3.0.2 is TRANSITIONAL", "libssl", "3.0.2", "TRANSITIONAL", string(NACSAPeralihan)},
		{"OpenSSL 3.2.0 is TRANSITIONAL", "openssl", "3.2.0", "TRANSITIONAL", string(NACSAPeralihan)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &model.CryptoAsset{}
			ClassifyLibraryAsset(asset, tt.libName, tt.version)
			assert.Equal(t, tt.wantStatus, asset.PQCStatus)
			assert.Equal(t, tt.wantLabel, asset.NACSALabel)
		})
	}
}

func TestClassifyLibraryVersion_Libsodium(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{"libsodium 1.0.18", "1.0.18"},
		{"libsodium 1.0.20", "1.0.20"},
		{"libsodium no version", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &model.CryptoAsset{}
			ClassifyLibraryAsset(asset, "libsodium", tt.version)
			assert.Equal(t, "SAFE", asset.PQCStatus)
			assert.Equal(t, string(NACSAPatuh), asset.NACSALabel)
		})
	}
}

func TestClassifyLibraryVersion_GnuTLS(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		wantStatus string
	}{
		{"GnuTLS 3.5 is DEPRECATED", "3.5.0", "DEPRECATED"},
		{"GnuTLS 3.6 is TRANSITIONAL", "3.6.0", "TRANSITIONAL"},
		{"GnuTLS 3.7.8 is TRANSITIONAL", "3.7.8", "TRANSITIONAL"},
		{"GnuTLS 2.12 is DEPRECATED", "2.12.0", "DEPRECATED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &model.CryptoAsset{}
			ClassifyLibraryAsset(asset, "libgnutls", tt.version)
			assert.Equal(t, tt.wantStatus, asset.PQCStatus)
		})
	}
}

func TestClassifyLibraryVersion_Unknown(t *testing.T) {
	asset := &model.CryptoAsset{}
	ClassifyLibraryAsset(asset, "some-unknown-lib", "2.0.0")
	assert.Equal(t, "TRANSITIONAL", asset.PQCStatus)
	assert.Equal(t, string(NACSAPeralihan), asset.NACSALabel)
}

func TestClassifyLibraryVersion_NoVersion(t *testing.T) {
	asset := &model.CryptoAsset{}
	ClassifyLibraryAsset(asset, "openssl", "")
	assert.Equal(t, "TRANSITIONAL", asset.PQCStatus)
	assert.Equal(t, string(NACSAPeralihan), asset.NACSALabel)
}

func TestClassifyLibraryVersion_MbedTLS(t *testing.T) {
	tests := []struct {
		name       string
		libName    string
		version    string
		wantStatus string
	}{
		{"mbedTLS 1.3 is DEPRECATED", "libmbedtls", "1.3.0", "DEPRECATED"},
		{"mbedTLS 2.0 is TRANSITIONAL", "libmbedcrypto", "2.0.0", "TRANSITIONAL"},
		{"mbedTLS 3.4 is TRANSITIONAL", "mbedtls", "3.4.0", "TRANSITIONAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &model.CryptoAsset{}
			ClassifyLibraryAsset(asset, tt.libName, tt.version)
			assert.Equal(t, tt.wantStatus, asset.PQCStatus)
		})
	}
}

func TestClassifyLibraryVersion_WolfSSL(t *testing.T) {
	asset := &model.CryptoAsset{}
	ClassifyLibraryAsset(asset, "wolfssl", "3.15.0")
	assert.Equal(t, "DEPRECATED", asset.PQCStatus)

	asset2 := &model.CryptoAsset{}
	ClassifyLibraryAsset(asset2, "libwolfssl", "5.6.0")
	assert.Equal(t, "TRANSITIONAL", asset2.PQCStatus)
}

func TestClassifyLibraryVersion_OpenSSH(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		wantStatus string
	}{
		{"OpenSSH 6.9 is DEPRECATED", "6.9", "DEPRECATED"},
		{"OpenSSH 7.0 is TRANSITIONAL", "7.0", "TRANSITIONAL"},
		{"OpenSSH 9.0 is TRANSITIONAL", "9.0", "TRANSITIONAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := &model.CryptoAsset{}
			ClassifyLibraryAsset(asset, "openssh", tt.version)
			assert.Equal(t, tt.wantStatus, asset.PQCStatus)
		})
	}
}

func TestClassifyLibraryVersion_GnuPG(t *testing.T) {
	asset := &model.CryptoAsset{}
	ClassifyLibraryAsset(asset, "gnupg", "1.4.23")
	assert.Equal(t, "DEPRECATED", asset.PQCStatus)

	asset2 := &model.CryptoAsset{}
	ClassifyLibraryAsset(asset2, "gpg", "2.2.0")
	assert.Equal(t, "TRANSITIONAL", asset2.PQCStatus)
}

func TestClassifyLibraryVersion_LibreSSL(t *testing.T) {
	asset := &model.CryptoAsset{}
	ClassifyLibraryAsset(asset, "libressl", "2.9.0")
	assert.Equal(t, "DEPRECATED", asset.PQCStatus)

	asset2 := &model.CryptoAsset{}
	ClassifyLibraryAsset(asset2, "libressl", "3.8.0")
	assert.Equal(t, "TRANSITIONAL", asset2.PQCStatus)
}

func TestNormalizeLibKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"libcrypto", "openssl"},
		{"libcrypto.so.3", "openssl"},
		{"libssl3", "openssl"},
		{"libgnutls.so.30", "gnutls"},
		{"libsodium", "libsodium"},
		{"OpenSSL", "openssl"},
		{"unknown-lib", ""},
		{"libmbedcrypto", "mbedtls"},
		{"openssh-client", "openssh"},
		{"gnupg2", "gnupg"},
		{"gpg", "gnupg"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeLibKey(tt.input))
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input     string
		wantMajor int
		wantMinor int
		wantOk    bool
	}{
		{"1.1.1k", 1, 1, true},
		{"3.0.2", 3, 0, true},
		{"1.0.2u", 1, 0, true},
		{"2", 2, 0, true},
		{"", 0, 0, false},
		{"bad", 0, 0, false},
		{"3.6", 3, 6, true},
		{"1.0", 1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			major, minor, ok := parseVersion(tt.input)
			assert.Equal(t, tt.wantMajor, major)
			assert.Equal(t, tt.wantMinor, minor)
			assert.Equal(t, tt.wantOk, ok)
		})
	}
}
