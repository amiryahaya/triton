package model

import (
	"time"
)

// SBOM represents a Software Bill of Materials
type SBOM struct {
	BOMFormat   string       `json:"bomFormat"`
	SpecVersion string       `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version     int          `json:"version"`
	Metadata    Metadata     `json:"metadata"`
	Components  []Component  `json:"components"`
}

// CBOM represents a Cryptographic Bill of Materials
type CBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     Metadata       `json:"metadata"`
	Components   []Component    `json:"components"`
	CryptoAssets []CryptoAsset  `json:"cryptoAssets,omitempty"`
}

type Metadata struct {
	Timestamp time.Time `json:"timestamp"`
	Tools     []Tool    `json:"tools"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Component struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	PURL       string `json:"purl,omitempty"`
	Hashes     []Hash `json:"hashes,omitempty"`
	Licenses   []License `json:"licenses,omitempty"`
}

type Hash struct {
	Algorithm string `json:"alg"`
	Value     string `json:"content"`
}

type License struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CryptoAsset struct {
	Type         string `json:"type"`
	Subject      string `json:"subject,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
	NotBefore    int64  `json:"notBefore,omitempty"`
	NotAfter     int64  `json:"notAfter,omitempty"`
	Algorithm    string `json:"algorithm"`
	KeySize      int    `json:"keySize,omitempty"`
	IsCA         bool   `json:"isCA,omitempty"`
	
	// PQC Classification
	PQCStatus     string `json:"pqcStatus,omitempty"` // SAFE, TRANSITIONAL, DEPRECATED, UNSAFE
	PQCConfidence float64 `json:"pqcConfidence,omitempty"`
}

type Finding struct {
	Type        string       `json:"type"`
	Path        string       `json:"path"`
	Component   *Component   `json:"component,omitempty"`
	CryptoAsset *CryptoAsset `json:"cryptoAsset,omitempty"`
	Confidence  float64      `json:"confidence"`
}
