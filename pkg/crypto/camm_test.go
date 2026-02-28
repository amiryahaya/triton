package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestAssessCAMM_Empty(t *testing.T) {
	result := AssessCAMM(nil, nil)
	assert.Equal(t, CAMMLevel0, result.Level)
	assert.NotEmpty(t, result.Manual)
}

func TestAssessCAMM_Level1_CryptoInventory(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
			},
		},
	}
	result := AssessCAMM(systems, nil)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel1)
	assert.Contains(t, indicatorIDs(result.Indicators), "1.4")
}

func TestAssessCAMM_Level1_TLS13(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "TLS 1.3"},
				{Algorithm: "AES-256-GCM"},
			},
		},
	}
	result := AssessCAMM(systems, nil)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel1)
	assert.Contains(t, indicatorIDs(result.Indicators), "1.2")
}

func TestAssessCAMM_Level2_Diversity(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
				{Algorithm: "ECDSA-P256"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "SHA-384"},
			},
		},
	}
	result := AssessCAMM(systems, nil)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel2)
	assert.Contains(t, indicatorIDs(result.Indicators), "2.1")
	assert.Contains(t, indicatorIDs(result.Indicators), "2.2")
}

func TestAssessCAMM_Level2_WithExclusion(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "SHA-512"},
			},
		},
	}
	findings := []model.Finding{
		{
			Module: "configs",
			CryptoAsset: &model.CryptoAsset{
				Function:  "TLS disabled algorithms",
				Algorithm: "DES",
			},
		},
	}
	result := AssessCAMM(systems, findings)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel2)
	assert.Contains(t, indicatorIDs(result.Indicators), "2.3")
}

func TestAssessCAMM_Level2_WithPQC(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "ML-KEM-1024"},
				{Algorithm: "RSA-2048"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "SHA-512"},
			},
		},
	}
	result := AssessCAMM(systems, nil)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel2)
	assert.Contains(t, indicatorIDs(result.Indicators), "2.4")
}

func TestAssessCAMM_NilCryptoAssetInFindings(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "AES-256-GCM"},
			},
		},
	}
	findings := []model.Finding{
		{
			Module:      "configs",
			CryptoAsset: nil, // nil CryptoAsset should not panic
		},
		{
			Module: "configs",
			CryptoAsset: &model.CryptoAsset{
				Function:  "TLS disabled algorithms",
				Algorithm: "DES",
			},
		},
	}
	result := AssessCAMM(systems, findings)
	assert.GreaterOrEqual(t, result.Level, CAMMLevel1)
}

func TestAssessCAMM_ManualIndicators(t *testing.T) {
	result := AssessCAMM(nil, nil)
	// Should have manual indicators for Level 3.2 + Level 4
	assert.NotEmpty(t, result.Manual)
	assert.GreaterOrEqual(t, len(result.Manual), 3) // 3.2, 4.1, 4.2
}

func TestAssessCAMM_Level3_CertbotDetected(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
				{Algorithm: "ECDSA-P256"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "ML-KEM-1024"}, // PQC for 2.4
			},
		},
	}
	findings := []model.Finding{
		{
			Module: "configs",
			Source: model.FindingSource{Path: "/etc/letsencrypt/renewal/example.com.conf"},
			CryptoAsset: &model.CryptoAsset{
				Function: "TLS disabled algorithms",
				Purpose:  "ACME certificate renewal",
			},
		},
	}
	result := AssessCAMM(systems, findings)
	assert.Equal(t, CAMMLevel3, result.Level)
	assert.Equal(t, "Partial", result.Confidence)
	assert.Contains(t, indicatorIDs(result.Indicators), "3.1")
}

func TestAssessCAMM_Level3_VaultDetected(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "SHA-512"},
				{Algorithm: "ML-DSA-65"}, // PQC for 2.4
			},
		},
	}
	findings := []model.Finding{
		{
			Module: "configs",
			Source: model.FindingSource{Path: "/etc/vault/config.hcl"},
			CryptoAsset: &model.CryptoAsset{
				Function: "Configuration",
				Purpose:  "vault pki/issue transit",
			},
		},
	}
	result := AssessCAMM(systems, findings)
	assert.Equal(t, CAMMLevel3, result.Level)
	assert.Equal(t, "Partial", result.Confidence)
}

func TestAssessCAMM_Level3_CertManagerDetected(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
				{Algorithm: "ECDSA-P384"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "ML-KEM-768"}, // PQC for 2.4
			},
		},
	}
	findings := []model.Finding{
		{
			Module: "containers",
			Source: model.FindingSource{Path: "/k8s/cert-manager.yaml"},
			CryptoAsset: &model.CryptoAsset{
				Function: "Kubernetes",
				Purpose:  "cert-manager ClusterIssuer",
			},
		},
	}
	result := AssessCAMM(systems, findings)
	assert.Equal(t, CAMMLevel3, result.Level)
}

func TestAssessCAMM_Level3_NoRotationStaysLevel2(t *testing.T) {
	systems := []model.System{
		{
			CryptoAssets: []model.CryptoAsset{
				{Algorithm: "RSA-2048"},
				{Algorithm: "ECDSA-P256"},
				{Algorithm: "AES-256-GCM"},
				{Algorithm: "ML-KEM-1024"}, // PQC for 2.4
			},
		},
	}
	// No rotation tool findings
	result := AssessCAMM(systems, nil)
	assert.Equal(t, CAMMLevel2, result.Level)
	assert.Equal(t, "Auto-assessed", result.Confidence)
}

func TestDetectRotationAutomation(t *testing.T) {
	tests := []struct {
		name     string
		findings []model.Finding
		want     bool
	}{
		{
			name: "certbot in path",
			findings: []model.Finding{
				{Module: "configs", Source: model.FindingSource{Path: "/etc/letsencrypt/renewal.conf"},
					CryptoAsset: &model.CryptoAsset{Purpose: "config"}},
			},
			want: true,
		},
		{
			name: "vault in purpose",
			findings: []model.Finding{
				{Module: "configs", Source: model.FindingSource{Path: "/etc/config.yml"},
					CryptoAsset: &model.CryptoAsset{Purpose: "VAULT_ADDR transit"}},
			},
			want: true,
		},
		{
			name: "cert-manager in container scan",
			findings: []model.Finding{
				{Module: "containers", Source: model.FindingSource{Path: "/deploy/cert-manager.yaml"},
					CryptoAsset: &model.CryptoAsset{Purpose: "k8s deployment"}},
			},
			want: true,
		},
		{
			name: "auto-renew in script",
			findings: []model.Finding{
				{Module: "scripts", Source: model.FindingSource{Path: "/cron/renew-certs.sh"},
					CryptoAsset: &model.CryptoAsset{Purpose: "auto-renew certificates"}},
			},
			want: true,
		},
		{
			name: "no rotation indicators",
			findings: []model.Finding{
				{Module: "configs", Source: model.FindingSource{Path: "/etc/ssh/sshd_config"},
					CryptoAsset: &model.CryptoAsset{Purpose: "SSH config"}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectRotationAutomation(tt.findings)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCAMMLevelLabel(t *testing.T) {
	tests := []struct {
		level int
		label string
	}{
		{0, "Level 0 - No Crypto-Agility"},
		{1, "Level 1 - Basic"},
		{2, "Level 2 - Managed"},
		{3, "Level 3 - Advanced"},
		{4, "Level 4 - Optimized"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.label, CAMMLevelLabel(tt.level))
	}
}

// indicatorIDs extracts the indicator IDs (e.g., "1.2") from indicator strings.
func indicatorIDs(indicators []string) []string {
	var ids []string
	for _, ind := range indicators {
		if len(ind) >= 3 {
			ids = append(ids, ind[:3])
		}
	}
	return ids
}
