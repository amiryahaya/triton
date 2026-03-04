package report

import (
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// GroupFindingsIntoSystems groups findings into systems with crypto-agility assessment.
//
// Deprecated: Use model.GroupFindingsIntoSystemsWithAgility directly.
func GroupFindingsIntoSystems(findings []model.Finding) []model.System {
	return model.GroupFindingsIntoSystemsWithAgility(findings, crypto.AssessAssetAgility)
}
