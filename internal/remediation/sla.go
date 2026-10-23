package remediation

import (
	"tijeri/internal/risk"
)

// ComputeSLA maps the risk engine's BOD deadline tier to an SLA in days.
// The architecture dictates that SLA is sourced directly from Phase 5 output (BODTier),
// rather than a flat CVSS-based rule.
func ComputeSLA(exposure *bool, kev bool, automatable *bool, techImpact bool, criticalityTier string) int {
	score, _ := risk.RecomputeScore(exposure, kev, automatable, techImpact, criticalityTier, 0.0, "")
	return score.BODTier
}
