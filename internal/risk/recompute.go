package risk

import "fmt"

type ExplainabilityOutput struct {
	BODTier             int     `json:"bod_tier"`
	CriticalityOverride *string `json:"criticality_override,omitempty"`
	EPSSRank            float64 `json:"epss_rank"`
	SSVCBucket          string  `json:"ssvc_bucket"`
}

// RecomputeScore represents P5-6 and P5-7 logic.
// Takes current state of the finding/asset and returns a full explainable payload.
func RecomputeScore(exposure *bool, kev bool, automatable *bool, techImpact bool, criticalityTier string, epss float64, ssvcBucket string) (ExplainabilityOutput, error) {
	// Step 1: Base BOD 26-04 Tier
	baseDeadline := CalculateBOD2604Deadline(exposure, kev, automatable, techImpact)
	
	// Step 2: Criticality Override
	newDeadline, reason := ApplyCriticalityOverride(baseDeadline, criticalityTier)
	
	// Ensure SSVC bucket is one of the valid ones from schema (P5-7)
	validBuckets := map[string]bool{"track": true, "track_star": true, "attend": true, "act": true, "": true}
	if !validBuckets[ssvcBucket] {
		return ExplainabilityOutput{}, fmt.Errorf("invalid ssvc_bucket: %s", ssvcBucket)
	}

	return ExplainabilityOutput{
		BODTier:             newDeadline,
		CriticalityOverride: reason,
		EPSSRank:            epss,
		SSVCBucket:          ssvcBucket,
	}, nil
}
