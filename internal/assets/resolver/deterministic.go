package resolver

import (
	"tijeri/internal/assets"
)

// DeterministicCompare performs exact-match comparison for cloud instance ID,
// hardware serial, and TPM/hardware UUID. An exact match auto-merges with
// NO review flag. A near-miss (off-by-one-char) does NOT match.
func DeterministicCompare(a, b assets.IdentitySignal) MergeDecision {
	// Only compare signals of the same type.
	if a.SignalType() != b.SignalType() {
		return MergeDecision{ShouldMerge: false, Tier: TierNone}
	}

	// Deterministic tier only handles exact-match identifier types.
	switch a.SignalType() {
	case "cloud_instance_id", "hardware_serial", "tpm_uuid":
		if a.Value() == b.Value() {
			return MergeDecision{
				ShouldMerge: true,
				Tier:        TierDeterministic,
				Confidence:  1.0,
				NeedsReview: false, // Deterministic tier: no review needed
			}
		}
		// Near-miss: explicitly no merge
		return MergeDecision{ShouldMerge: false, Tier: TierNone}
	default:
		// Not a deterministic identifier type — fall through to other tiers
		return MergeDecision{ShouldMerge: false, Tier: TierNone}
	}
}
