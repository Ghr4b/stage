package resolver

import (
	"strings"

	"tijeri/internal/assets"
)

const (
	ProbabilisticMergeThreshold  = 0.7
	HeuristicReviewThreshold     = 0.4
)

// ProbabilisticWeights defines the weights for each scoring factor.
type ProbabilisticWeights struct {
	HostnameSimilarity float64
	SubnetMatch        float64
	OSFingerprint      float64
	FirstSeenProximity float64
}

var DefaultWeights = ProbabilisticWeights{
	HostnameSimilarity: 0.35,
	SubnetMatch:        0.25,
	OSFingerprint:      0.20,
	FirstSeenProximity: 0.20,
}

// ProbabilisticMetadata carries the extra metadata needed for probabilistic scoring.
// Signals must carry this in addition to the base IdentitySignal interface.
type ProbabilisticMetadata struct {
	Hostname  string
	Subnet    string
	OS        string
	FirstSeen int64 // Unix timestamp
}

// ProbabilisticSignal is an IdentitySignal with extra metadata for scoring.
type ProbabilisticSignal interface {
	assets.IdentitySignal
	Metadata() ProbabilisticMetadata
}

// ProbabilisticCompare scores two signals using weighted factors.
// Above ProbabilisticMergeThreshold → merge WITH review flag.
// Below ProbabilisticMergeThreshold but above HeuristicReviewThreshold → heuristic queue.
// Below HeuristicReviewThreshold → no merge.
func ProbabilisticCompare(a, b assets.IdentitySignal) MergeDecision {
	pa, okA := a.(ProbabilisticSignal)
	pb, okB := b.(ProbabilisticSignal)
	if !okA || !okB {
		return MergeDecision{ShouldMerge: false, Tier: TierNone}
	}

	metaA := pa.Metadata()
	metaB := pb.Metadata()

	score := computeScore(metaA, metaB, DefaultWeights)

	if score >= ProbabilisticMergeThreshold {
		return MergeDecision{
			ShouldMerge: true,
			Tier:        TierProbabilistic,
			Confidence:  score,
			NeedsReview: true, // ALWAYS true for probabilistic tier
		}
	}

	if score >= HeuristicReviewThreshold {
		return MergeDecision{
			ShouldMerge: false, // Never auto-merge from heuristic tier (invariant I1)
			Tier:        TierHeuristic,
			Confidence:  score,
			NeedsReview: true,
		}
	}

	return MergeDecision{ShouldMerge: false, Tier: TierNone, Confidence: score}
}

func computeScore(a, b ProbabilisticMetadata, w ProbabilisticWeights) float64 {
	score := 0.0

	// Hostname similarity (simple: common prefix ratio)
	if a.Hostname != "" && b.Hostname != "" {
		score += w.HostnameSimilarity * hostnameSimilarity(a.Hostname, b.Hostname)
	}

	// Subnet match (exact match on subnet string)
	if a.Subnet != "" && b.Subnet != "" && a.Subnet == b.Subnet {
		score += w.SubnetMatch
	}

	// OS fingerprint match
	if a.OS != "" && b.OS != "" && strings.EqualFold(a.OS, b.OS) {
		score += w.OSFingerprint
	}

	// First-seen proximity (within 24h = full score, decays linearly to 0 at 30 days)
	if a.FirstSeen > 0 && b.FirstSeen > 0 {
		diff := a.FirstSeen - b.FirstSeen
		if diff < 0 {
			diff = -diff
		}
		const day = 86400
		if diff <= day {
			score += w.FirstSeenProximity
		} else if diff < 30*day {
			score += w.FirstSeenProximity * (1.0 - float64(diff)/float64(30*day))
		}
	}

	return score
}

func hostnameSimilarity(a, b string) float64 {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	if a == b {
		return 1.0
	}

	// Common prefix ratio
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	if maxLen == 0 {
		return 0.0
	}

	common := 0
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] == b[i] {
			common++
		} else {
			break
		}
	}

	return float64(common) / float64(maxLen)
}
